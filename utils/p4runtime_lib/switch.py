# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from abc import abstractmethod
from datetime import datetime
from queue import Queue
import time
import queue
import asyncio
import grpc
from p4.tmp import p4config_pb2
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc
import logging

MSG_LOG_MAX_LEN = 1024

# List of all active connections
connections = []


def ShutdownAllSwitchConnections():
    for c in connections:
        c.shutdown()


class SwitchConnection(object):

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0,
                 proto_dump_file="grpc.pcap"):
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(self.requests_stream))
        self.proto_dump_file = proto_dump_file
        self.queues = {}
        connections.append(self)

    @abstractmethod
    def buildDeviceConfig(self, **kwargs):
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        self.requests_stream.close()
        self.stream_msg_resp.cancel()

    def MasterArbitrationUpdate(self, dry_run=False, **kwargs):
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = 1

        if dry_run:
            print("P4Runtime MasterArbitrationUpdate: ", request)
        else:
            self.requests_stream.put(request)
            for item in self.stream_msg_resp:
                return item  # just one

    def SetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):
        device_config = self.buildDeviceConfig(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        if dry_run:
            print("P4Runtime SetForwardingPipelineConfig:", request)
        else:
            self.client_stub.SetForwardingPipelineConfig(request)

    def WriteTableEntry(self, table_entry, dry_run=False):
        try:

            request = p4runtime_pb2.WriteRequest()
            request.device_id = self.device_id
            request.election_id.low = 1

            update = request.updates.add()

            update.type = p4runtime_pb2.Update.INSERT
            print("insert table entry")

            update.entity.table_entry.CopyFrom(table_entry)

            if dry_run:
                print("P4Runtime Write (dry run):", request)
            else:
                print("writing rule...")
                self.client_stub.Write(request)
        except grpc.RpcError as e:
            print(f"gRPC RpcError: {e.code()} - {e.details()}")

        except Exception as e:
            print(f"An error occurred while writing to the P4 table: {e}")

    def ModifyTableEntry(self, table_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()

        update.type = p4runtime_pb2.Update.MODIFY
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print("P4Runtime Modify: ", request)
        else:
            self.client_stub.Write(request)

    def DeleteTableEntry(self, table_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()

        update.type = p4runtime_pb2.Update.DELETE
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print("P4Runtime Delete: ", request)
        else:
            self.client_stub.Write(request)

    def ReadTableEntries(self, table_id=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0
        if dry_run:
            print("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def ReadCounters(self, counter_id=None, index=None, dry_run=False):
        try:

            request = p4runtime_pb2.ReadRequest()
            request.device_id = self.device_id
            entity = request.entities.add()
            counter_entry = entity.counter_entry

            if counter_id is not None:
                counter_entry.counter_id = counter_id
            else:
                counter_entry.counter_id = 0

            if index is not None:
                counter_entry.index.index = index

            if dry_run:
                print("P4Runtime Read:", request)
            else:

                for response in self.client_stub.Read(request):
                    yield response

        except Exception as e:
            print(f"Error: {e}")

    def ReadRegisters(self, register_id=None, index=None, dry_run=False):

        try:
            print("Building ReadRequest for Registers...")
            request = p4runtime_pb2.ReadRequest()
            request.device_id = self.device_id
            entity = request.entities.add()
            register_entry = entity.register_entry
            if register_id is not None:
                register_entry.register_id = register_id
                print(f"Register ID: {register_id}")
            if index is not None:
                register_entry.index.index = index
                print(f"Index: {index}")
            if dry_run:
                print("P4Runtime Read (Dry Run):", request)
                return
            else:
                for response in self.client_stub.Read(request):
                    print("Received Response:", response)
                    yield response
        except Exception as e:
            print(f"Exception during ReadRegisters: {e}")

    def check_queue_status(self):
        try:
            msg_list = list(self.stream_msg_resp)

            return len(msg_list)
        except Exception as e:
            print(f"Error in queue control: {e}")
            return None

    async def PacketIn(self, timeout=1):
        """
        Returns the next available packet for the switch.
        If the queue is empty, waits until timeout and returns None.
        """
        try:

            item = await asyncio.wait_for(self.queues[self.name].get(), timeout=timeout)

            if item is None:
                print(f"⚠️ No packages available for the switch {self.name}.")
                return None, None

            message, timestamp_received = item
            #start_time = time.time()

            #processing_time = start_time - timestamp_received

            return message, timestamp_received
        except asyncio.TimeoutError:
            return None, None

    async def listen_for_messages(self, timeout=0):
        """
        Method that reads from the gRPC stream and puts packets into the asynchronous queue.
        It uses a timeout so as not to block the main thread.
        """
        self.queues[self.name] = asyncio.Queue(maxsize=5)  # Coda asincrona per lo switch

        print(f"🔄 Started listener for switch {self.name}")

        while True:
            try:

                item = await asyncio.to_thread(next, self.stream_msg_resp)
                if item is not None:

                    timestamp_received = time.time()
                    print(f"📥 New message received from {self.name}: {item} at time: {timestamp_received}")
                    await self.queues[self.name].put((item, timestamp_received))
                else:
                    print(f"⚠️ Empty package received for switch {self.name}, ignored.")

            except StopIteration:
                print(f"⚠️ Stream for switch {self.name} closed.")
                break
            except Exception as e:
                print(f"⚠️ Error while listening to messages for {self.name}: {e}")

            await asyncio.sleep(timeout)

    def packet_out_msg(self, pl, meta):
        return p4runtime_pb2.PacketOut(payload=pl, metadata=meta)

    def PacketOut(self, pl_arr, meta_arr):
        request = p4runtime_pb2.StreamMessageRequest()

        for response in self.stream_msg_resp:
            if response.WhichOneof("update") is "packet":
                print("=============================================================")
                print("Received packet-in payload %s" % (response.packet.payload))
                print("Received packet-in metadata: ")
                for metadata in response.packet.metadata:
                    # uint32
                    print("\tmetadata id: %s" % s(metadata.metadata_id))
                    # bytes
                    print("\tmetadata value: %s" % s(metadata.value))
                print("=============================================================")

    def PacketOut(self, packet, dry_run=False):
        """
        Send a PacketOut packet to the switch.
        :param packet: The packet to send.
        :return: The response from the switch (if available), None otherwise.
        """
        try:

            request = p4runtime_pb2.StreamMessageRequest()
            request.packet.CopyFrom(packet)

            if dry_run:
                print(
                    "P4 Runtime WritePacketOut: ", request)
            else:
                print(f"sending packet out: ", request)
                self.requests_stream.put(request)
                print("packet out sent")
                return True
                #for item in self.stream_msg_resp:
                #    print(f"sending packet out: ", item)
                #    return item

        except Exception as e:
            print(f"Error while sending PacketOut: {e}")
            return None

    # Digest
    def WriteDigestEntry(self, digest_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        request.election_id.high = 0
        request.role_id = 0
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.digest_entry.CopyFrom(digest_entry)

        if dry_run:
            print("P4Runtime write DigestEntry: ", request)
        else:
            self.client_stub.Write(request)

    def DigestListAck(self, digest_ack, dry_run=False, **kwargs):
        try:

            request = p4runtime_pb2.StreamMessageRequest()
            request.digest_ack.CopyFrom(digest_ack)

            if dry_run:
                print("P4 Runtime DigestListAck: ", request)
            else:

                self.requests_stream.put(request)

                for item in self.stream_msg_resp:
                    return item

        except Exception as e:

            print(f"⚠️ Error during message processing: {e}")

    def MessageList(self, dry_run=False, **kwargs):
        try:
            request = p4runtime_pb2.StreamMessageRequest()
            if dry_run:
                print("P4 Runtime DigestList Response: ", request)
            else:
                print(f"request:{request}")
                try:
                    self.requests_stream.put(request)
                except Exception as e:
                    print(f"Failed to put request into the stream: {e}")
                    return None
                if not self.stream_msg_resp:
                    print("No items in stream_msg_resp, continuing execution.")
                    return None

                for item in self.stream_msg_resp:
                    print(f"item:{item}")
                    return item

        except Exception as e:
            print(f"An error occurred in MessageList: {e}")

    def WritePREEntry(self, pre_entry, dry_run=False):
        try:

            request = p4runtime_pb2.WriteRequest()
            request.device_id = self.device_id
            request.election_id.low = 1
            update = request.updates.add()
            update.type = p4runtime_pb2.Update.INSERT
            update.entity.packet_replication_engine_entry.CopyFrom(pre_entry)

            if dry_run:
                print("P4Runtime Write:", request)
            else:

                print("Sending the Write request to the P4Runtime server...")
                response = self.client_stub.Write(request)

                print("Successful writing to P4Runtime")
                print(f"Response received: {response}")

        except grpc.RpcError as rpc_error:

            print(f"RPC error when writing PREEntry: {rpc_error.code()}: {rpc_error.details()}")
        except Exception as e:

            print(f"Error while writing PREEntry: {e}")

    def ModifyPREEntry(self, pre_entry, dry_run=False):
        try:

            request = p4runtime_pb2.WriteRequest()
            request.device_id = self.device_id
            request.election_id.low = 1
            update = request.updates.add()
            update.type = p4runtime_pb2.Update.MODIFY
            update.entity.packet_replication_engine_entry.CopyFrom(pre_entry)

            if dry_run:
                print("P4Runtime Write:", request)
            else:

                response = self.client_stub.Write(request)

                print("Successful writing to P4Runtime")
                print(f"Response received: {response}")

        except grpc.RpcError as rpc_error:

            print(f"RPC error when writing PREEntry: {rpc_error.code()}: {rpc_error.details()}")
        except Exception as e:

            print(f"Error while writing PREEntry: {e}")


class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write("Message too long (%d bytes)! Skipping log...\n" % len(msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)


class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)
