from config import SWITCH_PORTS, HOST_TO_PORT, MAC_IP_MAPPING, TREE
from prometheus_client import Gauge
import threading
import binascii
import socket
import re
from scapy.all import Ether
from tabulate import tabulate
import ipaddress
from collections import deque
import time
from concurrent.futures import ThreadPoolExecutor
import math
import pandas as pd
import os


class DigestManager:

    def __init__(self, p4info_helper, switches, filename="digest_data.xlsx", filename_time="digest_data_time.xlsx"):
        self.filename = filename
        self.filename_time = filename_time
        self.clear_excel_file()
        self.queue_data = {}
        self.lock = threading.Lock()
        self.threads = []
        self.running = True
        self.p4info_helper = p4info_helper

        self.port_map = {sw: {} for sw in switches.values()}
        self.arp_rules = {sw: {} for sw in switches.values()}

        self.bcast = "ff:ff:ff:ff:ff:ff"  # broadcast
        self.switch_port_queue_depth = Gauge('switch_port_queue_depth',
                                             'Coda di congestione per switch e porta',
                                             ['switch', 'port'])
        self.tunnel_id_gauge = Gauge('tunnel_id', 'ID del tunnel', ['switch', 'port'])
        self.switch_time_gauge = Gauge('switch_time', 'Tempo di switch', ['switch', 'flow'])
        self.interarrival_time_gauge = Gauge('interarrival_time', 'Tempo di interarrivo tra pacchetti in ms',
                                             ['switch', 'flow'])
        self.packet_length_gauge = Gauge('packet_length', 'Lunghezza del pacchetto in Byte', ['switch', 'flow'])
        self.queue_time_gauge = Gauge('queue_time', 'Tempo di attesa in coda', ['switch', 'flow'])
        self.sending_rate_gauge = Gauge('sending_rate', 'sending rate in bps', ['switch', 'flow'])
        self.digest_timestamp_gauge = Gauge('digest_timestamp', 'digest timestamp', ['switch', 'flow'])
        self.last_timestamp_gauge = Gauge('last_digest_timestamp', 'last digest timestamp', ['switch', 'flow'])
        self.total_byte_gauge = Gauge('total_byte_count', 'total_byte_count', ['switch', 'flow'])
        self.total_packet_gauge = Gauge('total_packet_count', 'total_packet_count', ['switch', 'flow'])
        self.throughput_gauge = Gauge('throughput', 'throughput', ['switch', 'flow'])
        self.isWLGauge = Gauge('weak_learner', 'weak learner', ['switch', 'is_WL'])
        self.isMaliciousGauge = Gauge('ismalicious_flow', 'malicious flow', ['switch', 'flow'])
        self.overhead_Gauge = Gauge('overhead', 'overhead', ['switch', 'flow'])
        self.maliciousFlowGauge = Gauge(
            'malicious_flow',
            'Flows detected as malicious',
            ['switch', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'tunnel_id']
        )
        self.last_timestamps = {}
        self.last_byte_count = {}

    def clear_excel_file(self):
        """ Completely empty the Excel file upon initialization of the class """
        empty_df = pd.DataFrame(columns=[
            "Switch", "Tunnel ID", "Queue Depth (packets)", "Queue Time (ms)",
            "Switch Time (ms)", "Interarrival Time (ms)", "Packet Length (Bytes)",
            "Sending Rate (bps)", "Throughput (bps)", "Digest Timestamp (ms)",
            "Total Byte Count", "Total Packet Count", "Weak Learner"
        ])
        empty_df.to_excel(self.filename, index=False)

    def save_to_excel_time(self, switch, tunnel_id, queue_depth, queue_time, switch_time,
                           ):
        data = {
            "Switch": [switch],
            "Tunnel ID": [tunnel_id],
            "Queue Depth (packets)": [queue_depth],
            "Queue Time (ms)": [queue_time],
            "Switch Time (ms)": [switch_time],
        }
        new_df = pd.DataFrame(data)

        if os.path.exists(self.filename_time):

            existing_df = pd.read_excel(self.filename_time)
            updated_df = pd.concat([existing_df, new_df], ignore_index=True)
        else:

            updated_df = new_df

        updated_df.to_excel(self.filename_time, index=False)

        print(f"📊 Dati salvati con successo in {self.filename_time}")

    def save_to_excel(self, switch, tunnel_id, queue_depth, queue_time, switch_time,
                      interarrival_time, packet_length, sending_rate, throughput,
                      digest_timestamp, total_byte_count, total_packet_count, is_WL, processing_time):

        data = {
            "Switch": [switch],
            "Tunnel ID": [tunnel_id],
            "Queue Depth (packets)": [queue_depth],
            "Queue Time (ms)": [queue_time],
            "Switch Time (ms)": [switch_time],
            "Interarrival Time (ms)": [interarrival_time],
            "Packet Length (Bytes)": [packet_length],
            "Sending Rate (bps)": [sending_rate],
            "Throughput (bps)": [throughput],
            "Digest Timestamp (ms)": [digest_timestamp],
            "Total Byte Count": [total_byte_count],
            "Total Packet Count": [total_packet_count],
            "Weak Learner": ["Yes" if is_WL == 1 else "No"],
            "processing time": [processing_time]
        }

        new_df = pd.DataFrame(data)

        if os.path.exists(self.filename):

            existing_df = pd.read_excel(self.filename)
            updated_df = pd.concat([existing_df, new_df], ignore_index=True)
        else:
            # Se non esiste, crea un nuovo DataFrame
            updated_df = new_df

        # Salva i dati in un file Excel
        updated_df.to_excel(self.filename, index=False)

        print(f"📊 Dati salvati con successo in {self.filename}")

    def update_digest_timestamp(self, switch, tunnel_id, digest_timestamp, total_byte_count):
        current_byte = total_byte_count
        current_time = digest_timestamp
        key = (switch, tunnel_id)

        if key in self.last_timestamps and key in self.last_byte_count:
            delta_time = current_time - self.last_timestamps[key]
            delta_byte = current_byte - self.last_byte_count[key]
            throughput = delta_byte * 8 / delta_time
            print(f"throughput: {throughput} bps")
            self.throughput_gauge.labels(switch=switch, flow=tunnel_id).set(
                throughput)
        else:
            delta_time = 0
            throughput = 0

        self.last_timestamps[key] = current_time
        self.last_byte_count[key] = total_byte_count

        print(f"digest delta time for tunnel {tunnel_id}: {delta_time}")
        self.digest_timestamp_gauge.labels(switch=switch, flow=tunnel_id).set(delta_time)
        return throughput

    def interpret_tunnel_id(self, tunnel_id, in_port, switch_name, queue_depth, queue_time, switch_time):

        tunnel_id_str = str(tunnel_id)
        current_switch = switch_name[1:]
        path = list(tunnel_id_str)

        try:

            previous_switch = str(in_port)

            if current_switch == str(in_port):
                raise ValueError(f"first switch for {tunnel_id}")

            port = SWITCH_PORTS['s' + previous_switch][switch_name]
            print(
                f" s{previous_switch} port {port}, queue depth: {queue_depth}")

            self.switch_port_queue_depth.labels(switch=previous_switch, port=port).set(queue_depth)
            self.queue_time_gauge.labels(switch=previous_switch, flow=tunnel_id).set(queue_time)
            self.switch_time_gauge.labels(switch=previous_switch, flow=tunnel_id).set(switch_time)
            # self.save_to_excel_time(previous_switch, tunnel_id, queue_depth, queue_time, switch_time)

            return previous_switch
        except ValueError as e:
            print("Error when interpreting tunnel_id:", e)
            return None

    def handle_digest_for_switch(self, switch, message, processing_time):
        try:

            print("Received DigestList message from switch:", switch.name)
            digest = message.digest
            print("===============================")

            digest_message_list = digest.data

            for members in digest_message_list:
                if members.WhichOneof('data') == 'struct':
                    struct_members = members.struct.members

                    if len(struct_members) >= 5:

                        if struct_members[0].WhichOneof('data') == 'bitstring':
                            tunnel_id_bytes = struct_members[0].bitstring
                            tunnel_id = int.from_bytes(tunnel_id_bytes, byteorder='big')
                            print(f"Tunnel ID: {tunnel_id}")
                        if struct_members[1].WhichOneof('data') == 'bitstring':
                            in_port_bytes = struct_members[1].bitstring
                            in_port = int.from_bytes(in_port_bytes,
                                                         byteorder='big')
                            print(f"IN port: {in_port}")

                        if struct_members[2].WhichOneof('data') == 'bitstring':
                            switch_time_bytes = struct_members[2].bitstring
                            switch_time = int.from_bytes(switch_time_bytes,
                                                         byteorder='big') / 1000000  # Converti in ms
                            print(f"Switch Time: {switch_time} ms")

                        if struct_members[3].WhichOneof('data') == 'bitstring':
                            queue_depth_bytes = struct_members[3].bitstring
                            queue_depth = int.from_bytes(queue_depth_bytes, byteorder='big')
                            print(f"Queue Depth: {queue_depth} packets")

                        if struct_members[4].WhichOneof('data') == 'bitstring':
                            interarrival_time_bytes = struct_members[4].bitstring
                            interarrival_time = int.from_bytes(interarrival_time_bytes,
                                                               byteorder='big') / 1000000
                            print(f"Interarrival Time: {interarrival_time} ms")
                            self.interarrival_time_gauge.labels(switch=switch.name, flow=tunnel_id).set(
                                interarrival_time)

                        if struct_members[5].WhichOneof('data') == 'bitstring':
                            packet_length_bytes = struct_members[5].bitstring
                            packet_length = int.from_bytes(packet_length_bytes, byteorder='big')
                            print(f"Packet Length: {packet_length} bytes")
                            self.packet_length_gauge.labels(switch=switch.name, flow=tunnel_id).set(
                                packet_length)

                        if struct_members[6].WhichOneof('data') == 'bitstring':
                            queue_time_bytes = struct_members[6].bitstring
                            queue_time = int.from_bytes(queue_time_bytes,
                                                        byteorder='big') / 1000000  # Converti in ms
                            print(f"Queue Time: {queue_time} ms")
                        if struct_members[7].WhichOneof('data') == 'bitstring':
                            digest_timestamp_bytes = struct_members[7].bitstring
                            digest_timestamp = int.from_bytes(digest_timestamp_bytes,
                                                              byteorder='big') / 1000000  # Converti in ms
                            print(f"Timestamp Digest Time: {digest_timestamp} ms")
                        if struct_members[8].WhichOneof('data') == 'bitstring':
                            byte_count_bytes = struct_members[8].bitstring
                            byte_count = int.from_bytes(byte_count_bytes,
                                                        byteorder='big')
                            print(f"Byte count: {byte_count} byte")
                            self.total_byte_gauge.labels(switch=switch.name, flow=tunnel_id).set(
                                byte_count)
                        if struct_members[9].WhichOneof('data') == 'bitstring':
                            packet_count_bytes = struct_members[9].bitstring
                            packet_count = int.from_bytes(packet_count_bytes,
                                                          byteorder='big')
                            print(f"Packet count: {packet_count} ")
                            self.total_packet_gauge.labels(switch=switch.name, flow=tunnel_id).set(
                                packet_count)
                        if struct_members[10].WhichOneof('data') == 'bitstring':
                            is_WL = int.from_bytes(struct_members[10].bitstring, byteorder='big')
                            if is_WL == 1:
                                print(f"switch {switch.name} is a WL")
                                self.isWLGauge.labels(switch=switch.name, is_WL='1').set(
                                    is_WL)
                            else:
                                print(f"switch {switch.name} is not a WL")
                                self.isWLGauge.labels(switch=switch.name, is_WL='0').set(
                                    is_WL)
                        if struct_members[11].WhichOneof('data') == 'bitstring':
                            is_malicious = int.from_bytes(struct_members[11].bitstring, byteorder='big')
                            if is_malicious == 1:
                                print(f"switch {switch.name} detected malicious flow")
                                self.isMaliciousGauge.labels(switch=switch.name, flow=tunnel_id).set(
                                    is_malicious)
                        if struct_members[12].WhichOneof('data') == 'bitstring':
                            src_port = int.from_bytes(struct_members[12].bitstring, byteorder='big')
                            print(f"source port: {src_port} ")
                        if struct_members[13].WhichOneof('data') == 'bitstring':
                            dst_port = int.from_bytes(struct_members[13].bitstring, byteorder='big')
                            print(f"destination port: {dst_port} ")
                        if struct_members[14].WhichOneof('data') == 'bitstring':
                            ip_bytes = struct_members[14].bitstring
                            src_ip = ".".join(str(b) for b in ip_bytes)
                            print(f"source ip: {src_ip}")
                        if struct_members[15].WhichOneof('data') == 'bitstring':
                            ip_bytes = struct_members[15].bitstring
                            dst_ip = ".".join(str(b) for b in ip_bytes)
                            print(f"destination ip: {dst_ip} ")
                        if struct_members[16].WhichOneof('data') == 'bitstring':
                            protocol = int.from_bytes(struct_members[16].bitstring, byteorder='big')
                            if protocol == 6:
                                print(f"Protocol: TCP ")
                            if protocol == 17:
                                print(f"Protocol: UDP ")
                        if is_malicious == 1:
                            protocol_str = 'TCP' if protocol == 6 else 'UDP' if protocol == 17 else str(protocol)

                            self.maliciousFlowGauge.labels(
                                switch=switch.name,
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                src_port=src_port,
                                dst_port=dst_port,
                                protocol=protocol_str,
                                tunnel_id=tunnel_id
                            ).set(1)

                        previous_switch = self.interpret_tunnel_id(tunnel_id, in_port, switch.name, queue_depth, queue_time,
                                                                   switch_time)
                        if (interarrival_time != 0):
                            sending_rate = (packet_length * 8) / interarrival_time
                        else:
                            sending_rate = 0
                        print(f"sending rate: {sending_rate} bps")
                        self.sending_rate_gauge.labels(switch=switch.name, flow=tunnel_id).set(
                            sending_rate)
                        throughput = self.update_digest_timestamp(switch.name, tunnel_id, digest_timestamp, byte_count)
                        current_time = time.time()
                        overhead = current_time - digest_timestamp
                        print(f"current time: {current_time}")
                        self.overhead_Gauge.labels(switch=switch.name, flow=tunnel_id).set(overhead)
                        # self.save_to_excel(switch.name, tunnel_id, queue_depth, queue_time, switch_time,
                        #                   interarrival_time, packet_length, sending_rate, throughput, digest_timestamp,
                        #                   byte_count, packet_count, is_WL, processing_time)


        except KeyboardInterrupt:
            print("Digest handling stopped by user.")
        except Exception as e:
            print(f"Unexpected error in handle_digests for switch {switch.name}: {e}")
