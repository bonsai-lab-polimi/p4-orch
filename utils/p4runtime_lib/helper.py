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
import re
import ipaddress
import google.protobuf.text_format
from p4.v1 import p4runtime_pb2
from p4.config.v1 import p4info_pb2

from .convert import encode


class P4InfoHelper(object):
    def __init__(self, p4_info_filepath):
        p4info = p4info_pb2.P4Info()
        # Load the p4info file into a skeleton P4Info object
        with open(p4_info_filepath) as p4info_f:
            google.protobuf.text_format.Merge(p4info_f.read(), p4info,
                                              allow_unknown_field=True)
        self.p4info = p4info

    def get(self, entity_type, name=None, id=None):
        if name is not None and id is not None:
            raise AssertionError("name or id must be None")

        for o in getattr(self.p4info, entity_type):
            pre = o.preamble
            if name:
                if (pre.name == name or pre.alias == name):
                    return o
            else:
                if pre.id == id:
                    return o

        if name:
            raise AttributeError("Could not find %r of type %s" % (name, entity_type))
        else:
            raise AttributeError("Could not find id %r of type %s" % (id, entity_type))

    def get_id(self, entity_type, name):
        return self.get(entity_type, name=name).preamble.id

    def get_name(self, entity_type, id):
        return self.get(entity_type, id=id).preamble.name

    def get_alias(self, entity_type, id):
        return self.get(entity_type, id=id).preamble.alias

    def get_registers_id(self, name):
        return self.get_id("registers", name)

    def __getattr__(self, attr):
        # Synthesize convenience functions for name to id lookups for top-level entities
        # e.g. get_tables_id(name_string) or get_actions_id(name_string)
        m = re.search(r"^get_(\w+)_id$", attr)
        if m:
            primitive = m.group(1)
            return lambda name: self.get_id(primitive, name)

        # Synthesize convenience functions for id to name lookups
        # e.g. get_tables_name(id) or get_actions_name(id)
        m = re.search(r"^get_(\w+)_name$", attr)
        if m:
            primitive = m.group(1)
            return lambda id: self.get_name(primitive, id)

        raise AttributeError("%r object has no attribute %r" % (self.__class__, attr))

    def get_match_field(self, table_name, name=None, id=None):
        for t in self.p4info.tables:
            pre = t.preamble
            if pre.name == table_name:
                for mf in t.match_fields:
                    if name is not None:
                        if mf.name == name:
                            return mf
                    elif id is not None:
                        if mf.id == id:
                            return mf
        raise AttributeError("%r has no attribute %r" % (table_name, name if name is not None else id))

    def get_match_field_id(self, table_name, match_field_name):
        return self.get_match_field(table_name, name=match_field_name).id

    def get_match_field_name(self, table_name, match_field_id):
        return self.get_match_field(table_name, id=match_field_id).name

    def get_match_field_pb(self, table_name, match_field_name, value):
        p4info_match = self.get_match_field(table_name, match_field_name)
        bitwidth = p4info_match.bitwidth
        p4runtime_match = p4runtime_pb2.FieldMatch()
        p4runtime_match.field_id = p4info_match.id
        match_type = p4info_match.match_type
        if match_type == p4info_pb2.MatchField.EXACT:
            exact = p4runtime_match.exact
            exact.value = encode(value, bitwidth)
        elif match_type == p4info_pb2.MatchField.LPM:
            lpm_entry = p4runtime_match.lpm
            lpm_entry.value = encode(value[0], bitwidth)
            lpm_entry.prefix_len = value[1]
        elif match_type == p4info_pb2.MatchField.TERNARY:
            ternary_entry = p4runtime_match.ternary
            ternary_entry.value = encode(value[0], bitwidth)
            ternary_entry.mask = encode(value[1], bitwidth)
        elif match_type == p4info_pb2.MatchField.RANGE:
            range_entry = p4runtime_match.range
            range_entry.low = encode(value[0], bitwidth)
            range_entry.high = encode(value[1], bitwidth)
        else:
            raise Exception("Unsupported match type with type %r" % match_type)
        return p4runtime_match

    def get_match_field_value(self, match_field):
        match_type = match_field.WhichOneof("field_match_type")
        if match_type == 'valid':
            return match_field.valid.value
        elif match_type == 'exact':
            return match_field.exact.value
        elif match_type == 'lpm':
            return (match_field.lpm.value, match_field.lpm.prefix_len)
        elif match_type == 'ternary':
            return (match_field.ternary.value, match_field.ternary.mask)
        elif match_type == 'range':
            return (match_field.range.low, match_field.range.high)
        else:
            raise Exception("Unsupported match type with type %r" % match_type)

    def get_action_param(self, action_name, name=None, id=None):
        for a in self.p4info.actions:
            pre = a.preamble
            if pre.name == action_name:
                for p in a.params:
                    if name is not None:
                        if p.name == name:
                            return p
                    elif id is not None:
                        if p.id == id:
                            return p
        raise AttributeError(
            "action %r has no param %r, (has: %r)" % (action_name, name if name is not None else id, a.params))

    def get_action_param_id(self, action_name, param_name):
        return self.get_action_param(action_name, name=param_name).id

    def get_action_param_name(self, action_name, param_id):
        return self.get_action_param(action_name, id=param_id).name

    def get_action_param_pb(self, action_name, param_name, value):
        p4info_param = self.get_action_param(action_name, param_name)
        p4runtime_param = p4runtime_pb2.Action.Param()
        p4runtime_param.param_id = p4info_param.id
        p4runtime_param.value = encode(value, p4info_param.bitwidth)
        return p4runtime_param

    # get metadata
    def get_metadata_pb(self, metadata_id, value):
        p4runtime_metadata = p4runtime_pb2.PacketMetadata()
        p4runtime_metadata.metadata_id = metadata_id
        p4runtime_metadata.value = value
        return p4runtime_metadata

    def buildTableEntry(self,
                        table_name,
                        match_fields=None,
                        default_action=False,
                        action_name=None,
                        action_params=None,
                        priority=None):
        try:
            table_entry = p4runtime_pb2.TableEntry()
            table_entry.table_id = self.get_tables_id(table_name)

            if priority is not None:
                table_entry.priority = priority

            if match_fields:
                table_entry.match.extend([
                    self.get_match_field_pb(table_name, match_field_name, value)
                    for match_field_name, value in match_fields.items()
                ])

            if default_action:
                table_entry.is_default_action = True

            if action_name:
                action = table_entry.action.action
                action.action_id = self.get_actions_id(action_name)
                if action_params:
                    action.params.extend([
                        self.get_action_param_pb(action_name, field_name, value)
                        for field_name, value in action_params.items()
                    ])

            print("table entry built")
            return table_entry

        except Exception as e:

            print(f"Error during the construction of the table entry '{table_name}': {str(e)}")
            return None

        # get packetout

    def buildPacketOut(self, payload, metadata=None):
        try:
            packet_out = p4runtime_pb2.PacketOut()
            packet_out.payload = payload

            if metadata:
                for metadata_id, value in metadata.items():
                    if not isinstance(value, bytes):
                        raise ValueError(
                            f"error value")

                    metadata_pb = self.get_metadata_pb(metadata_id, value)
                    packet_out.metadata.append(metadata_pb)

            return packet_out

        except Exception as e:

            print(f"An error occurred during the construction of the PacketOut: {e}")
            return None

    def buildDigestEntry(self, digest_name=None):
        digest_entry = p4runtime_pb2.DigestEntry()

        digest_entry.digest_id = self.get_digests_id(digest_name)

        digest_entry.config.max_timeout_ns = 100000000
        digest_entry.config.max_list_size = 10
        digest_entry.config.ack_timeout_ns = 500000000
        return digest_entry

    def buildDigestAck(self, digest_id, list_id):
        try:

            digest_ack = p4runtime_pb2.DigestListAck()
            digest_ack.digest_id = digest_id
            digest_ack.list_id = list_id
            return digest_ack

        except Exception as e:

            print(f"⚠️ Error when constructing DigestListAck: {e}")
            return None

    def buildMCEntry(self, multicast_group_id, replicas):
        try:
            mc_entry = p4runtime_pb2.PacketReplicationEngineEntry()
            mc_entry.multicast_group_entry.multicast_group_id = multicast_group_id

            for replica in replicas:
                try:

                    r = p4runtime_pb2.Replica()
                    r.port = bytes([replica['port']])
                    r.instance = replica['instance']
                    mc_entry.multicast_group_entry.replicas.extend([r])
                except KeyError as ke:
                    print(
                        f"Error: Missing key in replica {replica}. Required keys: 'egress_port', 'instance'. Error: {ke}")
                except Exception as e:
                    print(f"Unexpected error building replica {replica}: {e}")

            return mc_entry
        except Exception as e:
            print(f"Error building multicast entry with ID {multicast_group_id}: {e}")
            return None

    def buildCloneSessionEntry(self, clone_session_id, replicas, packet_length_bytes=0):
        clone_entry = p4runtime_pb2.PacketReplicationEngineEntry()
        clone_entry.clone_session_entry.session_id = clone_session_id
        clone_entry.clone_session_entry.packet_length_bytes = packet_length_bytes
        clone_entry.clone_session_entry.class_of_service = 0  # PI currently supports only CoS=0 for clone session entry
        for replica in replicas:
            r = p4runtime_pb2.Replica()
            r.egress_port = replica['egress_port']
            r.instance = replica['instance']
            clone_entry.clone_session_entry.replicas.extend([r])
        return clone_entry

    def upsertRule(self, sw, table_name, match_fields, table_entry):
        """
        Checks whether a rule exists in the table. If it exists, it modifies it; otherwise, it inserts it.

        :param table_entry:
        :param sw: Switch on which to apply the rule.
        :param table_name: Name of the table to operate on.
        :param match_fields: Match fields for the rule.
        :param action_name: Name of the action to apply.
        :param action_params: Parameters of the action.
        """
        try:
            existing_rule = None
            for response in sw.ReadTableEntries():

                for entity in response.entities:
                    entry = entity.table_entry
                    current_table_name = self.get_tables_name(entry.table_id)

                    if current_table_name == table_name:
                        print(f"entry match:{entry.match}")
                        for m in entry.match:

                            match_field_name = self.get_match_field_name(table_name, m.field_id)

                            match_field_value = self.get_match_field_value(m)
                            print(f"match field value:{match_field_value}")

                            formatted_value = self.format_match_value(match_field_value)
                            print(f"formatted value: {formatted_value}")
                            print(f"value search: {match_fields}")

                            if formatted_value == match_fields:
                                print("rule found")

                                existing_rule = entry

                                break

            if existing_rule:

                print(f"Existing rule found, I modify the rule...")
                sw.ModifyTableEntry(table_entry)
                print(f"Rule successfully modified in the table {table_name}.")
            else:
                print("Rule not found, I will proceed with insertion...")
                sw.WriteTableEntry(table_entry)
                print(f"Rule successfully inserted in the table {table_name}.")



        except Exception as e:
            print(f"Error when entering or editing the rule: {e}")

    def upsertRuleMultipleMatch(self, sw, table_name, match_fields, table_entry):
        """
        Checks whether a rule exists in the table. If it exists, it modifies it; otherwise, it inserts it.
        """
        try:
            existing_rule = None

            for response in sw.ReadTableEntries():
                for entity in response.entities:
                    entry = entity.table_entry
                    current_table_name = self.get_tables_name(entry.table_id)

                    if current_table_name == table_name:

                        entry_match_fields = {}

                        for m in entry.match:
                            match_field_name = self.get_match_field_name(table_name, m.field_id)
                            match_field_value = self.get_match_field_value(m)
                            formatted_value = self.format_match_value(match_field_value)

                            entry_match_fields[match_field_name] = formatted_value

                        print(f"Entry match fields: {entry_match_fields}")
                        print(f"Searching for: {match_fields}")


                        if entry_match_fields == match_fields:
                            print("Rule found!")
                            existing_rule = entry
                            break

            if existing_rule:
                print("Existing rule found, modifying the rule...")
                sw.ModifyTableEntry(table_entry)
                print(f"Rule successfully modified in table {table_name}.")
            else:
                print("Rule not found, proceeding with insertion...")
                sw.WriteTableEntry(table_entry)
                print(f"Rule successfully inserted in table {table_name}.")

        except Exception as e:
            print(f"Error in upsertRule: {e}")

    def format_match_value(self, value):
        """
        Format the value of a match field.
        This example handles IP addresses, MAC addresses, tuples (ranges), and generic values.
        You can extend it for other types of match fields.

        :param value: The value to be formatted (such as an IP address or a generic value).
        :return: The formatted value.
        """
        if isinstance(value, tuple):

            if all(isinstance(v, bytes) for v in value):

                return [int(value[0].hex(), 16), int(value[1].hex(), 16)]
            else:

                ip_addr, _ = value
                ip = ipaddress.ip_address(ip_addr)
                return str(ip)

        elif isinstance(value, bytes):

            return int(value.hex(), 16)

        elif isinstance(value, str):
            try:
                int(value, 16)
                return value.lower()
            except ValueError:
                return value.lower()

        elif isinstance(value, int):
            return value

        else:
            return value
