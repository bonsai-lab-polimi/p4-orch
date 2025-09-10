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


class ArpManager:

    def __init__(self, p4info_helper, switches):
        self.queue_data = {}
        self.lock = threading.Lock()
        self.threads = []
        self.running = True
        self.p4info_helper = p4info_helper

        self.port_map = {sw: {} for sw in switches.values()}
        self.arp_rules = {sw: {} for sw in switches.values()}

        self.bcast = "ff:ff:ff:ff:ff:ff"  # broadcast

    def forwardPacket(self, dst_ip_addr, dst_mac_addr, port, switch):
        try:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (dst_ip_addr, 32)},
                action_name="MyIngress.ipv4_forward",
                action_params={"dstAddr": dst_mac_addr, "port": port}
            )
            self.p4info_helper.upsertRule(switch, "MyIngress.ipv4_lpm", dst_ip_addr, table_entry)
        except Exception as e:
            print(f"Error installing ipv4 forward rule: {e}")

    def writeARPReply(self, sw, in_port, dst_eth_addr, src_eth_addr, port=None):
        try:
            table_name = "MyIngress.arp_exact"
            match_fields = {
                "standard_metadata.ingress_port": in_port,
                "hdr.ethernet.dstAddr": dst_eth_addr,
                "hdr.ethernet.srcAddr": src_eth_addr
            }
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.arp_exact",
                match_fields={
                    "standard_metadata.ingress_port": in_port,
                    "hdr.ethernet.dstAddr": dst_eth_addr,
                    "hdr.ethernet.srcAddr": src_eth_addr
                },
                action_name="MyIngress.arp_reply",
                action_params={
                    "port": port
                })
            self.p4info_helper.upsertRuleMultipleMatch(sw, table_name, match_fields, table_entry)
            print(
                f"Installed ARP Reply rule via P4Runtime. switch: {sw.name}, in port: {in_port}, dest eth: {dst_eth_addr}, out port: {port}")
        except Exception as e:
            print(f"Error installing ARP Reply rule: {e}")

    def writeARPFlood(self, sw, in_port, dst_eth_addr, src_eth_addr):
        try:
            table_name = "MyIngress.arp_exact"
            match_fields = {
                "standard_metadata.ingress_port": in_port,
                "hdr.ethernet.dstAddr": dst_eth_addr,
                "hdr.ethernet.srcAddr": src_eth_addr
            }
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.arp_exact",
                match_fields={
                    "standard_metadata.ingress_port": in_port,
                    "hdr.ethernet.dstAddr": dst_eth_addr,
                    "hdr.ethernet.srcAddr": src_eth_addr
                },
                action_name="MyIngress.flooding",
                action_params={
                }
            )
            self.p4info_helper.upsertRuleMultipleMatch(sw, table_name, match_fields, table_entry)
            print("Installed ARP Flooding rule via P4Runtime.")
        except Exception as e:
            print(f"Error installing ARP Flooding rule: {e}")

    def forward_multicast(self, sw, ingress_port, multicast_group_id=1):
        """
        Forward the multicast packet on all ports in the group except the input port.
        """
        try:

            spanning_tree_ports = TREE.get(sw.name, {}).values()
            host_port = HOST_TO_PORT.get(sw.name, None)
            if host_port:
                all_ports = set(spanning_tree_ports).union({host_port})
            else:
                all_ports = set(spanning_tree_ports)

            output_ports = all_ports - {ingress_port}

            replicas = [{'port': port, 'instance': 0} for port in output_ports]
            # print(f"Filtered replicas for {sw.name}: {replicas}")

            mc_group_entry = self.p4info_helper.buildMCEntry(
                multicast_group_id=multicast_group_id,
                replicas=replicas
            )
            sw.ModifyPREEntry(pre_entry=mc_group_entry)
            # print(f"Forwarded multicast packet on switch {sw.name}, excluding port {ingress_port}.")

        except Exception as e:
            print(f"Error forwarding multicast packet on {sw.name}: {e}")

    def prettify(self, mac_string):

        if isinstance(mac_string, str):
            mac_string = mac_string.encode()
        return ':'.join('%02x' % b for b in mac_string)

    def get_mac_by_ip(self, ip_address):
        for index, (mac, ip) in MAC_IP_MAPPING.items():
            if ip == ip_address:
                return index, mac
        return None, None

    def parse_ethernet_frame(self, packet, switch):
        try:
            if not hasattr(packet, "payload") or not packet.payload:
                raise ValueError("The packet does not contain a valid payload")
            pkt = Ether(_pkt=packet.payload)
            print(f"Parsed Ethernet packet")

            parsed_data = {
                "eth_src": pkt.getlayer(Ether).src,
                "eth_dst": pkt.getlayer(Ether).dst,
                "ether_type": pkt.getlayer(Ether).type,
                "metadata": []
            }
            if hasattr(packet, "metadata"):
                metadata = packet.metadata
                for meta in metadata:
                    metadata_id = meta.metadata_id
                    value = meta.value
                    ingress_port = int.from_bytes(value, byteorder="big")
                    parsed_data["metadata"].append({
                        "metadata_id": metadata_id,
                        "value": value,
                        "ingress_port": ingress_port
                    })
                    parsed_data["ingress_port"] = ingress_port

            if parsed_data["ether_type"] == 0x0806:  # EtherType ARP
                # print("ARP packet rilevato, inizio parsing...")
                self.parse_arp_packet(pkt, parsed_data)
            else:
                print(f"Non-ARP packet, EtherType: {hex(parsed_data['ether_type'])}")

            return parsed_data

        except Exception as e:
            print(f"Error while parsing the Ethernet frame: {e}")
            return None

    def parse_arp_packet(self, payload, parsed_data=None):

        hardware_type = payload.hwtype
        protocol_type = payload.ptype
        operation = payload.op

        sender_mac = payload.hwsrc  # MAC mittente
        sender_ip = payload.psrc  # IP mittente
        target_mac = payload.hwdst  # MAC destinatario
        target_ip = payload.pdst  # IP destinatario
        arp_data = {
            "hardware_type": hardware_type,
            "protocol_type": protocol_type,
            "operation": operation,
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_mac": target_mac,
            "target_ip": target_ip
        }

        if parsed_data:
            parsed_data["arp"] = arp_data

        return arp_data

    def handle_packet_for_switch(self, switch, message):

        try:

            packet = message.packet.payload
            parsed_data = self.parse_ethernet_frame(message.packet, switch)

            if parsed_data:

                eth_src = parsed_data["eth_src"]
                eth_dst = parsed_data["eth_dst"]
                ether_type = parsed_data["ether_type"]
                ingress_port = parsed_data["ingress_port"]
                arp_info = parsed_data["arp"]

                if arp_info:
                    hardware_type = arp_info.get("hardware_type")
                    protocol_type = arp_info.get("protocol_type")
                    operation = arp_info.get("operation")
                    sender_mac = arp_info.get("sender_mac")
                    sender_ip = arp_info.get("sender_ip")

                    target_mac = arp_info.get("target_mac")
                    target_ip = arp_info.get("target_ip")
            else:
                print("Errore durante il parsing del pacchetto.")
            try:
                if ether_type in [2048, 2054]:
                    if eth_src not in self.port_map.get(switch, {}):
                        self.port_map.setdefault(switch, {})[eth_src] = ingress_port

                    if eth_src not in self.arp_rules.get(switch, {}).get(ingress_port, []):
                        self.arp_rules.setdefault(switch, {}).setdefault(ingress_port, {}).setdefault(
                            eth_src, [])

                    if eth_dst == self.bcast:

                        if self.bcast not in self.arp_rules[switch][ingress_port]:
                            self.forward_multicast(switch, ingress_port)
                            self.writeARPFlood(switch, ingress_port, self.bcast, eth_src)
                            self.arp_rules[switch][ingress_port][eth_src].append(self.bcast)

                        packet_out = self.p4info_helper.buildPacketOut(
                            payload=packet,
                            metadata={
                                1: b"\x00\x00",
                                2: (1).to_bytes(2, byteorder='big')
                            }
                        )

                        switch.PacketOut(packet_out)
                    else:

                        if eth_dst not in self.arp_rules[switch][ingress_port][eth_src]:
                            self.writeARPReply(switch, ingress_port, eth_dst, eth_src,
                                               port=self.port_map[switch][eth_dst])
                            self.forwardPacket(target_ip, eth_dst, self.port_map[switch][eth_dst],
                                               switch)
                            self.arp_rules[switch][ingress_port][eth_src].append(eth_dst)

                        if eth_src not in self.arp_rules[switch][self.port_map[switch][eth_dst]][eth_dst]:
                            self.writeARPReply(switch, self.port_map[switch][eth_dst],
                                               eth_src, eth_dst,
                                               port=ingress_port)
                            self. forwardPacket(sender_ip, eth_src, ingress_port, switch)
                            self.arp_rules[switch][self.port_map[switch][eth_dst]][eth_dst].append(
                                eth_src)

            except KeyError as ke:
                print(f"KeyError handling ARP table: {ke}")
            except Exception as e:
                print(f"Error handling ARP traffic: {e}")

        except KeyboardInterrupt:
            print("Digest handling stopped by user.")
        except Exception as e:
            print(f"Unexpected error in handle_digests for switch {switch.name}: {e}")
