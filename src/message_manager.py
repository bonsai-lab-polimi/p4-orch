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
import asyncio



class MessageManager:

    def __init__(self, p4info_helper, switches):
        self.queue_data = {}
        self.lock = threading.Lock()
        self.threads = []
        self.running = True
        self.p4info_helper = p4info_helper

        self.port_map = {sw: {} for sw in switches.values()}
        self.arp_rules = {sw: {} for sw in switches.values()}

        self.bcast = "ff:ff:ff:ff:ff:ff"  # broadcast

    async def handle_messages_for_switch(self, switch, arp_manager, digest_manager):
        """
        It handles digest messages for a specific switch via the stream channel.
        """
        eth_src = None
        eth_dst = None
        ether_type = None
        ingress_port = None
        arp_info = None
        metadata_list = []
        try:
            while True:
                try:

                    message, timestamp_received = await switch.PacketIn(timeout=0.5)

                    if message is not None:
                        if message.WhichOneof('update') == 'packet':
                            arp_manager.handle_packet_for_switch(switch, message)

                        if message.WhichOneof('update') == 'digest':
                            digest_manager.handle_digest_for_switch(switch, message, timestamp_received)

                except Exception as e:
                    print(f"Error in processing message for switch {switch.name}: {e}")
        except KeyboardInterrupt:
            print("Message handling stopped by user.")
        except Exception as e:
            print(f"Unexpected error in handle message for switch {switch.name}: {e}")

    async def start(self, switches, arp_manager, digest_manager):
            """
            Start digest management tasks for each switch.
            """
            try:
                print(f"TREE:{TREE}")
                print(f"📡 starting the message management for {len(switches)} switch...")

                tasks = []
                for switch in switches.values():
                    try:

                        tasks.append(asyncio.create_task(switch.listen_for_messages()))
                        tasks.append(
                            asyncio.create_task(self.handle_messages_for_switch(switch, arp_manager, digest_manager)))
                    except Exception as e:
                        print(f"⚠️ Error during task startup for switch {switch}: {e}")

                # Aspetta che tutte le coroutine finiscano
                await asyncio.gather(*tasks)

            except Exception as e:
                print(f"⚠️ Error when starting message tasks.: {e}")

