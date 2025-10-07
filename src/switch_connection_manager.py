 #!/usr/bin/env python3
import argparse
import os
import sys
import time
import grpc
from config import SWITCH_PORTS, HOST_TO_PORT, NUM_PORTS

# Import P4Runtime lib from parent utils dir

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from config import TREE


class SwitchConnectionManager:
    def __init__(self, p4info_helper, bmv2_file_path, switch_count):
        self.p4info_helper = p4info_helper
        self.switches = {}
        self.switch_count = switch_count
        self.bmv2_file_path = bmv2_file_path

    def create_connections(self):
        for i in range(self.switch_count):
            switch_name = f's{i + 1}'
            self.switches[i] = p4runtime_lib.bmv2.Bmv2SwitchConnection(
                name=switch_name,
                address=f'127.0.0.1:{50050 + i + 1}',
                device_id=i+1,
                proto_dump_file=f'../p4src/logs/{switch_name}-p4runtime-requests.txt'

            )
            print(f"Connection to switch {switch_name}")

    def update_master(self):
        for switch in self.switches.values():
            try:
                switch.MasterArbitrationUpdate()
                print(f"Master arbitration updated for {switch.name}")
            except Exception as e:
                print(f"Error updating master on {switch.name}: {e}")

    def install_p4_program(self):
        for switch in self.switches.values():
            try:
                switch.SetForwardingPipelineConfig(
                    p4info=self.p4info_helper.p4info,
                    bmv2_json_file_path=self.bmv2_file_path
                )

                self.sendDigestEntry(sw=switch, digest_name="congestion_digest_t")
                print(f"Installed P4 Program on {switch.name}")
            except Exception as e:
                print(f"Error installing P4 Program on {switch.name}: {e}")

    def sendDigestEntry(self, sw, digest_name):
        digest_entry = self.p4info_helper.buildDigestEntry(digest_name=digest_name)
        sw.WriteDigestEntry(digest_entry)
        print(
            "Sent DigestEntry via P4Runtime.")

    def get_switches(self):
        return self.switches

    def get_switch(self, index):
        return self.switches.get(index)

    def create_multicast_group(self):
        """
        Configures the multicast group based on spanning tree and includes ports connected to hosts.
        """
        for sw in self.switches.values():
            try:

                spanning_tree_ports = TREE.get(sw.name, {}).values()


                host_port = HOST_TO_PORT.get(sw.name, None)
                if host_port:
                    all_ports = set(spanning_tree_ports).union({host_port})
                else:
                    all_ports = set(spanning_tree_ports)

                # Crea le repliche per tutte le porte valide
                replicas = [{'port': port, 'instance': 0} for port in all_ports]
                print(f"replicas for {sw.name}: {replicas}")

                # Configura il gruppo multicast
                mc_group_entry = self.p4info_helper.buildMCEntry(
                    multicast_group_id=1,  # ID del gruppo multicast
                    replicas=replicas
                )
                sw.WritePREEntry(pre_entry=mc_group_entry)
                print(f"Installed multicast group on switch {sw.name}.")

            except Exception as e:
                print(f"Error installing multicast group on {sw.name}: {e}")
