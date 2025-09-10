from config import SWITCH_PORTS, HOST_TO_PORT


class TunnelManager:
    def __init__(self, p4info_helper, switches):
        self.p4info_helper = p4info_helper
        self.switches = switches

    def write_tunnel_rules(self, ingress_sw, intermediate_switches, egress_sw, tunnel_id, dst_eth_addr, dst_ip_addr):
        tunnel_id_int = int(tunnel_id)

        # Ingress Rule
        try:
            print(f"Installing ingress tunnel rule on {ingress_sw.name}")
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (dst_ip_addr, 32)},
                action_name="MyIngress.myTunnel_ingress",
                action_params={"dst_id": tunnel_id_int}
            )
            self.p4info_helper.upsertRule(ingress_sw, "MyIngress.ipv4_lpm", dst_ip_addr, table_entry)
        except Exception as e:
            print(f"Error installing ingress tunnel rule: {e}")

        # Transit Rules (Intermediate Switches)
        for idx, switch in enumerate(intermediate_switches):
            next_switch = intermediate_switches[idx + 1] if idx + 1 < len(intermediate_switches) else egress_sw
            port_to_forward = SWITCH_PORTS[switch.name][next_switch.name]
            try:
                print(f"Installing transit tunnel rule on {switch.name} forwarding to {next_switch.name}")
                table_entry = self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.myTunnel_exact",
                    match_fields={"hdr.myTunnel.dst_id": tunnel_id_int},
                    action_name="MyIngress.myTunnel_forward",
                    action_params={"port": port_to_forward}
                )
                self.p4info_helper.upsertRule(switch, "MyIngress.myTunnel_exact", tunnel_id_int, table_entry)
            except Exception as e:
                print(f"Error installing transit tunnel rule on {switch.name}: {e}")

        # Egress Rule
        try:
            print(f"Installing egress tunnel rule on {egress_sw.name}")
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.myTunnel_exact",
                match_fields={"hdr.myTunnel.dst_id": tunnel_id_int},
                action_name="MyIngress.myTunnel_egress",
                action_params={"dstAddr": dst_eth_addr, "port": HOST_TO_PORT[egress_sw.name]}
            )
            self.p4info_helper.upsertRule(egress_sw, "MyIngress.myTunnel_exact", tunnel_id_int, table_entry)
        except Exception as e:
            print(f"Error installing egress tunnel rule: {e}")
