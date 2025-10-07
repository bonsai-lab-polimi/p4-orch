from prometheus_client import Gauge


class WLManager:
    def __init__(self, p4info_helper, switches):
        self.p4info_helper = p4info_helper
        self.switches = switches
        self.isWLGauge = Gauge('weak_learner', 'weak learner', ['switch'])

    def install_wl_rules(self, wl_nodes, switches):
        """
        Install the rules on the 'WL_table' table. If a switch is a WL (i.e., it is in the wl_nodes list),
        install a rule with flag = 1. Otherwise, install a rule with flag = 0.
        """
        i = 1
        for switch in switches.values():
            try:

                print(f"switch value: {switch}")
                if switch.device_id in wl_nodes:
                    flag_value = 1
                    print(f"Installing rule with flag=1 on {switch.name} (WL switch).")
                    table_entry = self.p4info_helper.buildTableEntry(
                        table_name="MyIngress.color_table",
                        match_fields={"meta.color": 00},
                        action_name="MyIngress.set_color",

                        action_params={"color_n": i}
                    )
                    print(table_entry)
                    self.p4info_helper.upsertRule(switch, "MyIngress.color_table", 0, table_entry)
                    i += 1
                    self.isWLGauge.labels(switch=switch.name).set(
                        1)

                else:
                    flag_value = 0
                    print(f"Installing rule with flag=0 on {switch.name} (non-WL switch).")
                    self.isWLGauge.labels(switch=switch.name).set(
                        0)
                port_range = [1, 55]

                table_entry = self.p4info_helper.buildTableEntry(
                    table_name="MyIngress.WL_table",
                    match_fields={"standard_metadata.ingress_port": port_range},
                    action_name="MyIngress.WL_action" if flag_value == 1 else "MyIngress.no_WL_action",

                    action_params={},
                    priority=1
                )


                self.p4info_helper.upsertRule(switch, "MyIngress.WL_table", port_range, table_entry)

            except Exception as e:
                print(f"Error installing rule on {switch}: {e}")
