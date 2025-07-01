class WLManager:
    def __init__(self, p4info_helper, switches):
        self.p4info_helper = p4info_helper
        self.switches = switches

    def install_wl_rules(self, wl_nodes, switches):
        """
        Install the rules on the 'WL_table' table. If a switch is a WL (i.e., it is in the wl_nodes list),
        install a rule with flag = 1. Otherwise, install a rule with flag = 0.
        """
        i = 1
        for node_id in wl_nodes:
            try:
                switch = switches[node_id]
                if switch:

                    print(f"Installing rule with flag=1 and color={i} on {switch.name} (WL switch).")
                    self.inizializeWL(switch, i)
                    self.addSetColorRule("MyIngress.color_table", 0, "MyIngress.set_color", i, switch)
                    i += 1
                else:
                    print(f"Switch with node_id {node_id} not found.")
            except Exception as e:
                print(f"Error installing rule on {switch}: {e}")

        for switch in switches.values():
            try:

                print(f"switch value: {switch}")
                if switch.device_id in wl_nodes:
                    flag_value = 1
                    print(f"Installing rule with flag=1 on {switch.name} (WL switch).")
                else:
                    flag_value = 0
                    print(f"Installing rule with flag=0 on {switch.name} (non-WL switch).")
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

    def inizializeWL(self, switch, i):

        # self.setDefaultAction("MyIngress.ack_flag", "MyIngress.ack_fl", switch)
        # self.setDefaultAction("MyIngress.urg_flag", "MyIngress.urg_fl", switch)
        # self.setDefaultAction("MyIngress.psh_flag", "MyIngress.psh_fl", switch)
        # self.setDefaultAction("MyIngress.rst_flag", "MyIngress.rst_fl", switch)
        # self.setDefaultAction("MyIngress.syn_flag", "MyIngress.s_fl", switch)
        # self.setDefaultAction("MyIngress.f_header_len", "MyIngress.fwd_header", switch)
        # self.setDefaultAction("MyIngress.f_pkt_len_min", "MyIngress.calc_min_fwd", switch)
        # self.setDefaultAction("MyIngress.f_pkt_len_max", "MyIngress.calc_max_fwd", switch)
        # self.setDefaultAction("MyIngress.f_pkt_len_mean", "MyIngress.calc_Length_fwd_mean", switch)
        # self.setDefaultAction("MyIngress.f_iat_min", "MyIngress.fwd_iat_min", switch)
        # self.setDefaultAction("MyIngress.f_iat_max", "MyIngress.fwd_iat_max", switch)
        # self.setDefaultAction("MyIngress.f_iat_tot", "MyIngress.fwd_iat_tot", switch)
        # self.setDefaultAction("MyIngress.f_iat_mean", "MyIngress.fwd_iat_mean", switch)
        # self.setDefaultAction("MyIngress.fin_flag", "MyIngress.f_fl", switch)
        self.addCheckFeatureRule("MyIngress.level1",
                                 {"meta.node_id": 0, "meta.prevFeature": 0, "meta.isTrue": 1},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 1, "f_inout": 12, "threshold": 483}, switch)

        self.addCheckFeatureRule("MyIngress.level2",
                                 {"meta.node_id": 1, "meta.prevFeature": 12, "meta.isTrue": 1},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 2, "f_inout": 20, "threshold": 62}, switch)
        if i == 1:
            self.addCheckFeatureRule("MyIngress.level2",
                                     {"meta.node_id": 1, "meta.prevFeature": 12, "meta.isTrue": 0},
                                     "MyIngress.SetClass",
                                     {"node_id": 10, "class": 1}, switch)

        self.addSetClassRule("MyIngress.level3",
                             {"meta.node_id": 2, "meta.prevFeature": 20, "meta.isTrue": 1},
                             "MyIngress.SetClass",
                             {"node_id": 3, "class": 0}, switch)

        if i == 1:
            self.addCheckFeatureRule("MyIngress.level3",
                                     {"meta.node_id": 2, "meta.prevFeature": 20, "meta.isTrue": 0},
                                     "MyIngress.CheckFeature",
                                     {"node_id": 4, "f_inout": 7, "threshold": 51}, switch)
        if (i == 2) or (i == 3):
            self.addCheckFeatureRule("MyIngress.level3",
                                     {"meta.node_id": 2, "meta.prevFeature": 20, "meta.isTrue": 0},
                                     "MyIngress.CheckFeature",
                                     {"node_id": 4, "f_inout": 7, "threshold": 11}, switch)

        self.addCheckFeatureRule("MyIngress.level4",
                                 {"meta.node_id": 4, "meta.prevFeature": 7, "meta.isTrue": 1},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 5, "f_inout": 1, "threshold": 0}, switch)

        self.addCheckFeatureRule("MyIngress.level5",
                                 {"meta.node_id": 5, "meta.prevFeature": 1, "meta.isTrue": 1},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 6, "f_inout": 30, "threshold": 24059500}, switch)

        self.addCheckFeatureRule("MyIngress.level6",
                                 {"meta.node_id": 6, "meta.prevFeature": 30, "meta.isTrue": 1},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 7, "f_inout": 29, "threshold": 7365500}, switch)

        self.addCheckFeatureRule("MyIngress.level7",
                                 {"meta.node_id": 7, "meta.prevFeature": 29, "meta.isTrue": 1},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 8, "f_inout": 29, "threshold": 76500}, switch)

        self.addSetClassRule("MyIngress.level8",
                             {"meta.node_id": 8, "meta.prevFeature": 29, "meta.isTrue": 1},
                             "MyIngress.SetClass",
                             {"node_id": 9, "class": 1}, switch)

        self.addSetClassRule("MyIngress.level8",
                             {"meta.node_id": 8, "meta.prevFeature": 29, "meta.isTrue": 0},
                             "MyIngress.SetClass",
                             {"node_id": 10, "class": 1}, switch)

        self.addCheckFeatureRule("MyIngress.level7",
                                 {"meta.node_id": 7, "meta.prevFeature": 29, "meta.isTrue": 0},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 11, "f_inout": 32, "threshold": 24058000}, switch)

        self.addSetClassRule("MyIngress.level8",
                             {"meta.node_id": 11, "meta.prevFeature": 32, "meta.isTrue": 1},
                             "MyIngress.SetClass",
                             {"node_id": 12, "class": 1}, switch)

        self.addSetClassRule("MyIngress.level8",
                             {"meta.node_id": 11, "meta.prevFeature": 32, "meta.isTrue": 0},
                             "MyIngress.SetClass",
                             {"node_id": 13, "class": 1}, switch)

        self.addCheckFeatureRule("MyIngress.level6",
                                 {"meta.node_id": 6, "meta.prevFeature": 30, "meta.isTrue": 0},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 14, "f_inout": 29, "threshold": 130709000}, switch)

        self.addCheckFeatureRule("MyIngress.level7",
                                 {"meta.node_id": 14, "meta.prevFeature": 29, "meta.isTrue": 1},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 15, "f_inout": 29, "threshold": 18500}, switch)

        self.addSetClassRule("MyIngress.level8",
                             {"meta.node_id": 15, "meta.prevFeature": 29, "meta.isTrue": 1},
                             "MyIngress.SetClass",
                             {"node_id": 16, "class": 1}, switch)

        self.addSetClassRule("MyIngress.level8",
                             {"meta.node_id": 15, "meta.prevFeature": 29, "meta.isTrue": 0},
                             "MyIngress.SetClass",
                             {"node_id": 17, "class": 1}, switch)

        self.addCheckFeatureRule("MyIngress.level7",
                                 {"meta.node_id": 14, "meta.prevFeature": 29, "meta.isTrue": 0},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 18, "f_inout": 29, "threshold": 513448992}, switch)

        self.addSetClassRule("MyIngress.level8",
                             {"meta.node_id": 18, "meta.prevFeature": 29, "meta.isTrue": 1},
                             "MyIngress.SetClass",
                             {"node_id": 19, "class": 1}, switch)

        self.addSetClassRule("MyIngress.level8",
                             {"meta.node_id": 18, "meta.prevFeature": 29, "meta.isTrue": 0},
                             "MyIngress.SetClass",
                             {"node_id": 20, "class": 0}, switch)

        self.addCheckFeatureRule("MyIngress.level5",
                                 {"meta.node_id": 5, "meta.prevFeature": 1, "meta.isTrue": 0},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 21, "f_inout": 13, "threshold": 26}, switch)

        if i == 2:
            self.addSetClassRule("MyIngress.level6",
                                 {"meta.node_id": 21, "meta.prevFeature": 13, "meta.isTrue": 1},
                                 "MyIngress.SetClass",
                                 {"node_id": 22, "class": 0}, switch)
        if i == 1 or i == 3:
            self.addSetClassRule("MyIngress.level6",
                                 {"meta.node_id": 21, "meta.prevFeature": 13, "meta.isTrue": 1},
                                 "MyIngress.SetClass",
                                 {"node_id": 22, "class": 1}, switch)

        self.addSetClassRule("MyIngress.level6",
                             {"meta.node_id": 21, "meta.prevFeature": 13, "meta.isTrue": 0},
                             "MyIngress.SetClass",
                             {"node_id": 23, "class": 0}, switch)

        self.addCheckFeatureRule("MyIngress.level4",
                                 {"meta.node_id": 4, "meta.prevFeature": 7, "meta.isTrue": 0},
                                 "MyIngress.CheckFeature",
                                 {"node_id": 24, "f_inout": 30, "threshold": 87363000}, switch)

        self.addSetClassRule("MyIngress.level5",
                             {"meta.node_id": 24, "meta.prevFeature": 30, "meta.isTrue": 1},
                             "MyIngress.SetClass",
                             {"node_id": 25, "class": 0}, switch)
        if i == 1:
            self.addSetClassRule("MyIngress.level5",
                                 {"meta.node_id": 24, "meta.prevFeature": 30, "meta.isTrue": 0},
                                 "MyIngress.SetClass",
                                 {"node_id": 26, "class": 0}, switch)

    def setDefaultAction(self, table_name, action_name, switch):
        try:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name=table_name,
                action_name=action_name
            )
            switch.WriteTableEntry(table_entry)
            print(f"Set default action for {table_name} to {action_name}")

        except Exception as e:
            print(f"Error setting default action: {e}")

    def addCheckFeatureRule(self, table_name, match_fields, action_name, action_params, switch):
        try:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name=table_name,
                match_fields=match_fields,
                action_name=action_name,
                action_params=action_params
            )
            self.p4info_helper.upsertRuleMultipleMatch(switch, table_name, match_fields, table_entry)
            print(f"Added rule to {table_name}: {match_fields} => {action_params}")
        except Exception as e:
            print(f"Error adding rule to {table_name}: {e}")

    def addSetClassRule(self, table_name, match_fields, action_name, action_params, switch):
        try:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name=table_name,
                match_fields=match_fields,
                action_name=action_name,
                action_params=action_params
            )
            self.p4info_helper.upsertRuleMultipleMatch(switch, table_name, match_fields, table_entry)
            print(f"Added SetClass rule to {table_name}: {match_fields} => {action_params}")
        except Exception as e:
            print(f"Error adding SetClass rule to {table_name}: {e}")

    def addSetColorRule(self, table_name, match_color, action_name, color_value, switch):
        try:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name=table_name,
                match_fields={"meta.color": match_color},
                action_name=action_name,
                action_params={"color_n": color_value}
            )
            self.p4info_helper.upsertRule(switch, table_name, match_color, table_entry)
            print(f"Added color rule to {table_name}: match {match_color} => color {color_value}")
        except Exception as e:
            print(f"Error adding color rule to {table_name}: {e}")

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
