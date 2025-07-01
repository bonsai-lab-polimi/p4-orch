#!/usr/bin/env python3
import argparse
import os
import sys
import time
import grpc
from tabulate import tabulate

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import json


class TableManager:
    def __init__(self, p4info_helper):
        self.p4info_helper = p4info_helper

    def format_match_value(self, value):
        """
        Formats the match value into a readable string.

        :param value: The raw value to format
        :return: A formatted string representation of the value
        """
        if isinstance(value, tuple):
            # If it's a tuple (e.g., for LPM, ternary, or range matches)
            return " | ".join(self.format_match_value(v) for v in value)
        elif isinstance(value, bytes):
            # Convert bytes to a readable hexadecimal format
            return ' '.join(f"{b:02x}" for b in value)  # Display bytes in hex format
        else:
            return str(value)  # Fallback for any other type

    def read_table_rules(self, sw):
        print(f'\n----- Reading table rules for {sw.name} -----')
        table_data = []
        for response in sw.ReadTableEntries():
            for entity in response.entities:
                entry = entity.table_entry
                table_name = self.p4info_helper.get_tables_name(entry.table_id)
                row = {"Table Name": table_name}
                match_fields = []
                for m in entry.match:
                    match_field_name = self.p4info_helper.get_match_field_name(table_name, m.field_id)
                    match_field_value = self.p4info_helper.get_match_field_value(m)
                    match_fields.append(f"{match_field_name}: {self.format_match_value(match_field_value)}")
                row["Match Fields"] = ', '.join(match_fields)
                action = entry.action.action
                action_name = self.p4info_helper.get_actions_name(action.action_id)
                action_params = []
                for p in action.params:
                    action_param_name = self.p4info_helper.get_action_param_name(action_name, p.param_id)
                    action_param_value = p.value
                    action_params.append(f"{action_param_name}: {self.format_match_value(action_param_value)}")
                row["Action"] = action_name
                row["Action Params"] = ', '.join(action_params)
                table_data.append(row)
        headers = ["Table Name", "Match Fields", "Action", "Action Params"]
        print(tabulate(table_data, headers="keys", tablefmt='fancy_grid'))
