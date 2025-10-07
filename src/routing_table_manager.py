#!/usr/bin/env python3
import argparse
import os
import sys
import time
import grpc
from tabulate import tabulate
from pathlib import Path
import json

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections


class TableManager:
    def __init__(self, p4info_helper):
        """
        p4info_helper : instance of your P4Info helper providing get_tables_name,
                        get_match_field_name, get_match_field_value, get_actions_name, get_action_param_name, ...
        """
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
        """
        Reads table entries for a given switch and returns a list of dict rows.

        :param sw: switch connection object (must support ReadTableEntries())
        :return: list of dicts with keys: Table Name, Match Fields, Action, Action Params
        """
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
                row["Match Fields"] = ', '.join(match_fields) if match_fields else ""
                action = entry.action.action
                action_name = self.p4info_helper.get_actions_name(action.action_id)
                action_params = []
                for p in action.params:
                    action_param_name = self.p4info_helper.get_action_param_name(action_name, p.param_id)
                    action_param_value = p.value
                    action_params.append(f"{action_param_name}: {self.format_match_value(action_param_value)}")
                row["Action"] = action_name
                row["Action Params"] = ', '.join(action_params) if action_params else ""
                table_data.append(row)
        return table_data

    def export_tables(self, switches, file_path, fmt=None):
        """
        Exports table data for a list of switches to file. Overwrites existing file.

        :param switches: iterable of switch objects (each should have .name and ReadTableEntries())
        :param file_path: destination file path (string or Path)
        :param fmt: optional: 'xlsx', 'csv', 'md', 'json'. If None, inferred from file extension.
        """
        # gather data
        results = {}
        for sw in switches:
            rows = self.read_table_rules(sw)
            results[sw.name] = rows

        # infer format
        p = Path(file_path)
        if fmt is None:
            suffix = p.suffix.lower()
            if suffix == '.xlsx':
                fmt = 'xlsx'
            elif suffix == '.csv':
                fmt = 'csv'
            elif suffix == '.md' or suffix == '.markdown':
                fmt = 'md'
            elif suffix == '.json':
                fmt = 'json'
            else:
                # default to xlsx if no extension
                fmt = 'xlsx'

        # make parent dirs
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)

        # route to writer
        if fmt == 'xlsx':
            try:
                import pandas as pd
            except ImportError:
                raise RuntimeError("pandas is required for Excel output (install with `pip install pandas openpyxl`).")
            # remove existing file to guarantee overwrite behavior
            if p.exists():
                p.unlink()
            # write one sheet per switch
            with pd.ExcelWriter(p, engine='openpyxl') as writer:
                for sw_name, rows in results.items():
                    # sanitize sheet name (max 31 chars, cannot contain some chars)
                    sheet_name = str(sw_name)[:31].replace("/", "_").replace("\\", "_")
                    df = pd.DataFrame(rows)
                    if df.empty:
                        # write an empty but labelled sheet
                        df = pd.DataFrame([{"Info": "No table entries"}])
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
        elif fmt == 'csv':
            try:
                import pandas as pd
            except ImportError:
                raise RuntimeError("pandas is required for CSV output (install with `pip install pandas`).")
            # flatten all switches into single CSV with a 'Switch' column
            all_rows = []
            for sw_name, rows in results.items():
                for r in rows:
                    r_copy = dict(r)
                    r_copy['Switch'] = sw_name
                    all_rows.append(r_copy)
            df = pd.DataFrame(all_rows)
            # overwrite
            df.to_csv(p, index=False)
        elif fmt == 'md':
            # create a readable markdown file with sections per switch
            with p.open('w', encoding='utf-8') as f:
                for sw_name, rows in results.items():
                    f.write(f"## Switch: {sw_name}\n\n")
                    if not rows:
                        f.write("_No table entries_\n\n")
                        continue
                    headers = ["Table Name", "Match Fields", "Action", "Action Params"]
                    f.write(tabulate(rows, headers=headers, tablefmt='github'))
                    f.write("\n\n")
        elif fmt == 'json':
            # write raw json
            with p.open('w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        # done
        return str(p)

# Example usage:
# tm = TableManager(p4info_helper)
# file_written = tm.export_tables([sw1, sw2, sw3], "/tmp/p4_tables.xlsx")
# print("Wrote:", file_written)
