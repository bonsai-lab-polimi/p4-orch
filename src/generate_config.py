import json
from prometheus_client import start_http_server, Gauge
import time

num_switches = Gauge('num_switches', 'Total number of switches')
num_ports = Gauge('num_ports', 'Total number of ports per switch')
switch_links = Gauge('switch_links', 'Number of connections between switches', ['switch1', 'switch2'])
host_connections = Gauge('host_connections', 'Connections between host and switch', ['host', 'switch'])


def load_topology(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)


def parse_topology(topology):
    HOST_TO_PORT = {}
    SWITCH_PORTS = {s: {} for s in topology["switches"]}
    MAC_IP_MAPPING = {}
    TREE = {}

    # Parse hosts
    for i, (host, data) in enumerate(topology["hosts"].items(), start=1):
        MAC_IP_MAPPING[i] = (data["mac"], data["ip"].split('/')[0])

    # Parse links and switch ports
    for link in topology["links"]:
        if len(link) == 2:
            node1, node2 = link

            # Handle host connections
            if node1.startswith('h'):
                host, switch_port = node1, node2
            elif node2.startswith('h'):
                host, switch_port = node2, node1
            else:
                switch_port = None

            if switch_port:
                switch, port = switch_port.split('-p')
                HOST_TO_PORT[switch] = int(port)
                SWITCH_PORTS.setdefault(switch, {})[host] = int(port)
            else:
                # Handle switch connections
                switch1, port1 = node1.split('-p')
                switch2, port2 = node2.split('-p')
                SWITCH_PORTS[switch1][switch2] = int(port1)
                SWITCH_PORTS[switch2][switch1] = int(port2)

    NUM_SWITCHES = len(topology["switches"])
    NUM_PORTS = max(max(ports.values()) for ports in SWITCH_PORTS.values())

    return HOST_TO_PORT, SWITCH_PORTS, MAC_IP_MAPPING, NUM_SWITCHES, NUM_PORTS, TREE


def generate_config(file_path):
    topology = load_topology(file_path)
    HOST_TO_PORT, SWITCH_PORTS, MAC_IP_MAPPING, NUM_SWITCHES, NUM_PORTS, TREE = parse_topology(topology)
    # Update the Prometheus metrics dynamically based on the topology
    num_switches.set(NUM_SWITCHES)
    num_ports.set(NUM_PORTS)

    # Update switch connections (links between switches)
    for switch1, ports in SWITCH_PORTS.items():
        for switch2, port in ports.items():
            if switch1 != switch2:  # Avoid self-loops
                switch_links.labels(switch1=switch1, switch2=switch2).set(1)

    # Update host connections to switches
    for host, port in HOST_TO_PORT.items():
        host_connections.labels(host=host, switch=port).set(1)
    config = f"""
# Define the host and switch port mappings
HOST_TO_PORT = {HOST_TO_PORT}

SWITCH_PORTS = {SWITCH_PORTS}

# Define the MAC and IP address mappings for hosts
MAC_IP_MAPPING = {MAC_IP_MAPPING}

NUM_SWITCHES = {NUM_SWITCHES}
NUM_PORTS = {NUM_PORTS}

TREE = {TREE}
"""
    return config


def generate():
    file_path = "../p4src/topology.json"
    config_output = generate_config(file_path)
    with open("config.py", "w") as f:
        f.write(config_output)
    print("Generated network_config.py")
