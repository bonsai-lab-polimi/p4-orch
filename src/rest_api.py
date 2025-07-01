#!/usr/bin/env python3
import os
import sys
import json
import logging
import re
from fastapi import FastAPI, File, UploadFile
from fastapi import HTTPException

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from prometheus_client import Gauge
from fastapi.responses import Response
from prometheus_fastapi_instrumentator import Instrumentator

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import generate_config
import asyncio

generate_config.generate()

from switch_connection_manager import SwitchConnectionManager
from tunnelling_manager import TunnelManager
from routing_table_manager import TableManager
from counter_manager import CounterManager
# from queue_state_manager import QueueStateManager
from arp_manager import ArpManager
from spanningtree_manager import SpanningTree
from message_manager import MessageManager
from digest_manager import DigestManager
from WL_manager import WLManager
import p4runtime_lib.helper
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from config import MAC_IP_MAPPING
from config import NUM_SWITCHES, SWITCH_PORTS, HOST_TO_PORT
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger('grpc')

app = FastAPI()
instrumentator = Instrumentator()
instrumentator.instrument(app).expose(app)
switches = {}
controller = None
controller_started = False

nodes_gauge = Gauge("file_nodes", "Number of nodes in the input file")
colors_gauge = Gauge("file_colors", "Number of colors in the input file")
runtime_gauge = Gauge("file_runtime", "Runtime of the solution (in seconds)")
solution_cost_gauge = Gauge("file_solution_cost", "Solution cost extracted from the file")
num_nodes_deployed_gauge = Gauge("file_num_nodes_deployed", "Number of deployed nodes")
average_path_weight_gauge = Gauge("file_average_path_weight", "Average path weight")
percentage_covered_gauge = Gauge("file_percentage_covered", "Percentage of paths covered")

routes_gauge = Gauge(
    "file_routes",
    "Shortest paths constrained by coloring",
    labelnames=["from", "to", "path"]
)


# Classe P4Controller
class P4Controller:
    def __init__(self, p4info_file_path=None, bmv2_file_path=None):
        logger.info("Initializing P4Controller")

        if not p4info_file_path:
            p4info_file_path = '../p4src/build/advanced_tunnel.p4.p4info.txt'
        if not bmv2_file_path:
            bmv2_file_path = '../p4src/build/advanced_tunnel.json'

        if not os.path.exists(p4info_file_path):
            logger.error(f"p4info file not found: {p4info_file_path}. Please run 'make'.")
            return
        if not os.path.exists(bmv2_file_path):
            logger.error(f"BMv2 JSON file not found: {bmv2_file_path}. Please run 'make'.")
            return

        self.p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
        self.switch_manager = SwitchConnectionManager(self.p4info_helper, bmv2_file_path, NUM_SWITCHES)
        self.tunnel_manager = TunnelManager(self.p4info_helper, self.switch_manager.switches)
        self.table_manager = TableManager(self.p4info_helper)
        self.digest_manager = DigestManager(self.p4info_helper, self.switch_manager.switches)
        self.arp_manager = ArpManager(self.p4info_helper, self.switch_manager.switches)
        self.message_manager = MessageManager(self.p4info_helper, self.switch_manager.switches)
        self.spanningtree_manager = SpanningTree(SWITCH_PORTS)
        self.counter_manager = CounterManager(self.p4info_helper)
        # self.queue_state_manager = QueueStateManager(self.p4info_helper)
        self.WL_manager = WLManager(self.p4info_helper, self.switch_manager.switches)

    async def run(self):
        global controller_started
        global switches
        try:
            if not controller_started:
                logger.info("Starting switch connections")
                self.switch_manager.create_connections()
                self.switch_manager.update_master()
                controller_started = True
            self.switch_manager.install_p4_program()

            self.spanningtree_manager.build_tree()
            self.switch_manager.create_multicast_group()
            switches = self.switch_manager.get_switches()

            if not switches:
                logger.warning("No switches were found!")
            else:
                # Recreates the dictionary with keys starting at 1 to be consistent with the switch name
                switches = {idx + 1: switch for idx, switch in enumerate(switches.values())}
                logger.info(f"Switches initialized: {switches}")
                # self.WL_manager.inizializeWL(switches)
            await self.message_manager.start(switches, self.arp_manager, self.digest_manager)
            # start_monitoring_threads(switches, controller, self.arp_manager, self.digest_manager)
            # self.arp_manager.start(switches)
            # Monitor tunnel counters with ThreadPoolExecutor
            # logger.info("Starting tunnel counter monitoring using ThreadPoolExecutor")





        except KeyboardInterrupt:
            logger.info("\nGraceful shutdown...")
            ShutdownAllSwitchConnections()
        except Exception as e:
            logger.error(f"Unexpected error during controller run: {e}")
            ShutdownAllSwitchConnections()


def run_controller():
    global controller_started

    logger.info("Starting the P4Controller in a separate thread.")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:

        loop.run_until_complete(controller.run())
    finally:
        loop.close()

    controller_started = False
    logger.info("P4Controller has completed its execution.")


def install_tunnel_rules():
    try:
        # Carica le rotte dai file JSON
        try:
            with open('parsed_data.json', 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Error reading JSON file: {e}")
            return

        routes = {tuple(map(int, key.split(','))): value for key, value in data["routes"].items()}
        logger.info(f"Routes: {routes}")

        tunnels = []

        try:
            for (src_host, dst_host), path in routes.items():
                dst_eth_addr, dst_ip_addr = MAC_IP_MAPPING[dst_host]
                src_eth_addr, src_ip_addr = MAC_IP_MAPPING[src_host]
                tunnels.append(((src_host, dst_host), path, src_eth_addr, src_ip_addr, dst_eth_addr, dst_ip_addr))

                inverted_path = list(reversed(path))
                inverted_src_host, inverted_dst_host = dst_host, src_host
                src_eth_addr, src_ip_addr = MAC_IP_MAPPING[inverted_src_host]
                dst_eth_addr, dst_ip_addr = MAC_IP_MAPPING[inverted_dst_host]

                tunnels.append(((inverted_src_host, inverted_dst_host), inverted_path, src_eth_addr, src_ip_addr,
                                dst_eth_addr, dst_ip_addr))
        except Exception as e:
            logger.error(f"Error while building tunnels: {e}")
            return

        for tunnel in tunnels:
            logger.info(f"Tunnel configuration: {tunnel}")

        tunnel_ids = []
        try:
            for tunnel in tunnels:
                (src_host, dst_host), path, src_eth_addr, src_ip_addr, dst_eth_addr, dst_ip_addr = tunnel
                tunnel_id = ''.join(str(s) for s in path)
                tunnel_ids.append(tunnel_id)
                switches_id = path
                intermediate_switches_id = path[:-1]

                logger.info(f"Path: {path}")
                ingress_sw = switches[src_host]
                logger.info(f"Ingress switch: {ingress_sw.name}")
                egress_sw = switches[dst_host]
                logger.info(f"Egress switch: {egress_sw.name}")

                intermediate_switches = []
                switches_in_path = []
                for i, sw_id in enumerate(intermediate_switches_id, 1):
                    intermediate_switches.append(switches[sw_id])
                    logger.info(f"Intermediate switch {i}: {switches[sw_id].name}")
                for i, sw_id in enumerate(switches_id, 1):
                    switches_in_path.append(switches[sw_id])
                    logger.info(f"switch {i} in path: {switches[sw_id].name}")
                try:
                    controller.tunnel_manager.write_tunnel_rules(
                        ingress_sw, intermediate_switches, egress_sw, tunnel_id, dst_eth_addr, dst_ip_addr
                    )
                except Exception as e:
                    logger.error(f"Error while writing tunnel rules for tunnel {tunnel_id}: {e}")
                    return
                try:

                    print(f"source:{src_eth_addr}, destination:{dst_eth_addr}")

                    path_len = len(switches_id)
                    for i, sw_id in enumerate(switches_id):
                        sw = switches[sw_id]
                        switches_in_path.append(sw)
                        logger.info(f"switch {i + 1} in path: {sw.name}")

                        # Calcolo delle porte
                        if i == 0:
                            # Prima switch: entra dalla porta del primo host
                            in_port = HOST_TO_PORT[sw.name]  # oppure da una mappa predefinita
                            next_sw = switches[switches_id[i + 1]]
                            port = SWITCH_PORTS[sw.name][next_sw.name]
                        elif i == path_len - 1:
                            # Ultimo switch: esce verso l'host finale
                            prev_sw = switches[switches_id[i - 1]]
                            in_port = SWITCH_PORTS[sw.name][prev_sw.name]
                            port = HOST_TO_PORT[sw.name]
                        else:
                            prev_sw = switches[switches_id[i - 1]]
                            next_sw = switches[switches_id[i + 1]]
                            in_port = SWITCH_PORTS[sw.name][prev_sw.name]
                            port = SWITCH_PORTS[sw.name][next_sw.name]

                        controller.arp_manager.writeARPReply(sw, in_port, dst_eth_addr, src_eth_addr, port)



                except Exception as e:
                    logger.error(f"Error while writing tunnel rules for tunnel {tunnel_id}: {e}")
                    return
        except Exception as e:
            logger.error(f"Error processing tunnels: {e}")
            return

        try:
            for switch in switches.values():
                controller.table_manager.read_table_rules(switch)
        except Exception as e:
            logger.error(f"Error reading table rules for switches: {e}")
            return

    except Exception as e:

        logger.error(f"Unexpected error in install_tunnel_rules: {e}")


def start_monitoring_threads(switches, controller, arp_manager, digest_manager):
    loop = asyncio.get_running_loop()
    loop.create_task(controller.message_manager.start(switches, arp_manager, digest_manager))


def extract_info(file_content):
    data = {}

    nodes_match = re.search(r'#nodes = (\d+)', file_content)
    colors_match = re.search(r'#colors = (\d+)', file_content)
    run_time_match = re.search(r'Run time \(s\): ([\d.]+)', file_content)
    solution_cost_match = re.search(r'Solution cost: ([\d.]+)', file_content)

    data["nodes"] = int(nodes_match.group(1)) if nodes_match else None
    data["colors"] = int(colors_match.group(1)) if colors_match else None
    data["run_time"] = float(run_time_match.group(1)) if run_time_match else None
    data["solution_cost"] = float(solution_cost_match.group(1)) if solution_cost_match else None

    # Estrazione della colorazione dei nodi (Deployment)
    deployment_section = re.findall(r'Node (\d+) -> color (\d+)', file_content)
    data["deployment"] = {int(node): int(color) for node, color in deployment_section}

    routes = {}
    constrained_section = re.search(
        r'===== Shortest paths constrained by coloring =====(.*?)Num node deployed:',
        file_content,
        re.DOTALL
    )

    if constrained_section:
        constrained_text = constrained_section.group(1)
        constrained_paths = re.findall(r'\((\d+),(\d+)\) -> \[([0-9, ]+)\]', constrained_text)
        for path in constrained_paths:
            start, end = int(path[0]), int(path[1])
            nodes = list(map(int, path[2].split(',')))
            routes[f"{start},{end}"] = nodes

    data["routes"] = routes

    num_nodes_deployed_match = re.search(r'Num node deployed: (\d+)', file_content)
    average_path_weight_match = re.search(r'Average path weight: ([\d.]+)', file_content)
    percentage_covered_match = re.search(r'Percentage covered: ([\d.]+)%', file_content)

    data["num_nodes_deployed"] = int(num_nodes_deployed_match.group(1)) if num_nodes_deployed_match else None
    data["average_path_weight"] = float(average_path_weight_match.group(1)) if average_path_weight_match else None
    data["percentage_covered"] = float(percentage_covered_match.group(1)) if percentage_covered_match else None

    wl_match = re.search(r'WL: ([0-9,]+)', file_content)
    if wl_match:
        wl_nodes = list(map(int, wl_match.group(1).split(',')))
        data["wl_nodes"] = wl_nodes
    else:
        data["wl_nodes"] = []
    controller.WL_manager.install_wl_rules(wl_nodes, switches)
    return data


@app.post("/uploadfile")
async def upload_file(file: UploadFile = File(...)):
    try:
        logger.info("File received: %s", file.filename)
        content = await file.read()
        logger.info("File content read successfully")
        content = content.decode("utf-8")

        data = extract_info(content)

        if data["nodes"] is not None:
            nodes_gauge.set(data["nodes"])
        if data["colors"] is not None:
            colors_gauge.set(data["colors"])
        if data["run_time"] is not None:
            runtime_gauge.set(data["run_time"])
        if data["solution_cost"] is not None:
            solution_cost_gauge.set(data["solution_cost"])
        if data["num_nodes_deployed"] is not None:
            num_nodes_deployed_gauge.set(data["num_nodes_deployed"])
        if data["average_path_weight"] is not None:
            average_path_weight_gauge.set(data["average_path_weight"])
        if data["percentage_covered"] is not None:
            percentage_covered_gauge.set(data["percentage_covered"])

        output_filename = "parsed_data.json"
        with open(output_filename, "w") as f:
            json.dump(data, f, indent=4)
        logger.info("Data saved to %s", output_filename)

        install_tunnel_rules()

        return {"message": "Controller executed successfully"}

    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Error processing file: {str(e)}")


@app.get("/metrics/")
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.on_event("startup")
async def startup_event():
    logger.info("Server starting...")
    global controller
    controller = P4Controller()  # Inizializza il controller senza argomenti
    logger.info("Controller initialized successfully.")
    logger.info("Starting the controller in a new thread.")

    asyncio.create_task(controller.run())
    logger.info("Controller started in the event loop.")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("rest_api:app", host="0.0.0.0", port=8000, reload=True)
