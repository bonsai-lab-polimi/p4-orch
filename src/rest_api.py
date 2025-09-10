#!/usr/bin/env python3
import os
import sys
import json
import logging
import re
from fastapi import FastAPI, File, UploadFile
from fastapi import HTTPException
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from prometheus_client import Gauge
from fastapi.responses import Response
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi import Depends, HTTPException, status, Request
from fastapi.security.api_key import APIKeyHeader

# Import P4Runtime lib from parent utils dir
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../utils/'))
import generate_config
import asyncio
import time

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

def export_with_timeout(path, switches, timeout=10, fmt=None):

    def _worker():
        return controller.table_manager.export_tables(list(switches.values()), path, fmt=fmt)

    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_worker)
        try:
            return fut.result(timeout=timeout)
        except TimeoutError:
            fut.cancel()
            raise RuntimeError("Export timeout")
def install_tunnel_rules():
    logger.info("ENTER install_tunnel_rules")
    success = True

    try:
        try:
            with open('parsed_data.json', 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error("Error reading JSON file: %s", e)
            return

        # normalizzazione come prima
        routes = {tuple(map(int, key.split(','))): value for key, value in data.get("routes", {}).items()}
        logger.info("Routes parsed: %s", routes)

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
            logger.error("Error while building tunnels: %s", e)
            success = False  # non return; vogliamo arrivare al finally
        logger.info("Built %d tunnels", len(tunnels))

        tunnel_ids = []
        try:
            for tunnel in tunnels:
                (src_host, dst_host), path, src_eth_addr, src_ip_addr, dst_eth_addr, dst_ip_addr = tunnel
                tunnel_id = ''.join(str(s) for s in path)
                tunnel_ids.append(tunnel_id)
                switches_id = path
                intermediate_switches_id = path[:-1]

                logger.info("Processing tunnel %s -> path %s", (src_host, dst_host), path)

                try:
                    ingress_sw = switches[src_host]
                    egress_sw = switches[dst_host]
                except KeyError as e:
                    logger.error("Switch mapping missing for host: %s", e)
                    success = False
                    continue  # passa al tunnel successivo

                # costruisci lista oggetti switch intermedi
                intermediate_switches = []
                try:
                    for sw_id in intermediate_switches_id:
                        intermediate_switches.append(switches[sw_id])
                except KeyError as e:
                    logger.error("Switch id mancante nella path: %s", e)
                    success = False
                    continue

                # scrive regole tunnel (mantieni la tua implementazione)
                try:
                    controller.tunnel_manager.write_tunnel_rules(
                        ingress_sw, intermediate_switches, egress_sw, tunnel_id, dst_eth_addr, dst_ip_addr
                    )
                except Exception as e:
                    logger.error("Error while writing tunnel rules for tunnel %s: %s", tunnel_id, e)
                    success = False
                    continue

                # stampa e calcoli delle porte (solo logging, non return)
                try:
                    logger.info("source:%s, destination:%s", src_eth_addr, dst_eth_addr)
                    path_len = len(switches_id)
                    for i, sw_id in enumerate(switches_id):
                        sw = switches[sw_id]
                        logger.debug("switch %d in path: %s", i + 1, sw.name)

                        if i == 0:
                            in_port = HOST_TO_PORT[sw.name]
                            next_sw = switches[switches_id[i + 1]]
                            port = SWITCH_PORTS[sw.name][next_sw.name]
                        elif i == path_len - 1:
                            prev_sw = switches[switches_id[i - 1]]
                            in_port = SWITCH_PORTS[sw.name][prev_sw.name]
                            port = HOST_TO_PORT[sw.name]
                        else:
                            prev_sw = switches[switches_id[i - 1]]
                            next_sw = switches[switches_id[i + 1]]
                            in_port = SWITCH_PORTS[sw.name][prev_sw.name]
                            port = SWITCH_PORTS[sw.name][next_sw.name]

                        # se vuoi installare ARPReply puoi farlo qui (era commentato)
                        controller.arp_manager.writeARPReply(sw, in_port, dst_eth_addr, src_eth_addr, port)
                except Exception as e:
                    logger.error("Error while calculating ports for tunnel %s: %s", tunnel_id, e)
                    success = False
                    continue

        except Exception as e:
            logger.error("Error processing tunnels top-level: %s", e)
            success = False

        # Alla fine (sia che success sia True o False) leggiamo le tabelle per debug
        try:
            for switch in switches.values():
                logger.info("About to read table rules from %s", switch.name)
                controller.table_manager.read_table_rules(switch)
            # --- Export tables su file (absolute path per sicurezza) ---
            try:
                out = "/tmp/p4_tables.xlsx"  # usa .json per evitare dipendenze, cambia estensione se preferisci .xlsx
                # Se vuoi .xlsx e hai pandas/openpyxl: out = "/tmp/p4_tables.xlsx" e rimuovi fmt arg
                file_written = export_with_timeout(out, switches, timeout=15, fmt="xlsx")
                logger.info("Table export saved to: %s", file_written)
            except Exception as e:
                logger.exception("Errore esportando le tabelle: %s", e)

        except Exception as e:
            logger.error("Error reading table rules for switches: %s", e)


    except Exception as e:
        logger.error("Unexpected error in install_tunnel_rules: %s", e)

    finally:
        logger.info("EXIT install_tunnel_rules (success=%s)", success)



ACTION_PARAMS_MAP = {
    "MyIngress.CheckFeature": ["node_id", "f_inout", "threshold"],
    "MyIngress.SetClass": ["node_id", "class"],
    "NoAction": [],
}


def get_match_fields_for(table_name):
    if table_name.startswith("MyIngress.level"):
        return ["meta.node_id", "meta.prevFeature", "meta.isTrue"]
    raise ValueError(f"Match fields non definiti per {table_name}")


def install_table_entries_on_wls(info, p4info_helper):
    for wl_node in info["wl_nodes"]:
        sw = switches[wl_node]
        entries = info["table_entries"].get(wl_node, [])

        for entry in entries:
            match_values = entry["match_fields"]
            action_values = entry["action_params"]
            table_name = entry["table"]
            action_name = entry["action"]

            # Prendo i nomi reali dei match fields
            match_field_names = get_match_fields_for(table_name)
            if len(match_field_names) != len(match_values):
                raise ValueError(f"Numero di match fields non corrisponde per {table_name}")

            # Creo il dizionario match_fields {nome: valore}
            match_fields = {name: value for name, value in zip(match_field_names, match_values)}

            # Prendo i nomi reali dei parametri action
            action_param_names = ACTION_PARAMS_MAP.get(action_name, [])
            if len(action_param_names) != len(action_values):
                raise ValueError(f"Numero di action params non corrisponde per {action_name}")

            action_params = {name: value for name, value in zip(action_param_names, action_values)}

            # Costruisco la regola
            table_entry = p4info_helper.buildTableEntry(
                table_name=table_name,
                match_fields=match_fields,
                action_name=action_name,
                action_params=action_params
            )

            p4info_helper.upsertRuleMultipleMatch(
                sw,
                table_name,
                match_fields,
                table_entry
            )

            print(f"✅ Regola installata su WL {wl_node}: {table_name} → {action_name}")


def start_monitoring_threads(switches, controller, arp_manager, digest_manager):
    loop = asyncio.get_running_loop()
    loop.create_task(controller.message_manager.start(switches, arp_manager, digest_manager))


def extract_info(file_content: str) -> dict:
    """
    Parse input JSON (string) produced a monte and normalize into the old 'data' dict shape.
    Expects JSON like the example you provided (keys: instance_info, deployment,
    shortest_paths_constrained, wl_nodes, table_entries, metrics, shortest_paths_classic).
    """
    try:
        logger.debug("Primi 200 caratteri del file_content: %r", file_content[:200])
        parsed = json.loads(file_content)
    except Exception as e:
        # Fallisce se non è JSON: solleva errore chiaro (upload_file dovrebbe catturare e ritornare 400)
        raise ValueError(f"Input non è JSON valido: {e}")

    data = {}

    # instance_info scalari (backwards compat: anche supportare root-level keys)
    inst = parsed.get("instance_info", {})
    data["nodes"] = inst.get("nodes", parsed.get("nodes"))
    data["colors"] = inst.get("colors", parsed.get("colors"))
    data["run_time"] = inst.get("run_time", parsed.get("run_time"))
    data["solution_cost"] = inst.get("solution_cost", parsed.get("solution_cost"))

    # deployment (manteniamo la stessa struttura dict[int->int])
    deployment = parsed.get("deployment", parsed.get("deployment", {}))
    # se i key sono stringhe numeriche, convertile ad int
    try:
        data["deployment"] = {int(k): int(v) for k, v in deployment.items()}
    except Exception:
        # se non possibile convertire, mantieni il dict originale (ma logga)
        logger.warning("Deployment non interamente numerico, mantenuto come fornito.")
        data["deployment"] = deployment


    routes = parsed.get("routes", parsed.get("shortest_paths_constrained", {}))

    normalized_routes = {}
    for k, v in routes.items():

        if isinstance(v, list):
            try:
                normalized_routes[str(k)] = [int(x) for x in v]
            except Exception:
                logger.warning("Una route ha elementi non interi, li lascio invariati per debug: %s", k)
                normalized_routes[str(k)] = v
        else:
            logger.warning("Route '%s' non è lista, ignorata.", k)
    data["routes"] = normalized_routes

    # metrics / summary
    metrics = parsed.get("metrics", {})
    data["num_nodes_deployed"] = metrics.get("num_nodes_deployed", parsed.get("num_nodes_deployed"))
    data["average_path_weight"] = metrics.get("average_path_weight", parsed.get("average_path_weight"))
    data["percentage_covered"] = metrics.get("percentage_covered", parsed.get("percentage_covered"))

    # WL nodes (assicurati siano int)
    wl_nodes_raw = parsed.get("wl_nodes", parsed.get("WL", []))
    wl_nodes = []
    for x in wl_nodes_raw:
        try:
            wl_nodes.append(int(x))
        except Exception:
            logger.warning("WL node non numerico ignorato: %s", x)
    data["wl_nodes"] = wl_nodes

    # table_entries: converti chiavi numeriche-stringa a int e assicurati tipi interni
    table_entries_raw = parsed.get("table_entries", {})
    table_entries = {}
    for k, entries in table_entries_raw.items():
        # wl key può essere "6" oppure 6
        try:
            key = int(k)
        except Exception:
            key = k
        parsed_list = []
        if isinstance(entries, list):
            for e in entries:
                table_name = e.get("table")
                action_name = e.get("action")
                # garantisci che match_fields/action_params siano liste di int
                match_fields = e.get("match_fields", [])
                action_params = e.get("action_params", [])
                try:
                    match_fields = [int(x) for x in match_fields]
                except Exception:
                    logger.warning("match_fields non numerici in WL %s, lasciati così.", k)
                try:
                    action_params = [int(x) for x in action_params]
                except Exception:
                    logger.warning("action_params non numerici in WL %s, lasciati così.", k)
                parsed_list.append({
                    "table": table_name,
                    "action": action_name,
                    "match_fields": match_fields,
                    "action_params": action_params
                })
        else:
            logger.warning("table_entries per WL %s non è una lista, ignorata.", k)
        table_entries[key] = parsed_list
    data["table_entries"] = table_entries

    # classic shortest paths (optional)
    data["shortest_paths_classic"] = parsed.get("shortest_paths_classic", {})

    # Mantieni comportamento originale: installa le WL rules subito se controller e switches esistono
    try:
        # 'controller' e 'switches' sono variabili globali nel tuo modulo (come nel tuo esempio)
        controller.WL_manager.install_wl_rules(data["wl_nodes"], switches)
    except NameError:
        # se non definite, non interrompere il parsing — caller deciderà cosa fare
        logger.debug("controller o switches non definiti in questo scope; skip WL install.")
    except Exception:
        logger.exception("Errore installando WL rules; proseguo comunque.")

    return data


# Upload endpoint: use the normalized parser and be defensive with side-effects


@app.post("/uploadfile")
async def upload_file(file: UploadFile = File(...)):
    try:
        received_file_time = time.time()
        logger.info("File received: %s", file.filename)
        raw = await file.read()
        try:
            content = raw.decode("utf-8")
        except Exception as e:
            logger.error("Errore decodifica file: %s", e)
            raise HTTPException(status_code=400, detail="File non decodificabile come UTF-8")

        # Parse + normalize using your JSON-only parser
        try:
            data = extract_info(content)  # questa è la funzione JSON-only che hai inserito
        except ValueError as e:
            logger.error("Errore parsing JSON: %s", e)
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.exception("Errore imprevisto in extract_info")
            raise HTTPException(status_code=400, detail="Errore parsing input")

        # aggiorna gauges (defensivamente)
        try:
            if data.get("nodes") is not None:
                nodes_gauge.set(data["nodes"])
            if data.get("colors") is not None:
                colors_gauge.set(data["colors"])
            if data.get("run_time") is not None:
                runtime_gauge.set(data["run_time"])
            if data.get("solution_cost") is not None:
                solution_cost_gauge.set(data["solution_cost"])
            if data.get("num_nodes_deployed") is not None:
                num_nodes_deployed_gauge.set(data["num_nodes_deployed"])
            if data.get("average_path_weight") is not None:
                average_path_weight_gauge.set(data["average_path_weight"])
            if data.get("percentage_covered") is not None:
                percentage_covered_gauge.set(data["percentage_covered"])
        except Exception:
            logger.exception("Errore aggiornando gauges; proseguo comunque.")

        # --- persist normalized JSON to disk (legacy reads parsed_data.json) ---
        output_filename = "parsed_data.json"
        # assicurati che esista la chiave 'routes' (anche vuota) e che sia serializzabile
        if "routes" not in data:
            data["routes"] = {}

        try:
            # scrittura atomica minima: scrivi su file temporaneo e rinomina
            tmp_name = output_filename + ".tmp"
            with open(tmp_name, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, output_filename)  # atomicamente sostituisce
            logger.info("Data saved to %s", output_filename)
        except Exception:
            logger.exception("Errore scrittura parsed_data.json")
            raise HTTPException(status_code=500, detail="Errore salvando parsed_data.json")

        # --- chiamate legacy (che leggono parsed_data.json internamente) ---


        # stampa e log delle WL e delle table_entries per debug
        try:
            logger.info("=== WL NODES === %s", data.get("wl_nodes", []))
            logger.info("=== TABLE ENTRIES PER WL ===")
            for wl_node, entries in data.get("table_entries", {}).items():
                logger.info("▶ WL Node %s:", wl_node)
                for entry in entries:
                    logger.info("  table_add %s %s %s => %s",
                                entry["table"],
                                entry["action"],
                                " ".join(map(str, entry["match_fields"])),
                                " ".join(map(str, entry["action_params"])))
        except Exception:
            logger.exception("Errore logging table_entries")

        # install table entries (questa funzione accetta 'data' e controller.p4info_helper)
        try:
            install_table_entries_on_wls(data, controller.p4info_helper)
        except Exception:
            logger.exception("Error installing table entries")
        try:
            install_tunnel_rules()  # funzione legacy che legge parsed_data.json
        except Exception:
            logger.exception("Error in install_tunnel_rules (legacy)")

        return {
            "message": "Controller executed successfully",
            "execution_time": time.time() - received_file_time
        }
    except HTTPException:
        # rilancia HTTPException intatto
        raise
    except Exception as e:
        logger.exception("Error processing file: %s", e)
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
