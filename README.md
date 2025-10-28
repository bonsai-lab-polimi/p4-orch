# Programmable Network Monitoring and Classification with P4


This project implements both the P4 data plane pipeline and a Python-based controller for a programmable network of switches and hosts.

The P4 program defines the complete packet-processing logic: parsing headers, handling IPv4 and ARP traffic, encapsulating and decapsulating packets for tunneling, flow classification and generating telemetry digests enriched with lightweight “weak learners” for traffic analysis.

The controller, developed with FastAPI, provides a REST API to install and update rules, manage Layer 2 communication, collect and process digests, and perform mitigation actions when a malicious flow is detected by the P4 switches. It also integrates with Prometheus and Grafana for real-time monitoring and visualization.
Together, the P4 pipeline and the controller form a hybrid architecture: simple, high-speed operations run directly in the switches, while the controller aggregates information and enforces higher-level policies.
---

## Features

- **LAYER 2**
    - **Dynamic Spanning Tree Construction:**  
      Upon startup of the FastAPI server, the controller constructs a **spanning tree** using `s1` as the root. This tree is used for flooding packets when necessary.
    
    - **ARP Request Handling:**  
      When a switch receives an ARP request, it forwards it to the controller. The controller, via the `ARPManager`, decides whether to:
      - Flood the ARP request along the spanning tree (if there is no MAC-to-port mapping).
      - Forward the ARP request to the correct port if the MAC-to-port mapping is already known, installing on switches the correct match-action table rule.
    
    This ensures the standard switch behavior of forwarding packets along the shortest path (i.e., the port from which the ARP request was received).

- **Dynamic Tunnel Rule Installation:**  
  Tunnel rules are installed or updated dynamically each time a routing rule file is uploaded to the `/uploadfile` endpoint.  
  The rules are installed on all switches to manage the specified paths.
  
  The `/uploadfile` endpoint allows uploading a file (even modified) multiple times. Each upload:
  - Causes the controller to analyze the new routing rules.
  - Dynamically modifies or updates the rules installed on the switches.
  - If specified, it also determines which switches should host the WeakLearners and which classification rules should be installed on them.
    
  The file can be re-uploaded multiple times (even modified), allowing for dynamic updates to the network state.
- **Network Monitoring Digest for Real-Time Network Analysis:**
  A key feature of this controller is the ability to collect network monitoring digests from each switch. These digests provide detailed, real-time information about the state of the network, enabling the controller to monitor various performance metrics, such as congestion, packet count, queue depth, and malicious flow detected by the Weak Learners.

  The monitoring digest helps analyze the health of the network and detect potential issues like congestion or packet drops. Each switch periodically sends a congestion digest to the controller.

- **Metrics Exposure with Prometheus and Grafana:**  
  The controller exposes all the metrics extracted from digest messages for monitoring the network configuration.




## Installation

Before installing this project, make sure that the P4 development environment is properly configured as described in the [P4 tutorials repository](https://github.com/p4lang/tutorials?tab=readme-ov-file#obtaining-required-software), section **Obtaining required software**.  
This step installs the necessary tools such as **BMv2**, **P4C**, and **Mininet**.

Once the environment is set up, follow these steps:

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd p4-orch/p4src


2. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure the network topology in the `topology.json` file.
   
---


## Starting the Network and Controller

1. **Compile and Start the Network**

    In your terminal run:
    ```bash
       make
    ```

   This command will perform the following operations:
    
    - Compile the `advanced_tunnel.p4` program.
    - Start an instance of Mininet with the topology specified in the `topology.json` file.
    - Assign IP addresses to the respective hosts.
    
    After starting Mininet, you should see a Mininet prompt. Now, run a ping between h1 and h2:
    
    ```bash
    mininet> h1 ping h2
    ```

    Since there are no rules on the switches yet, you should not receive responses to the ping.
    
     ### Additional Details
    
     - **P4 Program Compilation**: The P4 program, such as `advanced_tunnel.p4`, is compiled to run on an emulator like BMv2 (bare-metal v2).
     - **Mininet**: Mininet emulates a virtual network with switches and hosts.


2. **Start the FastAPI Server**  
   Run the server using `uvicorn`:
   ```bash
   cd p4-orch/src
   uvicorn rest_api:app --host 0.0.0.0 --port 8000
   ```
   - Upon startup:
     - The controller initializes and connects to all switches.
     - Installs the P4 program on each switch.
     - Builds a spanning tree using `s1` as the root.

   Example log during startup:
    ```
    INFO:     Waiting for application startup.
    2025-01-28 20:27:10,547 - INFO - Server starting...
    2025-01-28 20:27:10,547 - INFO - Initializing P4Controller
    2025-01-28 20:27:10,551 - INFO - Controller initialized successfully.
    2025-01-28 20:27:10,551 - INFO - Starting the controller in a new thread.
    2025-01-28 20:27:10,552 - INFO - Starting the P4Controller in a separate thread.
    INFO:     Application startup complete.
    2025-01-28 20:27:10,552 - INFO - Starting switch connections
    INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)

    ```
3. **The `pingall` Command in Mininet**

   The `pingall` command in Mininet is used to test connectivity between all hosts in the network. When you run `pingall`, all hosts send ARP (Address Resolution Protocol) packets to determine the MAC address corresponding to the IP addresses of their destination hosts.
    
   If the switches do not have information about the destinations (specifically the MAC addresses), these ARP packets are sent to the controller. The controller receives the ARP requests, processes the information, and installs the necessary rules on the switches. These rules include ARP rules to resolve MAC addresses and forwarding rules for packets between hosts.
    
   #### First `pingall`:

   When you run the first `pingall` command, the switches do not yet have forwarding rules for packets. Therefore, when the hosts send ARP packets, they are forwarded to the controller. Since the rules are not installed yet, the result of the `pingall` command will be the following:
   
   ```bash
   mininet> pingall
   *** Ping: testing ping reachability
   h1 -> X X X X
   h2 -> h1 X X X
   h3 -> h1 X X X
   h4 -> h1 X X X
   h5 -> h1 X X X
   *** Results: 80% dropped (4/20 received)
   ```
   
   In this case, the ARP packets are sent, and since the ARP and forwarding rules have not been installed yet, many packets are lost.
       
    #### Second `pingall`:
       
    Once the controller has processed the ARP requests and installed the necessary rules, the switches will know where to forward the packets. As a result, the second `pingall` command will show that all hosts can communicate correctly with each other, without any packet loss:

   ```bash
   mininet> pingall
   *** Ping: testing ping reachability
   h1 -> h2 h3 h4 h5
   h2 -> h1 h3 h4 h5
   h3 -> h1 h2 h4 h5
   h4 -> h1 h2 h3 h5
   h5 -> h1 h2 h3 h4
   *** Results: 0% dropped (20/20 received)
   ```
       
   In this case, the switches already have the rules installed and there is no packet loss, indicating that the network is functioning correctly.

4. **Install Tunnel Rules via `/uploadfile`**  
   Upload a file with routing rules to the `/uploadfile` endpoint. For example:
   ```bash
   curl -X POST "http://<server-ip>:8000/uploadfile" -F "file=@path/to/your/file.json"

   ```
    
   The controller will process the file, install the rules on the switches, and deploy any Weak Learners on the specified switches.


Logs generated by the switches are available in the `p4src/logs` directory, while packet captures of their interfaces can be found in `p4src/pcap`.

## Example topology and test scripts

The repository already includes a ready-made example topology, example `.json` files that can be uploaded via the REST API, and several Python scripts to help testing the pipeline and controller logic:

- `topology.json` — a sample network topology that can be used as a starting point for experiments.
- `examples/rules_example.json` — example routing/tunnel rule files ready to be uploaded to the controller.
- `server.py` — helper script to start a host in the emulated topology as a simple TCP server listening on a configurable port (useful to validate reachability and tunnel behaviour).
- `RST_Flood.py` and `SYN_Flood.py` — lightweight traffic generators that produce RST- and SYN-based flood traffic respectively, intended for controlled testing of detection and mitigation features.

## Monitoring with Prometheus and Grafana

The controller exposes Prometheus-compatible metrics on port **8000** at the `/metrics` endpoint. By configuring Prometheus to scrape this endpoint and importing the provided Grafana dashboard JSON from the repository, you can obtain a complete, real-time view of the system.

### Prometheus
Add a scrape job to your `prometheus.yml` with the controller address (replace `<controller-host>` with the actual hostname or IP):

```yaml
scrape_configs:
  - job_name: 'p4_controller'
    static_configs:
      - targets: ['<controller-host>:8000']
```
### Grafana
The repository includes a sample Grafana dashboard JSON (`examples/grafana_dashboard.json`). To use it:

1. Open Grafana and go to **Dashboards → Import**.
2. Upload the JSON file or paste its contents.
3. Select your Prometheus data source and confirm.

This will create a dashboard showing key metrics collected by the controller (rule installations, digests, classifications, etc.).

### Notes
- Make sure Prometheus can reach the controller on port **8000**.  
- The included dashboard is meant as a starting point — you can extend or modify it to track specific metrics of interest.  
