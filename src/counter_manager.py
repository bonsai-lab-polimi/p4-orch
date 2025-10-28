from prometheus_client import Counter, Gauge
import time


class CounterManager:
    def __init__(self, p4info_helper):
        self.p4info_helper = p4info_helper

        # Definition of Prometheus counters
        # Number of packets
        self.ingress_tunnel_packet_count = Gauge(
            'ingress_tunnel_packet_count',
            'Ingress Tunnel Packet Count',
            ['switch', 'tunnel_id']
        )
        self.egress_tunnel_packet_count = Gauge(
            'egress_tunnel_packet_count',
            'Egress Tunnel Packet Count',
            ['switch', 'tunnel_id']
        )
        # Bytes
        self.ingress_tunnel_byte_count = Gauge('ingress_tunnel_byte_count', 'Numero di byte ingressi per tunnel',
                                               ['switch', 'tunnel_id'])
        self.egress_tunnel_byte_count = Gauge('egress_tunnel_byte_count', 'Numero di byte egressi per tunnel',
                                              ['switch', 'tunnel_id'])
        # Definition of Prometheus counters

    def update_prometheus_counters(self, sw, counter_name, tunnel_id, packet_count, byte_count):
        """
        Aggiorna i contatori Prometheus
        """
        if counter_name == "MyIngress.ingressTunnelCounter":
            self.ingress_tunnel_packet_count.labels(sw.name, tunnel_id).set(packet_count)
            self.ingress_tunnel_byte_count.labels(sw.name, tunnel_id).set(byte_count)
        elif counter_name == "MyIngress.egressTunnelCounter":
            self.egress_tunnel_packet_count.labels(sw.name, tunnel_id).set(packet_count)
            self.egress_tunnel_byte_count.labels(sw.name, tunnel_id).set(byte_count)

    def update_counter(self, sw, counter_name, index):
        """
        Legge e aggiorna Prometheus con i conteggi dei pacchetti dagli switch.
        """
        tunnel_id_int = int(index)
        for response in sw.ReadCounters(self.p4info_helper.get_counters_id(counter_name), tunnel_id_int):
            print(f"Reading counter {counter_name} for tunnel_id {tunnel_id_int} on switch {sw.name}")
            print(f"Response: {response}")
            for entity in response.entities:
                counter = entity.counter_entry
                egress_port = counter.index
                packet_count = counter.data.packet_count
                byte_count = counter.data.byte_count
                print(f"Packet count: {packet_count}")

                # Update Prometheus counters
                self.update_prometheus_counters(sw, counter_name, tunnel_id_int, packet_count, byte_count)

    def monitor_tunnel_counters(self, switches, tunnel_ids):
        """
        Esegue il monitoraggio continuo dei contatori di pacchetti dagli switch.
        """
        while True:
            # print('\n----- Monitoring Tunnel Counters -----')
            for tunnel_id in tunnel_ids:
                # print(f'Tunnel ID: {tunnel_id}')
                for switch in switches.values():
                    print(f'Switch: {switch}')
                    self.update_counter(switch, "MyIngress.ingressTunnelCounter", tunnel_id)
                    self.update_counter(switch, "MyIngress.egressTunnelCounter", tunnel_id)
            time.sleep(5)
