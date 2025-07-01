from scapy.all import *
import time
import math
import logging
import threading

# Configura il logging per scrivere su file
logging.basicConfig(filename="h1_log.txt", level=logging.DEBUG, format='%(asctime)s - %(message)s')


def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    print("❌ Nessuna interfaccia 'eth0' trovata!")
    exit(1)


def handle_pkt(pkt):
    """Gestisce i pacchetti sniffati."""
    print("Got a packet")
    pkt.show2()
    sys.stdout.flush()


def start_udp_server():
    """Avvia un server UDP su porta 4321 per evitare ICMP Destination Unreachable."""
    UDP_IP = "0.0.0.0"  # Ascolta su tutti gli IP dell'host
    UDP_PORT = 4321

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    print(f"✅ UDP server listening on port {UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(1024)  # Riceve fino a 1024 byte
        print(f"📩 Received packet from {addr}: {data.decode(errors='ignore')}")


def send_packets_to_host(srcMAC, srcIP, dstMAC, dstIP, payload_size, iface, name, min_throughput, max_throughput,
                         total_packets, cycle_time):
    payload = "X" * payload_size  # Dati del payload
    start_time = time.time()

    for i in range(1, total_packets + 1):
        try:
            elapsed_time = time.time() - start_time
            # Calcola il throughput a campana (sinusoidale) per ogni host
            time_in_cycle = elapsed_time % cycle_time  # Tempo all'interno di un ciclo
            if time_in_cycle < cycle_time / 2:
                throughput = min_throughput + (max_throughput - min_throughput) * (
                        1 - math.cos(math.pi * time_in_cycle / (cycle_time / 2))) / 2
            else:
                throughput = max_throughput - (max_throughput - min_throughput) * (
                        1 - math.cos(math.pi * (time_in_cycle - (cycle_time / 2)) / (cycle_time / 2))) / 2

            # Gestione throughput distinti per ciascun host
            if name == "h1":  # h1: Invio rapido (throughput elevato)
                throughput = max_throughput  # Utilizzo il throughput massimo per h2
            elif name == "h3":  # h3: Alternanza 30s basso / 30s alto
                if (time_in_cycle // 90) % 2 == 0:  # Se siamo in una fase pari (0-30s, 60-90s, ...)
                    throughput = min_throughput  # Lento
                else:  # Se siamo in una fase dispari (30-60s, 90-120s, ...)
                    throughput = max_throughput
            elif name == "h2":  # h2: Velocità fluttuante
                throughput = min_throughput + (max_throughput - min_throughput) * (
                        1 - math.cos(math.pi * (elapsed_time % cycle_time) / cycle_time)) / 2
            elif name == "h5":  # h5: Invio alternato (rapido e poi pausa lunga)
                throughput = min_throughput

                # Calcola il tempo tra i pacchetti in base al throughput calcolato
            time_between_packets = 1 / (throughput / (len(payload) * 8))  # Calcolo dei pacchetti per secondo

            # Crea e invia il pacchetto
            pkt = Ether(src=srcMAC, dst=dstMAC) / IP(src=srcIP, dst=dstIP, tos=1) / UDP(dport=4321,
                                                                                        sport=1234) / payload
            sendp(pkt, iface=iface, verbose=False)

            # Calcola il tempo totale trascorso e stampa i dettagli
            elapsed_time = time.time() - start_time
            log_message = f"📦 Packet {i}/{total_packets} to {name} - Size: {payload_size}B - Throughput: {throughput / 1e3:.2f} kbps - Elapsed: {elapsed_time:.2f}s "
            print(log_message)
            logging.info(log_message)  # Log su file

            # Aspetta il tempo calcolato tra pacchetti
            time.sleep(time_between_packets)

        except Exception as e:
            error_message = f"Error sending packet {i} to {name}: {str(e)}"
            print(error_message)
            logging.error(error_message)  # Log su file degli errori


def main():
    # Host 1 (sorgente)
    srcMAC = "08:00:00:00:01:11"  # MAC dell'host 1 (h1)
    srcIP = "10.0.1.1"  # IP dell'host 1 (h1)

    # Destinazioni (h2, h3, h4, h5) seguendo la logica dei MAC addresses
    destinations = [
        {"mac": "08:00:00:00:02:22", "ip": "10.0.1.2", "name": "h2"},  # Host 2 (h2)
        {"mac": "08:00:00:00:03:33", "ip": "10.0.1.3", "name": "h3"},  # Host 3 (h3)
        {"mac": "08:00:00:00:01:11", "ip": "10.0.1.1", "name": "h1"},  # Host 1 (h1)
        {"mac": "08:00:00:00:05:55", "ip": "10.0.1.5", "name": "h5"},  # Host 5 (h5)
    ]

    iface = get_if()  # Ottieni l'interfaccia di rete
    payload_size = 1024  # Dimensione del payload in byte

    total_packets = 500000  # Numero totale di pacchetti da inviare
    min_throughput = 5_000  # 5 kbps
    max_throughput = 50_000  # 70 kbps
    duration_increase = 200  # Tempo per raggiungere throughput massimo
    duration_decrease = 200  # Tempo per tornare a throughput minimo
    cycle_time = duration_increase + duration_decrease  # Durata totale del ciclo

    threads = []
    for destination in destinations:
        dstMAC = destination["mac"]
        dstIP = destination["ip"]
        name = destination["name"]

        # Creazione e avvio di un thread per ogni destinazione con throughput specifico
        thread = threading.Thread(target=send_packets_to_host, args=(
            srcMAC, srcIP, dstMAC, dstIP, payload_size, iface, name, min_throughput, max_throughput, total_packets,
            cycle_time))
        threads.append(thread)
        thread.start()
    udp_thread = threading.Thread(target=start_udp_server, daemon=True)
    udp_thread.start()
    print(f"📡 Sniffing on {iface}")
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface=iface, prn=lambda x: handle_pkt(x))
    # Attendere che tutti i thread finiscano
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
