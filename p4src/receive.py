#!/usr/bin/env python3
import sys
import socket
import threading
from scapy.all import get_if_list, sniff


def get_if():
    """Trova l'interfaccia eth0."""
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


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


def main():
    iface = get_if()

    # Avvia il server UDP in un thread separato
    udp_thread = threading.Thread(target=start_udp_server, daemon=True)
    udp_thread.start()

    print(f"📡 Sniffing on {iface}")
    sys.stdout.flush()
    sniff(filter="udp and port 4321", iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
