#!/usr/bin/env python3
from scapy.all import IP, TCP, send

# Configurazione destinazione
SERVER_IP   = "10.0.1.2"
SERVER_PORT = 12345

def send_fin_only(dst_ip, dst_port):
    """
    Invia un singolo pacchetto TCP con solo il flag FIN al server
    """
    # Costruzione del pacchetto IP/TCP con solo FIN
    pkt = IP(dst=dst_ip) / TCP(dport=dst_port, sport=12345, flags="F")
    # Invio del pacchetto
    send(pkt, verbose=False)
    print(f"[+] Pacchetto FIN inviato a {dst_ip}:{dst_port}")

if __name__ == "__main__":
    send_fin_only(SERVER_IP, SERVER_PORT)
