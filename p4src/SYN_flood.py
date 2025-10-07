#!/usr/bin/env python3
"""
SYN Flood Test Script per Mininet
Invia 100 pacchetti SYN da IP e porta sorgente fissi
"""

from scapy.all import IP, TCP, send
import time

# Parametri
SRC_IP = "10.0.1.1"
DST_IP = "10.0.1.2"
SRC_PORT = 54321
DST_PORT = 12345
COUNT = 70
IAT = 0.05  # inter-arrival time tra pacchetti in secondi

def send_syn_flood(src_ip, dst_ip, src_port, dst_port, count, iat):
    print(f"[+] Inizio SYN flood: {count} pacchetti da {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    for i in range(1, count + 1):
        ip = IP(src=src_ip, dst=dst_ip)
        tcp = TCP(sport=src_port, dport=dst_port, flags='S', seq=i)
        pkt = ip / tcp
        send(pkt, verbose=False)
        if i % 10 == 0:
            print(f"[+] Inviati {i} pacchetti")
        time.sleep(iat)
    print("[+] SYN flood completato!")

if __name__ == "__main__":
    send_syn_flood(SRC_IP, DST_IP, SRC_PORT, DST_PORT, COUNT, IAT)
