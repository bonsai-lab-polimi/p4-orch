from scapy.all import *
import random

# Parametri di rete
new_dst_ip = "10.0.1.2"  # Nuovo IP di destinazione
new_src_ip = "10.0.1.1"  # Nuovo IP sorgente

new_dst_mac = "08:00:00:00:02:22"  # Nuovo MAC di destinazione
new_src_mac = "08:00:00:00:01:11"  # Nuovo MAC sorgente

iface = "eth0"

# Leggi i pacchetti dal file pcap
pcap_file = "malicious_flow.pcap"
packets = rdpcap(pcap_file)
modified_packets = []

for pkt in packets:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        # Modifica l'IP sorgente e di destinazione
        pkt[IP].src = new_src_ip
        pkt[IP].dst = new_dst_ip

        # Modifica i MAC address di sorgente e destinazione
        pkt[Ether].src = new_src_mac
        pkt[Ether].dst = new_dst_mac

        # Rimuovi i checksum, poiché devono essere ricalcolati dopo la modifica
        del pkt[IP].chksum
        del pkt[TCP].chksum

        modified_packets.append(pkt)

# Invia i pacchetti modificati
sendp(modified_packets, iface=iface, verbose=True)
sendp(modified_packets, iface=iface, verbose=True)
sendp(modified_packets, iface=iface, verbose=True)
sendp(modified_packets, iface=iface, verbose=True)
sendp(modified_packets, iface=iface, verbose=True)
sendp(modified_packets, iface=iface, verbose=True)
sendp(modified_packets, iface=iface, verbose=True)
sendp(modified_packets, iface=iface, verbose=True)
sendp(modified_packets, iface=iface, verbose=True)

