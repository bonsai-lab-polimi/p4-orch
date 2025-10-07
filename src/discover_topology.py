import struct
import argparse
import os
import sys
import time
import grpc

sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
from p4runtime_lib.helper import P4InfoHelper


# Carica le informazioni dal file p4info
#p4info_helper = P4InfoHelper('<path/to/p4info/file>')

# Configura i dettagli degli switch e la connessione al controller
# Supponiamo di avere 3 switch. Aggiungili qui in base alla tua rete.
NUMBER_OF_SWITCHES = 5
NUMBER_OF_PORTS = 20  # Numero di porte per ciascuno switch

switches = [
    p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name=f'switch_{i}', address=f'localhost:{50051 + i}', device_id=i
    ) for i in range(NUMBER_OF_SWITCHES)
]

def build_lldp_packet(chassis_id, port_id, ttl=120):
    """
    Costruisce un pacchetto LLDP con chassis_id e port_id per l'annuncio tra switch.
    """
    eth_dst = b'\x01\x80\xc2\x00\x00\x0e'  # Multicast LLDP
    eth_src = b'\x00\x00\x00\x00\x00\x01'  # Placeholder per l'indirizzo sorgente
    ether_type = b'\x88\xCC'               # EtherType per LLDP

    # TLV per chassis_id e port_id, oltre al TTL e fine TLV
    chassis_id_tlv = struct.pack('!BB', 1, chassis_id)
    port_id_tlv = struct.pack('!BB', 2, port_id)
    ttl_tlv = struct.pack('!BH', 3, ttl)
    end_tlv = b'\x00\x00'  # Fine dei campi TLV

    # Costruzione completa del pacchetto LLDP
    lldp_packet = eth_dst + eth_src + ether_type + chassis_id_tlv + port_id_tlv + ttl_tlv + end_tlv
    return lldp_packet

def send_lldp(switch, port):
    """
    Invia un pacchetto LLDP su una porta specifica dello switch.
    """
    # Crea il pacchetto LLDP per l'ID dello switch e la porta specifica
    lldp_packet = build_lldp_packet(chassis_id=switch.device_id, port_id=port)

    # Verifica se il metodo packet_out esiste per la connessione
    try:
        # Invia il pacchetto LLDP sulla porta specificata
        switch.write_packet_out(payload=lldp_packet, port=port)
        print(f"Inviato LLDP da switch {switch.device_id} sulla porta {port}")
    except AttributeError as e:
        print(f"Errore nell'invio del pacchetto LLDP: {e}")
        print("Verifica che il metodo packet_out sia supportato dalla connessione dello switch.")

def receive_lldp_packet(switch):
    """
    Riceve pacchetti LLDP e identifica il collegamento.
    """
    while True:
        packet = switch.packet_in()  # Riceve un pacchetto in arrivo
        # Controlla se il pacchetto è LLDP
        if packet and packet.payload.startswith(b'\x01\x80\xc2\x00\x00\x0e'):
            # Estrae chassis_id e port_id dal pacchetto LLDP
            src_device_id = struct.unpack('!B', packet.payload[14:15])[0]
            src_port_id = struct.unpack('!B', packet.payload[15:16])[0]
            print(f"Link discovered: {src_device_id} --{src_port_id}--> {switch.device_id}")

def main():
    try:
        # Avvia la connessione a ciascuno switch
        for switch in switches:
            switch.MasterArbitrationUpdate()
            print(f"Connesso a {switch.name} con ID {switch.device_id}")
        print(f"Connesso a tutti gli switch")
        # Ciclo per inviare periodicamente i pacchetti LLDP su tutte le porte
        while True:
            # Ascolta i pacchetti LLDP ricevuti da ogni switch
            for sw in switches:
                receive_lldp_packet(sw)

    except KeyboardInterrupt:
        print("Terminazione controller...")
    finally:
        # Chiudi le connessioni con gli switch alla chiusura del programma
        ShutdownAllSwitchConnections()

if __name__ == '__main__':
    main()
