import socket
import threading
import logging
import pandas as pd
import time
import os

HOST = '0.0.0.0'
TCP_PORT = 12345
UDP_PORT = 54321
FRASI_ACCETTATE = [b'Ciao, come stai?']
TIMEOUT = 10
EXPORT_INTERVAL = 30  # secondi

EXCEL_FILE = "packet_stats.xlsx"
CLIENT_SHEET = "Client"  # Qui scrivono i client
SERVER_SHEET = "Server"
SUMMARY_SHEET = "Summary"

# Conteggi separati per TCP e UDP
tcp_packet_counts = {}
udp_packet_counts = {}

packet_lock = threading.Lock()

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] [%(levelname)s] %(message)s')

def generate_summary():
    try:
        all_sheets = pd.read_excel(EXCEL_FILE, sheet_name=None, engine="openpyxl")
        client_df = all_sheets.get(CLIENT_SHEET, pd.DataFrame())
        server_df = all_sheets.get(SERVER_SHEET, pd.DataFrame())

        if client_df.empty or server_df.empty:
            logging.warning("⚠️ Dati insufficienti per generare il Summary")
            return

        client_sent = client_df.groupby(["IP", "Porta"]).size().reset_index(name="Sent")
        server_received = server_df.groupby(["IP", "Porta", "Protocollo"])["Packet_Count"].sum().reset_index(name="Received")

        # Uniamo per IP, Porta e Protocollo
        summary_df = pd.merge(client_sent, server_received, on=["IP", "Porta"], how="outer").fillna(0)
        summary_df["Sent"] = summary_df["Sent"].astype(int)
        summary_df["Received"] = summary_df["Received"].astype(int)
        summary_df["Packet_Loss"] = (summary_df["Sent"] - summary_df["Received"]).clip(lower=0)
        summary_df["Loss_%"] = summary_df.apply(
            lambda row: round((row["Packet_Loss"] / row["Sent"]) * 100, 2) if row["Sent"] > 0 else 0,
            axis=1
        )

        with pd.ExcelWriter(EXCEL_FILE, engine="openpyxl", mode="a", if_sheet_exists="replace") as writer:
            summary_df.to_excel(writer, sheet_name=SUMMARY_SHEET, index=False)

        logging.info("📊 Foglio 'Summary' aggiornato correttamente")

    except Exception as e:
        logging.error(f"❌ Errore durante la generazione del Summary: {e}")

def export_to_excel():
    with packet_lock:
        if not tcp_packet_counts and not udp_packet_counts:
            return

        # Prepara lista dati per TCP
        tcp_data = [{"IP": ip, "Porta": port, "Packet_Count": count, "Protocollo": "TCP"}
                    for (ip, port), count in tcp_packet_counts.items()]
        # Prepara lista dati per UDP
        udp_data = [{"IP": ip, "Porta": port, "Packet_Count": count, "Protocollo": "UDP"}
                    for (ip, port), count in udp_packet_counts.items()]

        all_data = tcp_data + udp_data
        df_new = pd.DataFrame(all_data)

        if df_new.empty:
            return

        if os.path.exists(EXCEL_FILE):
            try:
                all_sheets = pd.read_excel(EXCEL_FILE, sheet_name=None, engine="openpyxl")
            except Exception:
                all_sheets = {}
        else:
            all_sheets = {}

        df_existing = all_sheets.get(SERVER_SHEET, pd.DataFrame(columns=["IP", "Porta", "Packet_Count", "Protocollo"]))
        df_combined = pd.concat([df_existing, df_new], ignore_index=True)
        df_grouped = df_combined.groupby(["IP", "Porta", "Protocollo"], as_index=False)["Packet_Count"].sum()

        all_sheets[SERVER_SHEET] = df_grouped

        with pd.ExcelWriter(EXCEL_FILE, engine="openpyxl") as writer:
            for name, sheet in all_sheets.items():
                sheet.to_excel(writer, sheet_name=name, index=False)

        logging.info("📁 Server: dati aggiornati in 'packet_stats.xlsx'")

        tcp_packet_counts.clear()
        udp_packet_counts.clear()

def export_loop():
    while True:
        time.sleep(EXPORT_INTERVAL)
        export_to_excel()
        generate_summary()

def udp_listener():
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind((HOST, UDP_PORT))
    logging.info(f"🚀 Server UDP in ascolto su {HOST}:{UDP_PORT}")

    while True:
        try:
            data, addr = udp_server.recvfrom(4096)
            ip, port = addr
            with packet_lock:
                key = (ip, port)
                udp_packet_counts[key] = udp_packet_counts.get(key, 0) + 1

            # Se vuoi rispondere (opzionale)
            # if data in FRASI_ACCETTATE:
            #     udp_server.sendto(b"bene", addr)

        except Exception as e:
            logging.error(f"💥 Errore UDP: {e}")

def client_handler(conn, addr):
    ip = addr[0]
    client_port = addr[1]
    conn.settimeout(TIMEOUT)
    buffer = b""
    risposta_inviata = False

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            with packet_lock:
                key = (ip, client_port)
                tcp_packet_counts[key] = tcp_packet_counts.get(key, 0) + 1

            buffer += data
            for frase in FRASI_ACCETTATE:
                if frase in buffer and not risposta_inviata:
                    conn.sendall(b"bene")
                    risposta_inviata = True
                    break

    except Exception as e:
        logging.error(f"💥 Errore TCP: {e}")
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except:
            pass
        conn.close()

def main():
    threading.Thread(target=export_loop, daemon=True).start()
    threading.Thread(target=udp_listener, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, TCP_PORT))
    server.listen()

    logging.info(f"🚀 Server TCP in ascolto su {HOST}:{TCP_PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=client_handler, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
