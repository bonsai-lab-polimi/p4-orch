import socket
import time
import random
import pandas as pd
from datetime import datetime
import os

SERVER_IP = '10.0.1.2'
SERVER_PORT = 12345
MESSAGGI = [b'Ciao, ', b'come ', b'stai?']
NUM_CICLI = 1
EXCEL_FILE = "packet_stats.xlsx"
SHEET_NAME = "Client"  # 🔹 Foglio condiviso
log = []

def salva_client_data():
    global log
    new_df = pd.DataFrame(log, columns=["Timestamp", "IP", "Porta", "Messaggio", "Totale_Pacchetti_Inviati"])

    # 📥 Legge l'intero file se esiste
    if os.path.exists(EXCEL_FILE):
        try:
            all_sheets = pd.read_excel(EXCEL_FILE, sheet_name=None, engine="openpyxl")
        except Exception:
            all_sheets = {}
    else:
        all_sheets = {}

    # 🔄 Recupera dati già presenti nel foglio "Client"
    existing_df = all_sheets.get(SHEET_NAME, pd.DataFrame(columns=new_df.columns))
    combined_df = pd.concat([existing_df, new_df], ignore_index=True)
    all_sheets[SHEET_NAME] = combined_df

    # 📄 Scrittura sicura mantenendo tutti gli altri fogli
    with pd.ExcelWriter(EXCEL_FILE, engine="openpyxl") as writer:
        for sheet_name, df in all_sheets.items():
            df.to_excel(writer, sheet_name=sheet_name, index=False)

    print(f"📁 Client TCP: dati salvati in '{EXCEL_FILE}'")
    log.clear()

def run_client():
    global log
    for ciclo in range(NUM_CICLI):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        packet_count = 0  # 🔁 Riparte da 0 per ogni connessione

        try:
            client.connect((SERVER_IP, SERVER_PORT))
            client_ip, client_port = client.getsockname()
            print(f"🚀 Connessione {ciclo + 1}/{NUM_CICLI} da {client_ip}:{client_port}")

            for msg in MESSAGGI:
                client.send(msg)
                packet_count += 1
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                log.append([timestamp, client_ip, client_port, msg.decode(errors='ignore'), packet_count])
                print(f"✉️ Inviato: {msg.decode(errors='ignore')}")
                time.sleep(random.uniform(0.3, 0.7))

            # 📨 Attesa risposta dal server
            risposta = b""
            client.settimeout(25)
            try:
                while True:
                    data = client.recv(1024)
                    if not data:
                        break
                    risposta += data
            except socket.timeout:
                pass

            if risposta:
                print(f"✅ Risposta ricevuta: {risposta.decode(errors='ignore')}")

        except Exception as e:
            print(f"❌ Errore TCP: {e}")
        finally:
            client.close()
            print("🔚 Connessione chiusa\n")
            salva_client_data()
            time.sleep(2)

if __name__ == "__main__":
    run_client()
