import socket
import time
import random
import pandas as pd
from datetime import datetime
import os

SERVER_IP = '10.0.1.2'
SERVER_PORT = 12345
MESSAGGI = [b'Ciao, ', b'ciao ', b'ciao?']
NUM_CICLI = 5

EXCEL_FILE = "packet_stats.xlsx"
SHEET_NAME = "Client"  # 🟢 Foglio unificato per tutti i client
log = []

def salva_client_data():
    global log
    new_df = pd.DataFrame(log, columns=["Timestamp", "IP", "Porta", "Messaggio", "Totale_Pacchetti_Inviati"])

    all_sheets = {}

    # 📥 Legge il file esistente (se c'è)
    if os.path.exists(EXCEL_FILE):
        try:
            all_sheets = pd.read_excel(EXCEL_FILE, sheet_name=None, engine="openpyxl")
        except Exception as e:
            print(f"⚠️ Errore nella lettura di '{EXCEL_FILE}': {e}")
            all_sheets = {}

    # 🔄 Recupera dati esistenti dal foglio 'Client'
    existing_df = all_sheets.get(SHEET_NAME, pd.DataFrame(columns=new_df.columns))
    combined_df = pd.concat([existing_df, new_df], ignore_index=True)
    all_sheets[SHEET_NAME] = combined_df

    # 📝 Scrive tutti i fogli, mantenendo intatti quelli non modificati
    if not all_sheets:
        all_sheets["Placeholder"] = pd.DataFrame({"Note": ["File inizializzato"]})

    with pd.ExcelWriter(EXCEL_FILE, engine="openpyxl") as writer:
        for sheet_name, df in all_sheets.items():
            df.to_excel(writer, sheet_name=sheet_name, index=False)

    print(f"📁 Client (malicious): dati salvati in '{EXCEL_FILE}'")
    log.clear()

def run_client():
    global log
    for ciclo in range(NUM_CICLI):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        packet_count = 0  # reset per ciclo

        try:
            client.connect((SERVER_IP, SERVER_PORT))
            client_ip, client_port = client.getsockname()
            print(f"🚀 Connessione malicious {ciclo + 1}/{NUM_CICLI} da {client_ip}:{client_port}")

            for msg in MESSAGGI:
                client.send(msg)
                packet_count += 1
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                log.append([timestamp, client_ip, client_port, msg.decode(errors='ignore'), packet_count])
                print(f"✉️ Inviato (malicious): {msg.decode(errors='ignore')}")
                time.sleep(random.uniform(0.3, 0.6))

        except Exception as e:
            print(f"❌ Errore (malicious): {e}")
        finally:
            client.close()
            print("🔚 Connessione (malicious) chiusa\n")
            salva_client_data()
            time.sleep(2)

if __name__ == "__main__":
    run_client()
