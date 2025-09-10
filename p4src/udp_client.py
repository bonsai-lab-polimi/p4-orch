import socket
import time
import pandas as pd
from datetime import datetime
import os

SERVER_IP = '10.0.1.2'
SERVER_PORT = 54321
NUM_PACKETS = 5000
INTERVAL = 0.1  # secondi tra pacchetti

EXCEL_FILE = "packet_stats.xlsx"
SHEET_NAME = "Client"  # 🔁 Tutti scrivono qui
log = []

def salva_client_data():
    global log
    new_df = pd.DataFrame(log, columns=["Timestamp", "IP", "Porta", "Messaggio", "Totale_Pacchetti_Inviati"])

    all_sheets = {}

    # ✅ Legge il file se esiste
    if os.path.exists(EXCEL_FILE):
        try:
            all_sheets = pd.read_excel(EXCEL_FILE, sheet_name=None, engine="openpyxl")
        except Exception as e:
            print(f"⚠️ Errore nella lettura di '{EXCEL_FILE}': {e}")
            all_sheets = {}

    # 🔄 Recupera dati esistenti del foglio "Client"
    existing_df = all_sheets.get(SHEET_NAME, pd.DataFrame(columns=new_df.columns))
    combined_df = pd.concat([existing_df, new_df], ignore_index=True)
    all_sheets[SHEET_NAME] = combined_df

    # 📄 Scrive tutti i fogli mantenendo gli altri
    if not all_sheets:
        all_sheets["Placeholder"] = pd.DataFrame({"Note": ["File inizializzato"]})

    with pd.ExcelWriter(EXCEL_FILE, engine="openpyxl") as writer:
        for sheet_name, df in all_sheets.items():
            df.to_excel(writer, sheet_name=sheet_name, index=False)

    print(f"📁 Client UDP: dati salvati in '{EXCEL_FILE}'")
    log.clear()

def get_local_ip_port():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((SERVER_IP, SERVER_PORT))
        ip = s.getsockname()[0]
        port = s.getsockname()[1]
        s.close()
        return ip, port
    except:
        return "unknown", 0

def run_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((SERVER_IP, SERVER_PORT))  # stabilisce IP e porta locali
    client_ip, client_port = sock.getsockname()  # ora sono quelli effettivi del socket usato

    print(f"🚀 Inizio invio UDP verso {SERVER_IP}:{SERVER_PORT} da {client_ip}:{client_port}")

    for i in range(NUM_PACKETS):
        msg = f"packet_{i}".encode()
        try:
            sock.send(msg)  # usa connect() invece di sendto()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            log.append([timestamp, client_ip, client_port, msg.decode(), i + 1])
            time.sleep(INTERVAL)
        except Exception as e:
            print(f"❌ Errore invio UDP: {e}")
            break

    sock.close()
    print("🔚 Fine invio UDP. Salvataggio log...")
    salva_client_data()

if __name__ == "__main__":
    run_client()
