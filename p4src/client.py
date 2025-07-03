import socket
import time
import random

SERVER_IP = '10.0.1.2'  # Cambia con IP del server
SERVER_PORT = 12345
MESSAGGI = [b'Ciao, ', b'come ', b'stai?']

def run_client():
    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((SERVER_IP, SERVER_PORT))
            print("🚀 Connessione avviata")

            for msg in MESSAGGI:
                client.send(msg)
                print(f"✉️ Inviato: {msg.decode()}")
                time.sleep(random.uniform(0.3, 0.7))

            risposta_completa = b""
            while True:
                data = client.recv(1024)
                if not data:
                    # Connessione chiusa dal server
                    break
                risposta_completa += data

            print(f"✅ Risposta ricevuta: {risposta_completa.decode(errors='ignore')}")

        except Exception as e:
            print(f"❌ Errore: {e}")

        finally:
            client.close()
            print("🔚 Connessione chiusa, riprovo tra 2 secondi...\n")
            time.sleep(2)  # pausa prima di riaprire la connessione e ricominciare

if __name__ == "__main__":
    run_client()
