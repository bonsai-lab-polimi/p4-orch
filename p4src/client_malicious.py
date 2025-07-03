import socket
import time
import random

SERVER_IP = '10.0.1.2'
SERVER_PORT = 12345
MESSAGGI = [b'Malicious, ', b'flow ']
def run_malicious_client():
    while True:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((SERVER_IP, SERVER_PORT))
            print("🚀 Connessione aperta")
            for msg in MESSAGGI:
                client.send(msg)
                print(f"✉️ Inviato: {msg.decode()}")
                time.sleep(random.uniform(0.3, 0.7))
        except Exception as e:
            print(f"❌ Errore client: {e}")
        finally:
            client.close()
            print("🔚 Connessione chiusa")

if __name__ == "__main__":

    run_malicious_client()
