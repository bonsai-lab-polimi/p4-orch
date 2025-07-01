import socket
import time
import random
import string

SERVER_IP = '10.0.1.2'
SERVER_PORT = 12345

def generate_payload(size):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=size)).encode()

while True:
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, SERVER_PORT))
        print("🚨 Connessione stress aperta")

        while True:
            data = generate_payload(10 * 1024)  # 10 KB a pacchetto
            client.sendall(data)
            time.sleep(0.1)  # 1 ms tra invii

    except Exception as e:
        print(f"❌ Stress client errore: {e}")
        time.sleep(1)
