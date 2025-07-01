import socket
import threading
import logging

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
)

# Config
HOST = '0.0.0.0'
PORT = 12345
FRASI_ACCETTATE = [b'Ciao, come stai?']
TIMEOUT = 10  # secondi di timeout per i client inattivi

def client_handler(conn, addr):
    logging.info(f"🔗 Nuova connessione da {addr}")
    conn.settimeout(TIMEOUT)
    buffer = b""

    try:
        while True:
            try:
                data = conn.recv(4096)
                if not data:
                    logging.info(f"❌ Connessione chiusa dal client {addr}")
                    break

                buffer += data
                logging.debug(f"📥 Ricevuto da {addr}: {data}")

                # Controlla se la frase attesa è nel buffer
                for frase in FRASI_ACCETTATE:
                    if frase in buffer:
                        try:
                            conn.sendall(b"bene")
                            logging.info(f"✅ Risposta inviata a {addr}: 'bene'")
                        except Exception as send_err:
                            logging.error(f"❗ Errore invio risposta a {addr}: {send_err}")
                        return  # Chiudi connessione dopo risposta

            except socket.timeout:
                logging.warning(f"⏳ Timeout da {addr}, chiudo la connessione.")
                break

    except Exception as e:
        logging.error(f"💥 Errore nella connessione con {addr}: {e}")

    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()
        logging.info(f"🔚 Connessione chiusa con {addr}")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT))
        server.listen()
        logging.info(f"🚀 Server in ascolto su {HOST}:{PORT}")
    except Exception as e:
        logging.critical(f"❌ Errore durante il bind/listen del server: {e}")
        return

    while True:
        try:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=client_handler, args=(conn, addr), daemon=True)
            client_thread.start()
        except Exception as e:
            logging.error(f"💥 Errore accettando connessione: {e}")

if __name__ == "__main__":
    main()
