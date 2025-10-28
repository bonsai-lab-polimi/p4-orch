#!/usr/bin/env python3
"""
Invia 50 piccoli pacchetti TCP (PSH) verso un server.
Usare solo in ambiente di test controllato.
"""
import socket
import time
from datetime import datetime
import argparse

def now_ms():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def psh_sender(dst_ip, dst_port, count=50, iat=0.05, payload=b"x"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((dst_ip, dst_port))
        # Disabilita Nagle -> invio immediato di piccoli send() (favorisce PSH)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        print(f"[{now_ms()}] Connessione stabilita {s.getsockname()} -> {(dst_ip, dst_port)}")
        start = time.time()

        for i in range(1, count+1):
            try:
                s.sendall(payload)   # kernel invierà il pacchetto (con PSH)
            except Exception as e:
                print(f"[{now_ms()}] Errore in send: {e}")
                break
            print(f"[{now_ms()}] Inviato #{i} len={len(payload)}")
            time.sleep(iat)

        total = time.time() - start
        print(f"[{now_ms()}] Completati {i} invii in {total:.3f}s -> ~{(i/total) if total>0 else 0:.1f} pps")
    finally:
        s.close()
        print(f"[{now_ms()}] Connessione chiusa")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PSH sender (socket TCP, TCP_NODELAY)")
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--dst-port", type=int, required=True)
    parser.add_argument("--count", type=int, default=50, help="numero di pacchetti da inviare")
    parser.add_argument("--iat", type=float, default=0.05, help="inter-arrival time (s)")
    parser.add_argument("--payload", type=str, default="x", help="payload da inviare (stringa)")
    args = parser.parse_args()

    psh_sender(args.dst_ip, args.dst_port, count=args.count, iat=args.iat, payload=args.payload.encode())
