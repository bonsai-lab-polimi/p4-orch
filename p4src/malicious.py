#!/usr/bin/env python3
"""
malicious_traffic_generator.py

Generatore di burst TCP per test di detection distribuita (weak learners).
USO: python3 malicious_traffic_generator.py --server 10.0.1.2 --port 12345 --bursts 1 --packets 27 --iat 0.07

Attenzione: usa questo script SOLO su ambienti di test controllati e verso host
per cui hai autorizzazione esplicita. Non indirizzare traffico non autorizzato a terzi.

Funzionalità:
 - invia uno o più "burst" di pacchetti TCP in una singola connessione
 - possibilità di eseguire client concorrenti (threads)
 - logging su CSV (sempre). Se pandas+openpyxl sono installati, può salvare anche in Excel.
 - opzioni: numero di packets, iat (inter-arrival time medio), jitter, payload size/template,
   intervallo tra burst, invio FIN, timeout socket.
"""

from __future__ import annotations
import socket
import time
import argparse
import random
import threading
import csv
import os
from datetime import datetime
from typing import List, Tuple

# Try importing pandas for Excel support (optional)
try:
    import pandas as pd  # type: ignore
    PANDAS_AVAILABLE = True
except Exception:
    PANDAS_AVAILABLE = False

LOG_LOCK = threading.Lock()
GLOBAL_LOG: List[Tuple[str, str, int, str, int, int, float]] = []
# log entry: (timestamp, local_ip, local_port, payload_str, packet_idx, burst_idx, elapsed_since_start)


def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def send_burst_single_connection(
    server_ip: str,
    server_port: int,
    packets: int = 27,
    iat: float = 0.07,
    jitter_frac: float = 0.25,
    payload_size: int = 100,
    burst_index: int = 0,
    send_fin: bool = True,
    timeout: float = 5.0,
    client_id: int = 0
) -> None:
    """
    Apre una connessione TCP e invia `packets` payloads con inter-arrival time medio `iat`.
    Registra ogni invio in GLOBAL_LOG (thread-safe).
    """
    start_time = time.time()
    try:
        with socket.create_connection((server_ip, server_port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                local_ip, local_port = s.getsockname()
            except Exception:
                local_ip, local_port = "0.0.0.0", 0
            print(f"[Client {client_id}] Connessione a {server_ip}:{server_port} da {local_ip}:{local_port} (burst {burst_index})")

            for i in range(1, packets + 1):
                # Build payload: deterministic template with client_id and packet index
                payload = f"CLIENT{client_id}-BURST{burst_index}-PKT{i}-" + ("X" * max(0, payload_size - 1))
                payload_bytes = payload.encode("utf-8", errors="ignore")

                try:
                    s.sendall(payload_bytes)
                except Exception as e:
                    print(f"[Client {client_id}] Errore invio pacchetto #{i}: {e}")
                    break

                elapsed = time.time() - start_time
                entry = (now_ts(), local_ip, local_port, payload, i, burst_index, elapsed)
                with LOG_LOCK:
                    GLOBAL_LOG.append(entry)

                print(f"[Client {client_id}] Sent #{i:02d} (burst {burst_index}) len={len(payload_bytes)} time={elapsed:.3f}s")

                # jitter: uniform in [-jitter_frac*iat, +jitter_frac*iat]
                jitter = random.uniform(-jitter_frac * iat, jitter_frac * iat)
                sleep_time = max(0.0, iat + jitter)
                time.sleep(sleep_time)

            # Optionally shutdown write side to mimic FIN, then close
            if send_fin:
                try:
                    s.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

    except Exception as e:
        print(f"[Client {client_id}] Impossibile connettersi a {server_ip}:{server_port}: {e}")


def run_client_thread(
    server_ip: str,
    server_port: int,
    bursts: int,
    packets: int,
    iat: float,
    burst_interval: float,
    jitter_frac: float,
    payload_size: int,
    send_fin: bool,
    timeout: float,
    client_id: int
) -> None:
    """
    Thread function: esegue `bursts` volte send_burst_single_connection, aspettando burst_interval tra burst.
    """
    for b in range(1, bursts + 1):
        send_burst_single_connection(
            server_ip=server_ip,
            server_port=server_port,
            packets=packets,
            iat=iat,
            jitter_frac=jitter_frac,
            payload_size=payload_size,
            burst_index=b,
            send_fin=send_fin,
            timeout=timeout,
            client_id=client_id
        )
        if b < bursts:
            time.sleep(burst_interval)


def save_log_csv(path: str = "packet_stats.csv") -> None:
    with LOG_LOCK:
        rows = list(GLOBAL_LOG)

    if not rows:
        print("Nessun dato da salvare.")
        return

    header = ["Timestamp", "Local_IP", "Local_Port", "Payload", "Packet_Index", "Burst_Index", "Elapsed_s"]
    write_header = not os.path.exists(path)
    try:
        with open(path, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if write_header:
                writer.writerow(header)
            for r in rows:
                writer.writerow(r)
        print(f"[LOG] Salvato {len(rows)} righe in {path}")
    except Exception as e:
        print(f"[LOG] Errore salvataggio CSV: {e}")


def save_log_excel(path: str = "packet_stats.xlsx", sheet_name: str = "Client") -> None:
    if not PANDAS_AVAILABLE:
        print("[LOG] pandas non disponibile: impossibile salvare Excel. Installa pandas+openpyxl o usa --csv-only.")
        return

    with LOG_LOCK:
        rows = list(GLOBAL_LOG)

    if not rows:
        print("Nessun dato da salvare.")
        return

    df_new = pd.DataFrame(rows, columns=["Timestamp", "Local_IP", "Local_Port", "Payload", "Packet_Index", "Burst_Index", "Elapsed_s"])
    try:
        if os.path.exists(path):
            # append to existing sheet or create/merge
            with pd.ExcelWriter(path, engine="openpyxl", mode="a", if_sheet_exists="overlay") as writer:
                # read existing sheet if present
                try:
                    existing = pd.read_excel(path, sheet_name=sheet_name, engine="openpyxl")
                    df_combined = pd.concat([existing, df_new], ignore_index=True)
                except Exception:
                    df_combined = df_new
                df_combined.to_excel(writer, sheet_name=sheet_name, index=False)
        else:
            with pd.ExcelWriter(path, engine="openpyxl") as writer:
                df_new.to_excel(writer, sheet_name=sheet_name, index=False)
        print(f"[LOG] Salvato {len(rows)} righe in {path} (sheet: {sheet_name})")
    except Exception as e:
        print(f"[LOG] Errore salvataggio Excel: {e}")


def parse_args():
    parser = argparse.ArgumentParser(description="TCP burst traffic generator for WL detection testing.")
    parser.add_argument("--server", "-s", required=False, default="10.0.1.2", help="Server IP (target)")
    parser.add_argument("--port", "-p", required=False, default=12345, type=int, help="Server port")
    parser.add_argument("--bursts", "-b", required=False, default=1, type=int, help="Number of bursts per client")
    parser.add_argument("--packets", "-n", required=False, default=60, type=int, help="Packets per burst")
    parser.add_argument("--iat", required=False, default=0.07, type=float, help="Average inter-arrival time (s) between packets")
    parser.add_argument("--jitter", required=False, default=0.25, type=float, help="Fractional jitter of IAT (0..1)")
    parser.add_argument("--burst-interval", required=False, default=2.0, type=float, help="Seconds between bursts")
    parser.add_argument("--clients", required=False, default=1, type=int, help="Number of parallel client threads")
    parser.add_argument("--payload-size", required=False, default=600, type=int, help="Approximate payload size in bytes")
    parser.add_argument("--send-fin/--no-fin", dest="send_fin", default=True, help="Whether to shutdown write side (FIN) after burst")
    parser.add_argument("--timeout", required=False, default=5.0, type=float, help="Socket connect/send timeout (s)")
    parser.add_argument("--csv", required=False, default="packet_stats.csv", help="CSV file path to save logs (default: packet_stats.csv)")
    parser.add_argument("--excel", required=False, default=None, help="Excel file path to save logs (requires pandas+openpyxl). If omitted, only CSV is written.")
    return parser.parse_args()


def main():
    args = parse_args()

    print("=== Malicious Traffic Generator ===")
    print("ATTENZIONE: usare SOLO in ambiente di test o verso host autorizzati.")
    print(f"Target: {args.server}:{args.port} | bursts={args.bursts} | packets={args.packets} | clients={args.clients}")
    if args.excel and not PANDAS_AVAILABLE:
        print("[WARN] Hai chiesto Excel ma pandas non è disponibile. Verrà scritto solo CSV.")

    threads = []
    for client_id in range(1, args.clients + 1):
        t = threading.Thread(
            target=run_client_thread,
            args=(
                args.server,
                args.port,
                args.bursts,
                args.packets,
                args.iat,
                args.burst_interval,
                args.jitter,
                args.payload_size,
                args.send_fin,
                args.timeout,
                client_id,
            ),
            daemon=False,
        )
        threads.append(t)
        t.start()
        # small stagger to avoid all clients opening at the exact same instant
        time.sleep(0.02)

    # wait for threads to finish
    for t in threads:
        t.join()

    # save logs
    save_log_csv(args.csv)
    if args.excel:
        save_log_excel(args.excel)

    print("Done.")


if __name__ == "__main__":
    main()
