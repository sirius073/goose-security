#!/usr/bin/env python3
import time
import os
import argparse
import socket
import struct
import csv
import resource
import json
import tracemalloc
import threading
import queue
import fcntl

# --- CRYPTO IMPORTS ---
from crypto_algos.chacha20_provider import ChaCha20Provider
from crypto_algos.ascon128a_provider import Ascon128aProvider
from crypto_algos.ed25519_provider import Ed25519Provider
from crypto_algos.ecies_provider import ECIESProvider
from crypto_algos.aes_gcm_provider import AESGCMProvider

parser = argparse.ArgumentParser(description="Multi-Threaded R-GOOSE Subscriber")
parser.add_argument("--algo", type=str, default="none", help="Choices: none, ecies, ascon, ed25519, chacha, aesgcm")
parser.add_argument("--csv", type=str, default="./metrics/goose_metrics.csv", help="CSV file to append metrics")
parser.add_argument("--threads", type=int, default=2, help="Number of crypto worker threads")
parser.add_argument("--iface", type=str, default="h2-eth0", help="Network interface to listen on")
args = parser.parse_args()

# --- R-GOOSE Configuration ---
MCAST_GRP = '239.0.0.1'
MCAST_PORT = 10102

os.makedirs(os.path.dirname(args.csv), exist_ok=True)

# GLOBAL METRICS & THREAD LOCKS
total_attempts = 0
valid_packet_count = 0
sum_net_transit = 0.0
total_payload_bits = 0
metric_sums = {}

print_lock = threading.Lock()
csv_lock = threading.Lock()
metrics_lock = threading.Lock()
packet_queue = queue.Queue()

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', bytes(ifname[:15], 'utf-8'))
        )[20:24])
    except OSError:
        print(f"[!] Error: Could not find IP for interface '{ifname}'. Check if interface exists.")
        os._exit(1)

def cur_mem_kb():
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return float(getattr(usage, "ru_maxrss", 0.0))
    except Exception:
        return 0.0

def write_csv_header_if_needed(csv_path):
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="") as cf:
            writer = csv.writer(cf)
            writer.writerow(["ts","direction","algo","msg_index","net_transit_ms","crypto_ms",
                             "payload_bytes","overhead_bytes","throughput_mbps","mem_kb","message_text", "detailed_metrics"])

def process_goose_worker(crypto_provider, csv_path):
    global total_attempts, valid_packet_count, sum_net_transit, total_payload_bits, metric_sums

    while True:
        udp_payload, wire_recv_timestamp = packet_queue.get()

        if len(udp_payload) < 8:
            packet_queue.task_done()
            continue

        with metrics_lock:
            total_attempts += 1
            current_attempt = total_attempts

        timestamp_bytes = udp_payload[:8]
        secure_stream = udp_payload[8:]

        try:
            send_timestamp = struct.unpack("!d", timestamp_bytes)[0]

            if crypto_provider is None:
                raw_goose_payload = secure_stream
                sub_metrics = {"sub_total_crypto_ms": 0.0, "sub_cpu_process_ms": 0.0, "sub_peak_memory_bytes": 0}
            else:
                tracemalloc.start()
                cpu_start = time.process_time_ns()

                raw_goose_payload, sub_metrics = crypto_provider.verify(secure_stream)

                cpu_end = time.process_time_ns()
                current_mem, peak_mem = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                sub_metrics["sub_cpu_process_ms"] = (cpu_end - cpu_start) / 1_000_000.0
                sub_metrics["sub_peak_memory_bytes"] = peak_mem

            t_net = max(0.0001, (wire_recv_timestamp - send_timestamp) * 1000)

            with metrics_lock:
                if total_attempts > 1:
                    valid_packet_count += 1
                    sum_net_transit += t_net
                    total_payload_bits += (len(udp_payload) * 8)
                    current_valid = valid_packet_count
                    for key, val in sub_metrics.items():
                        metric_sums[key] = metric_sums.get(key, 0.0) + val
                else:
                    current_valid = valid_packet_count

            crypto_ms = sub_metrics.get("sub_total_crypto_ms", 0.0)
            crypto_time_sec = max(0.0001, crypto_ms / 1000.0)
            throughput_mbps = ((len(udp_payload) * 8) / crypto_time_sec) / 1_000_000 if crypto_ms > 0 else 0.0
            mem_kb = cur_mem_kb()

            with csv_lock:
                with open(csv_path, "a", newline="") as cf:
                    csvw = csv.writer(cf)
                    csvw.writerow([time.time(), "subscriber", crypto_provider.get_algo_name() if crypto_provider else "NONE",
                                   current_valid, f"{t_net:.4f}", f"{crypto_ms:.4f}", len(raw_goose_payload),
                                   "", f"{throughput_mbps:.4f}", f"{mem_kb:.1f}", "", json.dumps(sub_metrics)])

            with print_lock:
                if current_valid > 0 and current_valid % 20 == 0:
                    tot_ms = sub_metrics.get("sub_total_crypto_ms", 0.0)
                    print(f"[*] [Thread-{threading.get_ident()}] Success {current_valid} | Transit: {t_net:.4f}ms | Crypto: {tot_ms:.4f}ms")

                if current_valid > 0 and current_valid % 100 == 0:
                    avg_net = sum_net_transit / current_valid
                    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE"
                    print(f"\n[*] =========================================")
                    print(f"[*] SUBSCRIBER METRICS ({current_valid} Message Running Average)")
                    print(f"[*] Algorithm: {algo_name} | Avg Transit: {avg_net:.5f} ms")
                    print(f"[*] =========================================")

        except ValueError as ve:
            error_msg = str(ve)
            with print_lock:
                print(f"\n[!!!] CRITICAL SECURITY ALERT | Packet Attempt #{current_attempt} [!!!]")
                if "Replay" in error_msg:
                    print(f"    [TYPE] Anti-Replay Violation")
                elif "Tampering" in error_msg or "Signature" in error_msg:
                    print(f"    [TYPE] Integrity/Authentication Violation")
                else:
                    print(f"    [TYPE] Unknown Security Error: {error_msg}")
                print(f"[!] DROPPING MALICIOUS PACKET. CONTINUING RECEPTION.\n")
        except Exception:
            pass
        finally:
            packet_queue.task_done()

def network_listener(sock):
    try:
        while True:
            udp_payload, addr = sock.recvfrom(4096)
            wire_recv_timestamp = time.time()
            packet_queue.put((udp_payload, wire_recv_timestamp))
    except KeyboardInterrupt:
        pass

def start_subscriber(crypto_provider, csv_path, num_threads):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext)"
    print(f"[*] Starting Multi-Threaded R-GOOSE Subscriber...")
    print(f"[*] Interface: {args.iface} | Listening on: {MCAST_GRP}:{MCAST_PORT}")
    print(f"[*] Security Algorithm: {algo_name}")
    print(f"[*] Spawning {num_threads} Crypto Worker Threads...\n")

    write_csv_header_if_needed(csv_path)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', MCAST_PORT))

    # Fix Errno 19: Bind IGMP Join to specific interface IP
    local_ip = get_ip_address(args.iface)
    mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(local_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    for _ in range(num_threads):
        worker = threading.Thread(target=process_goose_worker, args=(crypto_provider, csv_path), daemon=True)
        worker.start()

    try:
        network_listener(sock)
    except KeyboardInterrupt:
        print("\n[*] Subscriber manually stopped. Exiting safely.")
        os._exit(0)

def get_crypto_provider(algo_name):
    algo_name = algo_name.lower()
    if algo_name == "none": return None
    elif algo_name == "ed25519": return Ed25519Provider(role="subscriber")
    elif algo_name == "ecies": return ECIESProvider(role="subscriber")

    key_path = "keys/shared_key.bin"
    if not os.path.exists(key_path):
        print(f"Error: {key_path} missing.")
        os._exit(1)
    with open(key_path, "rb") as f: master_shared_key = f.read()
    if algo_name == "chacha": return ChaCha20Provider(master_shared_key)
    elif algo_name == "ascon": return Ascon128aProvider(master_shared_key)
    elif algo_name == "aesgcm": return AESGCMProvider(master_shared_key)
    else: os._exit(1)

if __name__ == "__main__":
    active_crypto_module = get_crypto_provider(args.algo)
    start_subscriber(active_crypto_module, args.csv, args.threads)