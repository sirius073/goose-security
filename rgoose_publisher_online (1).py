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
import fcntl

# --- PYGOOSE IMPORT ---
from pygoose.goose import generate_goose

# --- CRYPTO IMPORTS ---
from crypto_algos.chacha20_provider import ChaCha20Provider
from crypto_algos.ascon128a_provider import Ascon128aProvider
from crypto_algos.ed25519_provider import Ed25519Provider
from crypto_algos.ecies_provider import ECIESProvider
from crypto_algos.aes_gcm_provider import AESGCMProvider

parser = argparse.ArgumentParser(description="R-GOOSE Publisher (UDP Multicast)")
parser.add_argument("--algo", type=str, default="none", help="Choices: none, ecies, ascon, ed25519, chacha, aesgcm")
parser.add_argument("--count", type=int, default=100, help="Number of GOOSE messages to generate")
parser.add_argument("--csv", type=str, default="./metrics/goose_metrics.csv", help="CSV file to append metrics")
parser.add_argument("--iface", type=str, default="h1-eth0", help="Network interface to broadcast on")
args = parser.parse_args()

# --- R-GOOSE Configuration ---
MCAST_GRP = '239.0.0.1'
MCAST_PORT = 10102
TTL = 5

os.makedirs(os.path.dirname(args.csv), exist_ok=True)

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

def initialize_csv(csv_path):
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="") as cf:
            writer = csv.writer(cf)
            writer.writerow(["ts","direction","algo","msg_index","net_transit_ms","crypto_ms",
                             "payload_bytes","overhead_bytes","throughput_mbps","mem_kb","message_text", "detailed_metrics"])

def cur_mem_kb():
    try:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return float(getattr(usage, "ru_maxrss", 0.0))
    except Exception:
        return 0.0

def start_publisher(crypto_provider, msg_count_target, csv_path):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext)"
    print(f"[*] Starting R-GOOSE Publisher...")
    print(f"[*] Interface: {args.iface} | Multicast Target: {MCAST_GRP}:{MCAST_PORT}")
    print(f"[*] Security Algorithm: {algo_name}")
    
    # Setup UDP Socket and bind to specific outgoing interface
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)
    local_ip = get_ip_address(args.iface)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))

    initialize_csv(csv_path)

    metric_sums = {}
    total_payload_bits = 0
    msg_count = 0
    overhead_calculated = False
    msg_index = 0

    with open(csv_path, "a", newline="") as cf:
        csvw = csv.writer(cf)
        
        for wait_for_us, raw_packet in generate_goose(msg_count_target):
            if wait_for_us > 0:
                time.sleep(wait_for_us / 1_000_000.0)

            goose_payload = raw_packet[14:] # Strip Ethernet header

            if crypto_provider is None:
                secure_stream = goose_payload
                pub_metrics = {"pub_total_crypto_ms": 0.0, "pub_cpu_process_ms": 0.0, "pub_peak_memory_bytes": 0}
                overhead_bytes = 0
            else:
                tracemalloc.start()
                cpu_start = time.process_time_ns()

                secure_stream, pub_metrics = crypto_provider.protect(goose_payload)

                cpu_end = time.process_time_ns()
                current_mem, peak_mem = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                pub_metrics["pub_cpu_process_ms"] = (cpu_end - cpu_start) / 1_000_000.0
                pub_metrics["pub_peak_memory_bytes"] = peak_mem
                overhead_bytes = len(secure_stream) - len(goose_payload)

            if not overhead_calculated:
                print(f"\n[*] Transmitting live R-GOOSE messages...\n")
                overhead_calculated = True

            timestamp_bytes = struct.pack("!d", time.time())
            udp_payload = timestamp_bytes + secure_stream
            
            sock.sendto(udp_payload, (MCAST_GRP, MCAST_PORT))

            msg_index += 1
            msg_count += 1

            if msg_count > 1:
                for key, val in pub_metrics.items():
                    metric_sums[key] = metric_sums.get(key, 0.0) + val
                total_payload_bits += (len(udp_payload) * 8)

                if msg_count % 20 == 0:
                    tot_ms = pub_metrics.get("pub_total_crypto_ms", 0.0)
                    print(f"[*] Sent {msg_count} packets | Last Payload Gen: {tot_ms:.4f}ms")

            crypto_ms = pub_metrics.get("pub_total_crypto_ms", 0.0)
            crypto_time_sec = max(0.0001, crypto_ms / 1000.0)
            throughput_mbps = ((len(udp_payload) * 8) / crypto_time_sec) / 1_000_000
            mem_kb = cur_mem_kb()

            try:
                printable = ''.join([c if c.isprintable() else '.' for c in goose_payload.decode('ascii', errors='ignore')])[:200]
            except Exception:
                printable = ""

            csvw.writerow([time.time(), "publisher", algo_name, msg_index, "", crypto_ms,
                           len(goose_payload), overhead_bytes, f"{throughput_mbps:.4f}", f"{mem_kb:.1f}", printable, json.dumps(pub_metrics)])
            cf.flush()

    sock.close()

def get_crypto_provider(algo_name):
    algo_name = algo_name.lower()
    if algo_name == "none": return None
    elif algo_name == "ed25519": return Ed25519Provider(role="publisher")
    elif algo_name == "ecies": return ECIESProvider(role="publisher")

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
    start_publisher(active_crypto_module, args.count, args.csv)