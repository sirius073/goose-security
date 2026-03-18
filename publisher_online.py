#!/usr/bin/env python3
# publisher_metrics.py
import time
import os
import argparse
import socket
import struct
import csv
import resource  
import json      
import tracemalloc  

# --- PYGOOSE IMPORT ---
# Assuming pygoose is accessible in your Python path as per your reference scripts
from pygoose.goose import generate_goose

# ---------------------------------------------------------------------------
from crypto_algos.chacha20_provider import ChaCha20Provider
from crypto_algos.ascon128a_provider import Ascon128aProvider
from crypto_algos.ed25519_provider import Ed25519Provider
from crypto_algos.ecies_provider import ECIESProvider
from crypto_algos.aes_gcm_provider import AESGCMProvider
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Layer 2 GOOSE Publisher (with live generation & metrics)")
parser.add_argument("--algo", type=str, default="none", help="Choices: none, ecies, ascon, ed25519, chacha, aesgcm")
parser.add_argument("--count", type=int, default=100, help="Number of GOOSE messages to generate and send")
parser.add_argument("--csv", type=str, default="./metrics/goose_metrics.csv", help="CSV file to append metrics")
args = parser.parse_args()

GOOSE_TYPE = 0x88B8
IFACE = "h1-eth0"

os.makedirs(os.path.dirname(args.csv), exist_ok=True)

def initialize_csv(csv_path):
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
    print(f"[*] Starting Live Layer 2 Publisher...")
    print(f"[*] Security Algorithm: {algo_name}")
    print(f"[*] Generating {msg_count_target} messages on the fly...")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(GOOSE_TYPE))
    sock.bind((IFACE, 0))

    initialize_csv(csv_path)

    metric_sums = {}
    total_payload_bits = 0
    msg_count = 0
    overhead_calculated = False
    msg_index = 0

    with open(csv_path, "a", newline="") as cf:
        csvw = csv.writer(cf)
        
        # 1. Start the Live Generator Stream
        for wait_for_us, raw_packet in generate_goose(msg_count_target):
            
            # 2. Simulate the real-world GOOSE timing delay before processing
            if wait_for_us > 0:
                time.sleep(wait_for_us / 1_000_000.0)

            eth_header = raw_packet[:14]
            goose_payload = raw_packet[14:]

            # 3. Protect the GOOSE payload
            if crypto_provider is None:
                secure_stream = goose_payload
                pub_metrics = {"pub_total_crypto_ms": 0.0, "pub_cpu_process_ms": 0.0, "pub_peak_memory_bytes": 0}
                overhead_bytes = 0
            else:
                # --- START MEASUREMENT ---
                tracemalloc.start()
                cpu_start = time.process_time_ns()

                secure_stream, pub_metrics = crypto_provider.protect(goose_payload)

                # --- STOP MEASUREMENT ---
                cpu_end = time.process_time_ns()
                current_mem, peak_mem = tracemalloc.get_traced_memory()
                tracemalloc.stop()

                # Convert nanoseconds to milliseconds
                cpu_process_ms = (cpu_end - cpu_start) / 1_000_000.0
                
                # Add to metrics dictionary
                pub_metrics["pub_cpu_process_ms"] = cpu_process_ms
                pub_metrics["pub_peak_memory_bytes"] = peak_mem
                
                overhead_bytes = len(secure_stream) - len(goose_payload)

            # DISPLAY OVERHEAD ONCE (Before 1st Message)
            if not overhead_calculated:
                print(f"[*] =========================================")
                print(f"[*] CRYPTOGRAPHIC OVERHEAD ANALYSIS")
                print(f"[*] -----------------------------------------")
                print(f"[*] Original Payload   : {len(goose_payload)} bytes")
                print(f"[*] Crypto Metadata    : {overhead_bytes} bytes (Tags/Nonces/Salt)")
                print(f"[*] Network Latency TS : 8 bytes")
                print(f"[*] Total Added Bytes  : {overhead_bytes + 8} bytes")
                print(f"[*] =========================================\n")
                print(f"[*] Transmitting live messages...\n")
                overhead_calculated = True

            timestamp_bytes = struct.pack("!d", time.time())
            packet = eth_header + timestamp_bytes + secure_stream
            sock.send(packet)

            msg_index += 1
            msg_count += 1

            if msg_count > 1:
                for key, val in pub_metrics.items():
                    metric_sums[key] = metric_sums.get(key, 0.0) + val
                total_payload_bits += (len(packet) * 8)

                if msg_count % 20 == 0:
                    tot_ms = pub_metrics.get("pub_total_crypto_ms", 0.0)
                    print(f"[*] Sent {msg_count} packets | Last Payload Gen: {tot_ms:.4f}ms")

            crypto_ms = pub_metrics.get("pub_total_crypto_ms", 0.0)
            crypto_time_sec = max(0.0001, crypto_ms / 1000.0)
            throughput_mbps = ((len(packet) * 8) / crypto_time_sec) / 1_000_000

            mem_kb = cur_mem_kb()

            try:
                printable = ''.join([c if c.isprintable() else '.' for c in goose_payload.decode('ascii', errors='ignore')])
                printable = printable[:200]
            except Exception:
                printable = ""

            csvw.writerow([time.time(), "publisher", algo_name, msg_index, "", crypto_ms,
                           len(goose_payload), overhead_bytes, f"{throughput_mbps:.4f}", f"{mem_kb:.1f}", printable, json.dumps(pub_metrics)])
            cf.flush()

    # Final Metric Calculations
    valid_count = max(1, msg_count - 1)
    total_crypto_sum = metric_sums.get("pub_total_crypto_ms", 0.0)
    crypto_time_sec = max(0.0001, total_crypto_sum / 1000.0)
    throughput_mbps = (total_payload_bits / crypto_time_sec) / 1_000_000

    print(f"\n[*] =========================================")
    print(f"[*] PUBLISHER METRICS ({valid_count} Message Average)")
    print(f"[*] Algorithm: {algo_name}")
    print(f"[*] =========================================")
    for key, total_val in metric_sums.items():
        if key != "pub_total_crypto_ms":
            formatted_name = key.replace('_', ' ').title()
            print(f"  Avg {formatted_name.ljust(22)}: {(total_val / valid_count):.5f} ms/bytes")
    print(f"  -----------------------------------------")
    print(f"  Total Avg Payload Gen   : {(total_crypto_sum / valid_count):.5f} ms")
    print(f"  Processing Throughput   : {throughput_mbps:.2f} Mbps")
    print(f"[*] =========================================")
    sock.close()

def get_crypto_provider(algo_name):
    algo_name = algo_name.lower()
    if algo_name == "none": return None
    elif algo_name == "ed25519": return Ed25519Provider(role="publisher")
    elif algo_name == "ecies": return ECIESProvider(role="publisher")

    key_path = "keys/shared_key.bin"
    if not os.path.exists(key_path):
        print(f"Error: {key_path} missing.")
        exit(1)
    with open(key_path, "rb") as f: master_shared_key = f.read()
    if algo_name == "chacha": return ChaCha20Provider(master_shared_key)
    elif algo_name == "ascon": return Ascon128aProvider(master_shared_key)
    elif algo_name == "aesgcm": return AESGCMProvider(master_shared_key)
    else: exit(1)

if __name__ == "__main__":
    active_crypto_module = get_crypto_provider(args.algo)
    start_publisher(active_crypto_module, args.count, args.csv)