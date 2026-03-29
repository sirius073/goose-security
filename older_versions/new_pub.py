#!/usr/bin/env python3
import time
import os
import argparse
import socket
import struct

# ---------------------------------------------------------------------------
from crypto_algos.chacha20_provider import ChaCha20Provider
from crypto_algos.ascon128a_provider import Ascon128aProvider
from crypto_algos.ed25519_provider import Ed25519Provider
from crypto_algos.ecies_provider import ECIESProvider
from crypto_algos.aes_gcm_provider import AESGCMProvider
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Layer 2 GOOSE Publisher")
parser.add_argument("--algo", type=str, default="none", help="Choices: none, ecies, ascon, ed25519, chacha, aesgcm")
parser.add_argument("--file", type=str, default="goose_armory.bin", help="Path to the binary file containing the raw GOOSE messages")
args = parser.parse_args()

GOOSE_TYPE = 0x88B8
IFACE = "h1-eth0" 

def start_publisher(crypto_provider, payload_file_path):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext)"
    print(f"[*] Starting Layer 2 Publisher...")
    print(f"[*] Security Algorithm: {algo_name}")
    
    if not os.path.exists(payload_file_path):
        print(f"[!] Error: Payload file '{payload_file_path}' not found.")
        exit(1)
        
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(GOOSE_TYPE))
    sock.bind((IFACE, 0))
    
    metric_sums = {}
    total_payload_bits = 0
    msg_count = 0
    overhead_calculated = False

    with open(payload_file_path, "rb") as f:
        while True:
            meta_bytes = f.read(8)
            if not meta_bytes or len(meta_bytes) < 8:
                break 
                
            wait_for, pkt_len = struct.unpack("!fI", meta_bytes)
            raw_packet = f.read(pkt_len)
            if len(raw_packet) != pkt_len:
                break 
            
            eth_header = raw_packet[:14]
            goose_payload = raw_packet[14:] 
            
            # 4. Protect the GOOSE payload
            if crypto_provider is None:
                secure_stream = goose_payload
                pub_metrics = {"pub_total_crypto_ms": 0.0}
                overhead_bytes = 0
            else:
                secure_stream, pub_metrics = crypto_provider.protect(goose_payload)
                # Calculate Overhead: Difference between protected stream and original payload
                # This doesn't include the 8-byte network timestamp we add later
                overhead_bytes = len(secure_stream) - len(goose_payload)

            # DISPLAY OVERHEAD ONCE (Before 1st Message)
            if not overhead_calculated:
                print(f"[*] =========================================")
                print(f"[*] CRYPTOGRAPHIC OVERHEAD ANALYSIS")
                print(f"[*] -----------------------------------------")
                print(f"[*] Original Payload   : {len(goose_payload)} bytes")
                print(f"[*] Crypto Metadata    : {overhead_bytes} bytes (Tag + Nonce[BootID|stNum|sqNum])")
                print(f"[*] Network Latency TS : 8 bytes")
                print(f"[*] Total Added Bytes  : {overhead_bytes + 8} bytes")
                print(f"[*] =========================================\n")
                print(f"[*] Transmitting messages...\n")
                overhead_calculated = True

            # Pack timestamp for latency calculation (This happens AFTER crypto)
            timestamp_bytes = struct.pack("!d", time.time())
            
            # 5. Assemble and Send
            packet = eth_header + timestamp_bytes + secure_stream
            sock.send(packet)
            
            msg_count += 1
            
            if msg_count > 1:
                for key, val in pub_metrics.items():
                    metric_sums[key] = metric_sums.get(key, 0.0) + val
                total_payload_bits += (len(packet) * 8)
                
                if msg_count % 20 == 0:
                    tot_ms = pub_metrics.get("pub_total_crypto_ms", 0.0)
                    print(f"[*] Sent {msg_count} packets | Last Payload Gen: {tot_ms:.4f}ms")
            
            if wait_for > 0:
                time.sleep(wait_for / 1_000_000.0)

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
            print(f"  Avg {formatted_name.ljust(22)}: {(total_val / valid_count):.5f} ms")
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
    start_publisher(active_crypto_module, args.file)