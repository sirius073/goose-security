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

parser = argparse.ArgumentParser(description="Layer 2 GOOSE Subscriber")
parser.add_argument("--algo", type=str, default="none", help="Choices: none, ecies, ascon, ed25519, chacha, aesgcm")
args = parser.parse_args()

GOOSE_TYPE = 0x88B8
IFACE = "h2-eth0" 

# GLOBAL METRICS
total_attempts = 0  
valid_packet_count = 0
sum_net_transit = 0.0
total_payload_bits = 0
metric_sums = {}

def process_goose_frame(raw_packet, crypto_provider):
    global total_attempts, valid_packet_count, sum_net_transit, total_payload_bits, metric_sums
    
    wire_recv_timestamp = time.time()
    
    # Needs 14 (Eth Header) + 8 (Timestamp) = 22 bytes minimum
    if len(raw_packet) < 22: 
        return
        
    total_attempts += 1
    
    eth_header = raw_packet[:14]
    timestamp_bytes = raw_packet[14:22]
    secure_stream = raw_packet[22:]
    
    try:
        # 1. Unpack the 8-byte network timestamp
        send_timestamp = struct.unpack("!d", timestamp_bytes)[0]
        
        # 2. Cryptographic Verification & Authentication
        if crypto_provider is None:
            raw_goose_payload = secure_stream
            sub_metrics = {"sub_total_crypto_ms": 0.0}
        else:
            raw_goose_payload, sub_metrics = crypto_provider.verify(secure_stream)

        # 3. Reconstruct the full Layer 2 frame (Ready for PyGoose later)
        full_frame = eth_header + raw_goose_payload
        
        # 4. If we reach here, the packet is AUTHENTIC and FRESH
        t_net = max(0.0001, (wire_recv_timestamp - send_timestamp) * 1000)
        
        # Skip the 1st packet for metric accumulation (warmup)
        if total_attempts > 1: 
            valid_packet_count += 1
            sum_net_transit += t_net
            total_payload_bits += (len(raw_packet) * 8)
            
            for key, val in sub_metrics.items():
                metric_sums[key] = metric_sums.get(key, 0.0) + val
            
            if valid_packet_count % 20 == 0:
                tot_ms = sub_metrics.get("sub_total_crypto_ms", 0.0)
                print(f"[*] Success {valid_packet_count}/100 | Transit: {t_net:.4f}ms | Sub Crypto: {tot_ms:.4f}ms | Attempt #{total_attempts}")
            
            # 5. Final Averages and Exiting (Benchmarking 100 packets)
            if valid_packet_count == 100:
                avg_net = sum_net_transit / 100.0
                total_crypto_sum = metric_sums.get("sub_total_crypto_ms", 0.0)
                crypto_time_sec = max(0.0001, total_crypto_sum / 1000.0)
                throughput_mbps = (total_payload_bits / crypto_time_sec) / 1_000_000
                algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext)"
                
                print(f"\n[*] =========================================")
                print(f"[*] SUBSCRIBER METRICS (100 Message Average)")
                print(f"[*] Algorithm: {algo_name}")
                print(f"[*] =========================================")
                print(f"  Avg Network Transit     : {avg_net:.5f} ms")
                print(f"  -----------------------------------------")
                
                for key, total_val in metric_sums.items():
                    if key != "sub_total_crypto_ms":
                        formatted_name = key.replace('_', ' ').title()
                        print(f"  Avg {formatted_name.ljust(22)}: {(total_val / 100.0):.5f} ms")
                
                print(f"  -----------------------------------------")
                print(f"  Total Avg Sub Crypto    : {(total_crypto_sum / 100.0):.5f} ms")
                print(f"  Processing Throughput   : {throughput_mbps:.2f} Mbps")
                print(f"[*] =========================================")
                os._exit(0) 

    except ValueError as ve:
        # --- FAIL-SECURE PROTOCOL TRIGGERED ---
        error_msg = str(ve)
        print(f"\n[!!!] CRITICAL SECURITY ALERT | Packet Attempt #{total_attempts} [!!!]")
        
        if "Replay" in error_msg:
            print(f"    [TYPE] Anti-Replay Violation")
            print(f"    [INFO] Nonce already exists in Subscriber memory. Duplicate dropped.")
        elif "Tampering" in error_msg or "Signature" in error_msg or "authentication failed" in error_msg:
            print(f"    [TYPE] Integrity/Authentication Violation")
            print(f"    [INFO] Cryptographic Tag/Signature mismatch. Payload has been modified!")
        else:
            print(f"    [TYPE] Unknown Security Error")
            print(f"    [INFO] {error_msg}")
            
        print(f"    [STAT] Packets Validated Before Attack: {valid_packet_count}")
        print(f"\n[!] INITIATING FAIL-SECURE LOCKDOWN. HALTING RECEPTION.\n")
        
        # Stop listening and kill the subscriber immediately
        os._exit(1)
        
    except Exception as e: 
        # Catch non-crypto errors silently so the network loop doesn't break on garbage bytes
        pass 

def start_subscriber(crypto_provider):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext)"
    print(f"[*] Starting Layer 2 Subscriber...")
    print(f"[*] Security Algorithm: {algo_name}\n")
    
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(GOOSE_TYPE))
    sock.bind((IFACE, 0))
    
    while True:
        raw_packet = sock.recv(2048)
        process_goose_frame(raw_packet, crypto_provider)

def get_crypto_provider(algo_name):
    algo_name = algo_name.lower()
    if algo_name == "none": return None
    elif algo_name == "ed25519": return Ed25519Provider(role="subscriber")
    elif algo_name == "ecies": return ECIESProvider(role="subscriber")
    
    key_path = "keys/shared_key.bin"
    if not os.path.exists(key_path):
        print(f"Error: {key_path} missing. Run key generator first.")
        exit(1)
        
    with open(key_path, "rb") as f: master_shared_key = f.read()
    
    if algo_name == "chacha": return ChaCha20Provider(master_shared_key)
    elif algo_name == "ascon": return Ascon128aProvider(master_shared_key)
    elif algo_name == "aesgcm": return AESGCMProvider(master_shared_key)
    else: 
        print(f"Unknown algorithm: {algo_name}")
        exit(1)

if __name__ == "__main__":
    active_crypto_module = get_crypto_provider(args.algo)
    start_subscriber(active_crypto_module)