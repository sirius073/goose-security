#!/usr/bin/env python3
import json
import time
import os
import argparse
import socket
import csv

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

# Global tracking
valid_packet_count = 0
total_sub_crypto_time = 0.0
total_network_transit_time = 0.0
csv_file = open("subscriber_metrics.csv", "w", newline='')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["SqNum", "Trip_Command", "Net_Transit_ms", "Sub_Total_Crypto_ms"])

def process_goose_frame(payload_bytes, crypto_provider):
    global valid_packet_count, total_sub_crypto_time, total_network_transit_time
    
    # Catch the exact microsecond the frame leaves the wire
    wire_recv_timestamp = time.time()
    
    if not payload_bytes: return
    raw_payload = payload_bytes.decode('utf-8', errors='ignore')
    
    try:
        payload = json.loads(raw_payload)
        send_timestamp = payload.get("wire_send_timestamp", wire_recv_timestamp)
        t_net = (wire_recv_timestamp - send_timestamp) * 1000
        t_net = max(0.0001, t_net) # Prevent 0.0ms anomalies
        
        # 1. Cryptographic Verification
        if crypto_provider is None or payload.get("algo") == "None (Plaintext)":
            raw_msg = bytes.fromhex(payload["data"])
            sub_crypto_ms = 0.0
        else:
            raw_msg, sub_metrics = crypto_provider.verify(payload)
            sub_crypto_ms = sub_metrics["sub_total_crypto_ms"]

        goose_data = json.loads(raw_msg.decode('utf-8'))
        sq_num = goose_data['APDU']['SqNum']
        trip_cmd = goose_data['APDU']['Trip_Command']
        
        if sq_num > 1: # Ignore warmup packet
            valid_packet_count += 1
            total_sub_crypto_time += sub_crypto_ms
            total_network_transit_time += t_net
            csv_writer.writerow([sq_num, trip_cmd, t_net, sub_crypto_ms])
            
            if valid_packet_count == 100:
                avg_sub = total_sub_crypto_time / 100.0
                avg_net = total_network_transit_time / 100.0
                print(f"[*] Received 100 valid messages. Test complete.")
                print(f"  =========================================")
                print(f"  Avg Network Transit Time : {avg_net:.5f} ms")
                print(f"  Avg Decryption Time      : {avg_sub:.5f} ms")
                print(f"  =========================================\n")
                print(f"  NOTE: To get TRUE End-to-End Latency, add the Publisher's")
                print(f"  Avg Crypto Time to the two metrics above!")
                os._exit(0) # Force clean exit

    except ValueError as ve:
        print(f"[*] SECURITY ALERT: {str(ve)}\n")
    except Exception:
        pass 

def start_subscriber(crypto_provider):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext)"
    print(f"[*] Starting Layer 2 Subscriber...")
    print(f"[*] Security Algorithm: {algo_name}\n")
    
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(GOOSE_TYPE))
    sock.bind((IFACE, 0))
    
    while True:
        raw_packet = sock.recv(2048)
        process_goose_frame(raw_packet[14:], crypto_provider)

def get_crypto_provider(algo_name):
    algo_name = algo_name.lower()
    if algo_name == "none": return None
    elif algo_name == "ed25519": return Ed25519Provider(role="subscriber")
    elif algo_name == "ecies": return ECIESProvider(role="subscriber")
    
    with open("keys/shared_key.bin", "rb") as f:
        master_shared_key = f.read()
        
    if algo_name == "chacha": return ChaCha20Provider(master_shared_key)
    elif algo_name == "ascon": return Ascon128aProvider(master_shared_key)
    elif algo_name == "aesgcm": return AESGCMProvider(master_shared_key)
    else: exit(1)

if __name__ == "__main__":
    active_crypto_module = get_crypto_provider(args.algo)
    start_subscriber(active_crypto_module)
