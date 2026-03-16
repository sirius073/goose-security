#!/usr/bin/env python3
import json
import time
import os
import argparse
import socket
import struct
import csv

# ---------------------------------------------------------------------------
from crypto_algos.chacha20_provider import ChaCha20Provider
from crypto_algos.ascon128a_provider import Ascon128aProvider
from crypto_algos.ed25519_provider import Ed25519Provider
from crypto_algos.ecies_provider import ECIESProvider
from crypto_algos.aes_gcm_provider import AESGCMProvider # Renamed to use underscore
# ---------------------------------------------------------------------------

parser = argparse.ArgumentParser(description="Layer 2 GOOSE Publisher")
parser.add_argument("--algo", type=str, default="none", help="Choices: none, ecies, ascon, ed25519, chacha, aesgcm")
args = parser.parse_args()

GOOSE_MAC_HEX = "010ccd010001"
SRC_MAC_HEX = "001a2b3c4d5e"
GOOSE_TYPE = 0x88B8
IFACE = "h1-eth0" 

def create_goose_payload(st_num: int, sq_num: int, trip_command: bool) -> dict:
    return {
        "Associated_Data": {"MAC_Src": "00:1A:2B:3C:4D:5E", "MAC_Dst": "01:0C:CD:01:00:01", "VLAN": 1, "APPID": "0000"},
        "APDU": {"gocbRef": "Substation1/LLN0$GO$gcb1", "datSet": "Substation1/LLN0$dataset1", "goID": "Sub1_GOOSE", 
                 "StNum": st_num, "SqNum": sq_num, "Trip_Command": trip_command, "simulation": False, "confRev": 1}
    }

def start_publisher(crypto_provider):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext)"
    print(f"[*] Starting Layer 2 Publisher...")
    print(f"[*] Security Algorithm: {algo_name}\n")
    
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(GOOSE_TYPE))
    sock.bind((IFACE, 0))
    
    dst_mac_bytes = bytes.fromhex(GOOSE_MAC_HEX)
    src_mac_bytes = bytes.fromhex(SRC_MAC_HEX)
    eth_header = struct.pack("!6s6sH", dst_mac_bytes, src_mac_bytes, GOOSE_TYPE)
    
    # Open CSV for local metric logging
    csv_file = open("publisher_metrics.csv", "w", newline='')
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["SqNum", "Trip_Command", "Pub_Total_Crypto_ms"])
    total_crypto_time = 0.0

    for sq_num in range(1, 102):
        trip_status = True if sq_num >= 92 else False
        st_num = 2 if trip_status else 1
        raw_goose_msg = json.dumps(create_goose_payload(st_num, sq_num, trip_status)).encode('utf-8')
        
        # 1. Cryptographic Protection (Metrics stay local)
        if crypto_provider is None:
            network_payload = {"algo": "None (Plaintext)", "data": raw_goose_msg.hex()}
            pub_crypto_ms = 0.0
        else:
            network_payload, pub_metrics = crypto_provider.protect(raw_goose_msg)
            pub_crypto_ms = pub_metrics["pub_total_crypto_ms"]
        
        # 2. Add Wire Timestamp for Network Transit calculation
        #network_payload["wire_send_timestamp"] = time.time()
        
        # 3. Send the LEAN payload
        frame_data = json.dumps(network_payload).encode('utf-8')
        sock.send(eth_header + frame_data)
        
        # 4. Log metrics locally
        if sq_num > 1: # Ignore warmup packet for averages
            csv_writer.writerow([sq_num, trip_status, pub_crypto_ms])
            total_crypto_time += pub_crypto_ms
            if sq_num % 25 == 0:
                print(f"[*] Progress: Sent {sq_num} messages...")
        
        time.sleep(0.01 if trip_status else 0.05)

    print(f"\n[*] Test Complete. Publisher Avg Crypto Time: {(total_crypto_time/100):.5f} ms")
    sock.close()
    csv_file.close()

def get_crypto_provider(algo_name):
    algo_name = algo_name.lower()
    if algo_name == "none": return None
    elif algo_name == "ed25519": return Ed25519Provider(role="publisher")
    elif algo_name == "ecies": return ECIESProvider(role="publisher")
    
    # Shared Key Algorithms
    key_path = "keys/shared_key.bin"
    if not os.path.exists(key_path):
        print(f"Error: {key_path} missing.")
        exit(1)
    with open(key_path, "rb") as f:
        master_shared_key = f.read()
        
    if algo_name == "chacha": return ChaCha20Provider(master_shared_key)
    elif algo_name == "ascon": return Ascon128aProvider(master_shared_key)
    elif algo_name == "aesgcm": return AESGCMProvider(master_shared_key)
    else:
        print(f"Error: Unknown algorithm '{algo_name}'.")
        exit(1)

if __name__ == "__main__":
    active_crypto_module = get_crypto_provider(args.algo)
    start_publisher(active_crypto_module)
