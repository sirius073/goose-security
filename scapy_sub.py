#!/usr/bin/env python3
import json
import time
import os
import argparse
from scapy.all import sniff, Ether, Raw

# ---------------------------------------------------------------------------
# IMPORT CRYPTO ALGORITHM FROM YOUR FOLDER
from crypto_algos.chacha20_provider import ChaCha20Provider
from crypto_algos.ascon128a_provider import Ascon128aProvider
from crypto_algos.ed25519_provider import Ed25519Provider
from crypto_algos.ecies_provider import ECIESProvider
# ---------------------------------------------------------------------------

# --- Terminal Arguments ---
parser = argparse.ArgumentParser(description="Layer 2 GOOSE Subscriber")
parser.add_argument("--algo", type=str, default="none", help="Which crypto algo to use (none, ecies, ascon, ed25519, chacha)")
args = parser.parse_args()

# --- Layer 2 Constants ---
GOOSE_TYPE = 0x88B8
IFACE = "h2-eth0" # Mininet Subscriber Interface

# Global flags to stop the sniffer cleanly and track averages
test_complete = False
valid_packet_count = 0
total_pub_crypto_time = 0.0
total_sub_crypto_time = 0.0
total_network_transit_time = 0.0
total_e2e_time = 0.0

def process_goose_frame(packet, crypto_provider):
    global test_complete, valid_packet_count
    global total_pub_crypto_time, total_sub_crypto_time, total_network_transit_time, total_e2e_time
    
    # Catch the exact microsecond the frame leaves the wire
    end_to_end_finish = time.time()
    
    if not packet.haslayer(Raw):
        return
        
    raw_payload = packet[Raw].load.decode('utf-8', errors='ignore')
    
    try:
        payload = json.loads(raw_payload)
        
        # ==========================================
        # NO CRYPTO LOGIC (PLAINTEXT)
        # ==========================================
        if crypto_provider is None or payload.get("algo") == "None (Plaintext)":
            raw_msg = bytes.fromhex(payload["data"])
            
            send_timestamp = payload.get("send_timestamp", end_to_end_finish)
            total_transfer_time_ms = (end_to_end_finish - send_timestamp) * 1000
            
            goose_data = json.loads(raw_msg.decode('utf-8'))
            apdu = goose_data['APDU']
            sq_num = apdu['SqNum']
            
            if sq_num == 1:
                print(f"[*] Message 1 Received (Warm-up) - Processed silently.")
            else:
                valid_packet_count += 1
                total_e2e_time += total_transfer_time_ms
                
            if valid_packet_count == 100:
                avg_e2e = total_e2e_time / 100.0
                print(f"[*] Received 100 valid PLAINTEXT messages. Test complete.")
                print(f"  =========================================")
                print(f"  Total Average Network/E2E Time : {avg_e2e:.5f} ms")
                print(f"  =========================================\n")
                test_complete = True

        # ==========================================
        # SECURE CRYPTO LOGIC
        # ==========================================
        else:
            # 1. Cryptographic Verification & Decryption 
            raw_msg, sub_metrics = crypto_provider.verify(payload)
            
            # 2. Calculate True End-to-End Latency
            send_timestamp = payload.get("send_timestamp", end_to_end_finish)
            total_transfer_time_ms = (end_to_end_finish - send_timestamp) * 1000
            
            # 3. Parse GOOSE data
            goose_data = json.loads(raw_msg.decode('utf-8'))
            apdu = goose_data['APDU']
            sq_num = apdu['SqNum']
            
            # 4. Extract Publisher Metrics & Calculate Network Time
            pub_metrics = payload.get("metrics", {})
            pub_total = pub_metrics.get("pub_total_crypto_ms", 0)
            sub_total = sub_metrics.get("sub_total_crypto_ms", 0)
            
            # Network time = End-to-End MINUS Pub processing MINUS Sub processing
            t_net = total_transfer_time_ms - pub_total - sub_total
            t_net = max(0.00001, t_net) # Prevent math artifacts
            
            # 5. Track Averages and Exit Logic
            if sq_num == 1:
                print(f"[*] Message 1 Received (Warm-up) - Processed silently.")
            else:
                valid_packet_count += 1
                total_pub_crypto_time += pub_total
                total_sub_crypto_time += sub_total
                total_network_transit_time += t_net
                total_e2e_time += total_transfer_time_ms
                
            if valid_packet_count == 100:
                avg_pub = total_pub_crypto_time / 100.0
                avg_sub = total_sub_crypto_time / 100.0
                avg_combined = (total_pub_crypto_time + total_sub_crypto_time) / 100.0
                avg_net = total_network_transit_time / 100.0
                avg_e2e = total_e2e_time / 100.0
                
                print(f"[*] Received 100 valid SECURE messages. Test complete.")
                print(f"  =========================================")
                print(f"  Total Average Encryption Time : {avg_pub:.5f} ms")
                print(f"  Total Average Decryption Time : {avg_sub:.5f} ms")
                print(f"  Total Average Combined Crypto : {avg_combined:.5f} ms")
                print(f"  -----------------------------------------")
                print(f"  Total Average Network Transit : {avg_net:.5f} ms")
                print(f"  Total Average End-to-End Time : {avg_e2e:.5f} ms")
                print(f"  =========================================\n")
                
                test_complete = True

    except ValueError as ve:
        print(f"[*] SECURITY ALERT: {str(ve)}\n")
    except Exception as e:
        print(f"[*] CRITICAL ERROR processing message: {str(e)}\n")

def check_stop_filter(packet):
    """Tells Scapy to stop sniffing when we hit message 100"""
    return test_complete

def start_subscriber(crypto_provider):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext - No Security)"
    print(f"[*] Starting Layer 2 Subscriber IED...")
    print(f"[*] Security Algorithm: {algo_name}\n")
    print(f"[*] Sniffing for EtherType {hex(GOOSE_TYPE)} on {IFACE}...")
    
    # We pass the crypto_provider into the sniffer callback using a lambda
    sniff(
        iface=IFACE, 
        filter="ether proto 0x88b8", 
        prn=lambda pkt: process_goose_frame(pkt, crypto_provider), 
        stop_filter=check_stop_filter,
        store=0
    )
    print("[*] Subscriber Shutting Down.")

# ==========================================
# DYNAMIC ALGORITHM SELECTION 
# ==========================================
def get_crypto_provider(algo_name):
    """Acts like a switch/case to load the requested algorithm."""
    algo_name = algo_name.lower()
    if algo_name == "none":
        return None
    elif algo_name in ["chacha", "ascon"]:
        key_path = "keys/shared_key.bin"
        if not os.path.exists(key_path):
            print(f"Error: {key_path} not found. Run generate scripts first.")
            exit(1)
        with open(key_path, "rb") as f:
            master_shared_key = f.read()
        if algo_name == "chacha":
            return ChaCha20Provider(master_shared_key)
        elif algo_name == "ascon":
            return Ascon128aProvider(master_shared_key)
    elif algo_name == "ed25519":
        return Ed25519Provider(role="subscriber")
    elif algo_name == "ecies":
        return ECIESProvider(role="subscriber")
    else:
        print(f"Error: Unknown algorithm '{algo_name}'. Choices: none, chacha, ascon, ed25519, ecies.")
        exit(1)

if __name__ == "__main__":
    active_crypto_module = get_crypto_provider(args.algo)
    start_subscriber(active_crypto_module)
