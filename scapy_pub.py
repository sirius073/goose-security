#!/usr/bin/env python3
import json
import time
import os
import argparse
from scapy.all import Ether, Raw, sendp

# ---------------------------------------------------------------------------
# IMPORT CRYPTO ALGORITHM FROM YOUR FOLDER
from crypto_algos.chacha20_provider import ChaCha20Provider
from crypto_algos.ascon128a_provider import Ascon128aProvider
from crypto_algos.ed25519_provider import Ed25519Provider
from crypto_algos.ecies_provider import ECIESProvider
# ---------------------------------------------------------------------------

# --- Terminal Arguments ---
parser = argparse.ArgumentParser(description="Layer 2 GOOSE Publisher")
parser.add_argument("--algo", type=str, default="none", help="Which crypto algo to use (none, ecies, ascon, ed25519, chacha)")
args = parser.parse_args()

# --- Layer 2 Constants ---
GOOSE_MAC = "01:0C:CD:01:00:01"
GOOSE_TYPE = 0x88B8
IFACE = "h1-eth0"  # Mininet Publisher Interface

def create_goose_payload(st_num: int, sq_num: int, trip_command: bool) -> dict:
    """Constructs the exact GOOSE message format as defined in the paper."""
    return {
        "Associated_Data": {
            "MAC_Src": "00:1A:2B:3C:4D:5E",
            "MAC_Dst": GOOSE_MAC,
            "VLAN": 1,
            "APPID": "0000"
        },
        "APDU": {
            "gocbRef": "Substation1/LLN0$GO$gcb1",
            "datSet": "Substation1/LLN0$dataset1",
            "goID": "Sub1_GOOSE",
            "StNum": st_num,
            "SqNum": sq_num,
            "Trip_Command": trip_command,
            "simulation": False,
            "confRev": 1
        }
    }

def start_publisher(crypto_provider):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext - No Security)"
    print(f"[*] Starting Layer 2 Publisher IED...")
    print(f"[*] Security Algorithm: {algo_name}\n")
    print("[*] Commencing 101-Message Test Sequence over Layer 2 (1 Warmup + 100 Valid)...\n")
    
    # 101 Message Sequence: 1 Warmup, 90 Normal, 10 Trip
    for sq_num in range(1, 102):
        trip_status = True if sq_num >= 92 else False
        st_num = 2 if trip_status else 1
        
        # 1. Message Construction
        raw_goose_msg = json.dumps(create_goose_payload(st_num, sq_num, trip_status)).encode('utf-8')
        
        # 2. Cryptographic Protection OR Plaintext
        if crypto_provider is None:
            secure_payload = {
                "algo": "None (Plaintext)",
                "data": raw_goose_msg.hex(),
                "metrics": {}
            }
        else:
            secure_payload = crypto_provider.protect(raw_goose_msg)
        
        # 3. Add timestamp for end-to-end latency (right before injecting to wire)
        secure_payload["send_timestamp"] = time.time()
        
        # 4. Layer 2 Network Transmission via Scapy
        frame_data = json.dumps(secure_payload).encode('utf-8')
        goose_frame = Ether(dst=GOOSE_MAC, type=GOOSE_TYPE) / Raw(load=frame_data)
        
        sendp(goose_frame, iface=IFACE, verbose=False)
        
        # 5. Dynamic Print Logic
        if sq_num == 1:
            print(f"[*] Message 1 Sent (Warm-up / Cache Building) - Processed silently.")
        elif sq_num % 25 == 0:
            print(f"[*] Progress: Sent {sq_num} messages...")
        
        # 6. Real-World Calibration (sped up for 100-packet tests)
        if trip_status:
            time.sleep(0.01) # Rapid retransmission burst during a trip event
        else:
            time.sleep(0.05) # Normal baseline heartbeat delay (reduced from 0.33)

    print("\n[*] Test Sequence Complete. Publisher Shutting Down.")


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
        return Ed25519Provider(role="publisher")
    elif algo_name == "ecies":
        return ECIESProvider(role="publisher")
    else:
        print(f"Error: Unknown algorithm '{algo_name}'. Choices: none, chacha, ascon, ed25519, ecies.")
        exit(1)

if __name__ == "__main__":
    active_crypto_module = get_crypto_provider(args.algo)
    start_publisher(active_crypto_module)
