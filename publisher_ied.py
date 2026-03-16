import socket
import json
import time
import os
import argparse

# ---------------------------------------------------------------------------
# IMPORT CRYPTO ALGORITHM FROM YOUR FOLDER
from crypto_algos.chacha20_provider import ChaCha20Provider
from crypto_algos.ascon128a_provider import Ascon128aProvider
from crypto_algos.ed25519_provider import Ed25519Provider
from crypto_algos.ecies_provider import ECIESProvider
# ---------------------------------------------------------------------------

# --- Terminal Arguments ---
parser = argparse.ArgumentParser(description="GOOSE Publisher")
parser.add_argument("--algo", type=str, default="none", help="Which crypto algo to use (none, ecies, ascon, ed25519, chacha)")
args = parser.parse_args()

HOST = '127.0.0.1'
PORT = 65432

def create_goose_payload(st_num: int, sq_num: int, trip_command: bool) -> dict:
    """
    Constructs the exact GOOSE message format as defined in the paper:
    Section IV-D: GOOSE Message Structure (Associated Data + APDU).
    """
    return {
        "Associated_Data": {
            "MAC_Src": "00:1A:2B:3C:4D:5E",
            "MAC_Dst": "01:0C:CD:01:00:01",
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
    print(f"[*] Starting Publisher IED...")
    print(f"[*] Security Algorithm: {algo_name}\n")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[*] Publisher listening for Subscriber on {HOST}:{PORT}...")
        
        conn, addr = server_socket.accept()
        with conn:
            print(f"[+] Subscriber connected from {addr}\n")
            print("[*] Commencing 7-Message Test Sequence...\n")
            
            # 7 Message Sequence: 1 Warmup, 4 Normal, 2 Trip
            for sq_num in range(1, 8):
                trip_status = True if sq_num >= 6 else False
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
                
                # 3. Add timestamp for end-to-end latency
                secure_payload["send_timestamp"] = time.time()
                
                # 4. Network Transmission
                conn.sendall(json.dumps(secure_payload).encode('utf-8') + b'\n')
                
                # 5. Dynamic Print Logic
                if sq_num == 1:
                    print(f"[*] Message 1 Sent (Warm-up / Cache Building) - Processed silently.")
                else:
                    status_text = "TRIP!" if trip_status else "NORMAL"
                    
                    if crypto_provider is None:
                        print(f"--- Sent PLAINTEXT Message {sq_num} | Status: {status_text} ---")
                        print(f"  [!] WARNING: Data sent without encryption or signature.\n")
                    else:
                        print(f"--- Sent SECURE Message {sq_num} | Status: {status_text} ---")
                        metrics = secure_payload.get('metrics', {})
                        for key, value in metrics.items():
                            if key != 'pub_total_crypto_ms':
                                pretty_name = key.replace('pub_', '').replace('_ms', '').replace('_', ' ').title()
                                print(f"  {pretty_name}: {value:.5f} ms")
                                
                        print(f"  Total Pub Crypto: {metrics.get('pub_total_crypto_ms', 0):.5f} ms\n")
                
                # 6. Real-World Calibration (from the paper)
                if trip_status:
                    time.sleep(0.01) # Rapid retransmission burst during a trip event
                else:
                    time.sleep(0.33) # Normal baseline heartbeat delay (0.33 seconds)

            print("[*] Test Sequence Complete. Publisher Shutting Down.")


# ==========================================
# DYNAMIC ALGORITHM SELECTION 
# ==========================================
def get_crypto_provider(algo_name):
    """Acts like a switch/case to load the requested algorithm."""
    algo_name = algo_name.lower()
    
    if algo_name == "none":
        return None
        
    elif algo_name in ["chacha", "ascon"]:
        # These algorithms require the shared symmetric key
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
        # Ed25519 loads its keys via the role 'publisher'
        return Ed25519Provider(role="publisher")
        
    elif algo_name == "ecies":
        # ECIES loads its keys via the role 'publisher'
        return ECIESProvider(role="publisher")
        
    else:
        print(f"Error: Unknown algorithm '{algo_name}'. Choices: none, chacha, ascon, ed25519, ecies.")
        exit(1)

if __name__ == "__main__":
    # Dynamically load the provider based on the terminal argument
    active_crypto_module = get_crypto_provider(args.algo)
    
    # Start the publisher with the chosen module
    start_publisher(active_crypto_module)