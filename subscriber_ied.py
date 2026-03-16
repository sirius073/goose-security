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
parser = argparse.ArgumentParser(description="GOOSE Subscriber")
parser.add_argument("--algo", type=str, default="none", help="Which crypto algo to use (none, ecies, ascon, ed25519, chacha)")
parser.add_argument("--hacker", type=str, choices=['true', 'false'], default='false', help="Set to true to connect to adversary proxy")
args = parser.parse_args()

HOST = '127.0.0.1'
PORT = 65433 if args.hacker.lower() == 'true' else 65432

def start_subscriber(crypto_provider):
    algo_name = crypto_provider.get_algo_name() if crypto_provider else "NONE (Plaintext - No Security)"
    print(f"[*] Starting Subscriber IED...")
    print(f"[*] Connecting to Port: {PORT} (Hacker Proxy: {args.hacker.upper()})")
    print(f"[*] Security Algorithm: {algo_name}\n")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        print(f"[*] Connecting to Publisher at {HOST}:{PORT}...")
        
        while True:
            try:
                client_socket.connect((HOST, PORT))
                break
            except ConnectionRefusedError:
                time.sleep(1)
                
        print("[+] Connected successfully!\n")
        
        buffer = ""
        while True:
            data = client_socket.recv(4096)
            if not data:
                print("[-] Connection closed by Publisher.")
                break
                
            buffer += data.decode('utf-8')
            
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                payload = json.loads(line)
                
                try:
                    # ==========================================
                    # NO CRYPTO LOGIC (PLAINTEXT)
                    # ==========================================
                    if crypto_provider is None or payload.get("algo") == "None (Plaintext)":
                        raw_msg = bytes.fromhex(payload["data"])
                        
                        # Calculate True End-to-End Latency (Only Network + Parsing)
                        end_to_end_finish = time.time()
                        send_timestamp = payload.get("send_timestamp", end_to_end_finish)
                        total_transfer_time_ms = (end_to_end_finish - send_timestamp) * 1000
                        
                        # Parse GOOSE data
                        goose_data = json.loads(raw_msg.decode('utf-8'))
                        apdu = goose_data['APDU']
                        sq_num = apdu['SqNum']
                        trip_status = "TRIP!" if apdu.get('Trip_Command') else "Normal"
                        
                        if sq_num == 1:
                            print(f"[*] Message 1 Received (Warm-up) - Processed silently.")
                        else:
                            print(f"--- Valid PLAINTEXT Message Received | Status: {trip_status} | SqNum: {sq_num} ---")
                            print(f"  [!] WARNING: Data was not verified or decrypted.")
                            print(f"  =========================================")
                            print(f"  TOTAL END-TO-END (Network Only): {total_transfer_time_ms:.5f} ms\n")

                    # ==========================================
                    # SECURE CRYPTO LOGIC
                    # ==========================================
                    else:
                        # 1. Cryptographic Verification & Decryption 
                        raw_msg, sub_metrics = crypto_provider.verify(payload)
                        
                        # 2. Calculate True End-to-End Latency
                        end_to_end_finish = time.time()
                        send_timestamp = payload.get("send_timestamp", end_to_end_finish)
                        total_transfer_time_ms = (end_to_end_finish - send_timestamp) * 1000
                        
                        # 3. Parse GOOSE data
                        goose_data = json.loads(raw_msg.decode('utf-8'))
                        apdu = goose_data['APDU']
                        sq_num = apdu['SqNum']
                        trip_status = "TRIP!" if apdu.get('Trip_Command') else "Normal"
                        
                        # 4. Extract Publisher Metrics & Calculate Network Time
                        pub_metrics = payload.get("metrics", {})
                        pub_total = pub_metrics.get("pub_total_crypto_ms", 0)
                        sub_total = sub_metrics.get("sub_total_crypto_ms", 0)
                        
                        # Network time = End-to-End MINUS Pub processing MINUS Sub processing
                        t_net = total_transfer_time_ms - pub_total - sub_total
                        t_net = max(0.00001, t_net) # Prevent math artifacts from going negative
                        
                        # 5. Dynamic Output Display
                        if sq_num == 1:
                            print(f"[*] Message 1 Received (Warm-up) - Processed silently.")
                        else:
                            print(f"--- Valid SECURE Message Received | Status: {trip_status} | SqNum: {sq_num} ---")
                            
                            print(f"  [PUBLISHER METRICS]")
                            for key, value in pub_metrics.items():
                                if key != 'pub_total_crypto_ms':
                                    pretty_name = key.replace('pub_', '').replace('_ms', '').replace('_', ' ').title()
                                    print(f"    {pretty_name}: {value:.5f} ms")
                            print(f"    Total Pub Crypto:   {pub_total:.5f} ms")
                            
                            print(f"  [NETWORK TRANSIT]")
                            print(f"    OS/Socket Transfer: {t_net:.5f} ms")
                            
                            print(f"  [SUBSCRIBER METRICS]")
                            for key, value in sub_metrics.items():
                                if key != 'sub_total_crypto_ms':
                                    pretty_name = key.replace('sub_', '').replace('_ms', '').replace('_', ' ').title()
                                    print(f"    {pretty_name}: {value:.5f} ms")
                            print(f"    Total Sub Crypto:   {sub_total:.5f} ms")
                            
                            print(f"  =========================================")
                            print(f"  TOTAL END-TO-END:     {total_transfer_time_ms:.5f} ms\n")

                    # Exit cleanly after 7 messages
                    if sq_num == 7:
                        print("[*] Received final TRIP message. Test complete.")
                        return 

                except ValueError as ve:
                    print(f"[*] SECURITY ALERT: {str(ve)}\n")
                except Exception as e:
                    print(f"[*] CRITICAL ERROR processing message: {str(e)}\n")

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
        # Ed25519 knows how to load its own keys via the role 'subscriber'
        return Ed25519Provider(role="subscriber")
        
    elif algo_name == "ecies":
        # ECIES knows how to load its own keys via the role 'subscriber'
        return ECIESProvider(role="subscriber")
        
    else:
        print(f"Error: Unknown algorithm '{algo_name}'. Choices: none, chacha, ascon, ed25519, ecies.")
        exit(1)

if __name__ == "__main__":
    # Dynamically load the provider based on the terminal argument
    active_crypto_module = get_crypto_provider(args.algo)
    
    # Start the subscriber with the chosen module
    start_subscriber(active_crypto_module)