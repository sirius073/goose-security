#!/usr/bin/env python3
import struct
from scapy.all import wrpcap, Ether

def convert_bin_to_pcap(bin_file, pcap_file):
    packets = []
    print(f"[*] Reading custom binary: {bin_file}")
    
    with open(bin_file, "rb") as f:
        while True:
            meta_bytes = f.read(8)
            if len(meta_bytes) < 8:
                break
                
            wait_for, pkt_len = struct.unpack("!fI", meta_bytes)
            raw_packet = f.read(pkt_len)
            
            if len(raw_packet) != pkt_len:
                break
                
            # Treat the raw bytes as an Ethernet frame and add to our list
            packets.append(Ether(raw_packet))
            
    print(f"[*] Extracted {len(packets)} packets.")
    wrpcap(pcap_file, packets)
    print(f"[*] Successfully saved to: {pcap_file}")

if __name__ == "__main__":
    convert_bin_to_pcap("goose_armory.bin", "goose_inspect.pcap")
