import os
import json
import random
from scapy.all import IP, TCP, wrpcap

RAW_DIR = "datasets/raw/synthetic"
os.makedirs(RAW_DIR, exist_ok=True)

PCAP_FILE = os.path.join(RAW_DIR, "synthetic_syn_flood.pcap")
META_FILE = os.path.join(RAW_DIR, "synthetic_syn_flood.json")

print(f"Generating {PCAP_FILE}...")
packets = []
target_ip = "192.168.1.100"
target_port = 80

# Generate 50,000 SYN packets in a 2 second window
base_time = 1600000000.0
for i in range(50000):
    src_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    src_port = random.randint(1024, 65535)
    
    pkt = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
    pkt.time = base_time + (i * (2.0 / 50000.0))
    packets.append(pkt)

wrpcap(PCAP_FILE, packets)
print(f"Generated {len(packets)} packets.")

# Write metadata
meta = {
    "dataset": "SYNTHETIC",
    "attack_type": "SYN_FLOOD",
    "description": "High-volume synthetic SYN flood"
}
with open(META_FILE, "w") as f:
    json.dump(meta, f, indent=4)

print("Metadata saved.")
