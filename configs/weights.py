# Heuristic scoring weights
WEIGHTS = {
    "packet_rate":          25,
    "syn_ack_ratio":        20,
    "udp_rate":             15,
    "packet_size_variance": 10,
    "unique_src_ips":       15,
    "dst_ip_entropy":       15,
}

# Ensure weights always sum to exactly 100 at import time
assert sum(WEIGHTS.values()) == 100, "Weights must sum to 100"
