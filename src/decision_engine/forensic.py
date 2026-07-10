import json as _json

import json as _json


def _get_mitigation(score):
    if score >= 100:
        return "LEVEL_5_PERMANENT_BLACKLIST"
    elif score >= 85:
        return "LEVEL_4_TEMPORARY_FIREWALL_BLOCK"
    elif score >= 70:
        return "LEVEL_3_RATE_LIMITING"
    elif score >= 40:
        return "LEVEL_2_LOG_AND_ALERT"
    else:
        return "LEVEL_1_MONITOR"


def emit_forensic_log(row):
    if row["classification"] != "ATTACK":
        return None

    return {
        "incident_metadata": {
            "window_start":          row["window_start"],
            "attack_classification": row["attack_type_detected"],
            "heuristic_score":       row["heuristic_score"],     # /100
            "normalized_score":      row["normalized_score"],    # 0.0–1.0
            "attack_probability":    row["attack_probability"],  # sigmoid output
        },
        "network_signature": {
            "file_id":  row["file_id"],
            "filename": row["filename"],
            "dataset":  row["dataset"],
            "aggregated_flow_metrics": {
                "packet_rate":          row["packet_rate"],
                "syn_ack_ratio":        row["syn_ack_ratio"],
                "unique_src_ips":       row["unique_src_ips"],
                "packet_size_variance": row["packet_size_variance"],
                "dst_ip_entropy":       row["dst_ip_entropy"],
            },
        },
        # Full per-rule trace: exactly why this window was flagged
        "decision_trace":       row["decision_trace"],
        "mitigation_directive": _get_mitigation(row["heuristic_score"]),
    }


attack_windows = decisions[decisions["classification"] == "ATTACK"]
logs = [
    emit_forensic_log(row)
    for _, row in attack_windows.iterrows()
]
logs = [l for l in logs if l is not None]

print(f"Total ATTACK windows     : {len(attack_windows)}")
print(f"Forensic logs generated  : {len(logs)}")

if logs:
    print("\nSample forensic log:")
    print(_json.dumps(logs[0], indent=2))
else:
    print("\nNo ATTACK windows in this dataset — engine is calibrated correctly")
    print("for normal/malware baseline. Add DDoS traffic (Bot-IoT / CIC-DDoS2019)")
    print("to observe attack detections.")