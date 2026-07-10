import os
import pandas as pd
from src.decision_engine.scorer import heuristic_score

def run_decision_engine(feature_dir, thresholds=THRESHOLDS):
    all_decisions = []

    for fname in sorted(os.listdir(feature_dir)):
        if not fname.endswith(".csv"):
            continue

        df = pd.read_csv(os.path.join(feature_dir, fname))

        for _, row in df.iterrows():
            result = heuristic_score(row, thresholds)

            triggered_rules = [
                k for k, v in result["decision_trace"].items() if v["triggered"]
            ]

            all_decisions.append({
                "feature_id":           row["feature_id"],
                "file_id":              row["file_id"],
                "filename":             row["filename"],
                "dataset":              row["dataset"],
                "ground_truth":         row["attack_type"],
                "window_start":         row["window_start"],
                "packet_rate":          row["packet_rate"],
                "syn_ack_ratio":        row["syn_ack_ratio"],
                "udp_rate":             row["udp_rate"],
                "unique_src_ips":       row["unique_src_ips"],
                "packet_size_variance": row["packet_size_variance"],
                "dst_ip_entropy":       row["dst_ip_entropy"],
                "heuristic_score":      result["heuristic_score"],
                "normalized_score":     result["normalized_score"],
                "attack_probability":   result["attack_probability"],
                "classification":       result["classification"],
                "attack_type_detected": result["attack_type_detected"],
                "rules_triggered":      ", ".join(triggered_rules) if triggered_rules else "NONE",
                "decision_trace":       result["decision_trace"],
            })

    decisions = pd.DataFrame(all_decisions)

    print(f"Total windows evaluated : {len(decisions)}")
    print()
    print("Classification breakdown:")
    print(decisions["classification"].value_counts())
    print()
    print("Attack type breakdown:")
    print(decisions["attack_type_detected"].value_counts())
    print()

    display(
        decisions.drop(columns=["decision_trace"]).head(20)
    )

    return decisions


decisions = run_decision_engine(feature_dir)