import os
import pandas as pd
from src.decision_engine.scorer import heuristic_score

def compute_scores(feature_dir, thresholds):
    """
    Apply heuristic_score to all windows and return a DataFrame.
    """
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
                "attack_type":          row["attack_type"],
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
                "attack_type_detected": result["attack_type_detected"],
                "rules_triggered":      ", ".join(triggered_rules) if triggered_rules else "NONE",
                "decision_trace":       result["decision_trace"],
            })

    scores_df = pd.DataFrame(all_decisions)
    return scores_df

def classify(scores_df, band_suspicious, band_attack):
    """
    Apply final classification based on dynamic thresholds.
    """
    def _classify(score):
        if score >= band_attack:
            return "ATTACK"
        elif score >= band_suspicious:
            return "SUSPICIOUS"
        else:
            return "NORMAL"
            
    scores_df["classification"] = scores_df["heuristic_score"].apply(_classify)
    
    print(f"\nTotal windows evaluated : {len(scores_df)}")
    print()
    print("Classification breakdown:")
    print(scores_df["classification"].value_counts())
    print()
    print("Attack type breakdown:")
    print(scores_df["attack_type_detected"].value_counts())
    print()

    print(
        scores_df.drop(columns=["decision_trace"]).head(20)
    )

    return scores_df
