import os
import pandas as pd
from IPython.display import display
from configs.thresholds import NORMAL_LABELS

NORMAL_LABELS = {"NORMAL"}


def compute_thresholds(feature_dir, normal_labels=NORMAL_LABELS):
    dfs = []
    for fname in sorted(os.listdir(feature_dir)):
        if fname.endswith(".csv"):
            dfs.append(pd.read_csv(os.path.join(feature_dir, fname)))

    if not dfs:
        raise ValueError(f"No feature CSVs found in {feature_dir}")

    all_features = pd.concat(dfs, ignore_index=True)
    normal = all_features[all_features["attack_type"].isin(normal_labels)]

    if normal.empty:
        raise ValueError("No NORMAL windows found. Cannot compute thresholds.")

    # Upper-bound triggers: anomaly = value is HIGH
    upper_metrics = ["packet_rate", "syn_ack_ratio", "udp_rate", "unique_src_ips"]
    # Lower-bound triggers: anomaly = value is LOW (uniformity / focused targeting)
    lower_metrics = ["packet_size_variance", "dst_ip_entropy"]

    thresholds = {}
    stats_rows = []

    for col in upper_metrics:
        p50 = normal[col].quantile(0.50)
        p95 = normal[col].quantile(0.95)
        thresholds[col] = round(p95, 4)
        stats_rows.append({
            "metric":         col,
            "trigger":        "value > threshold",
            "normal_median":  round(p50, 4),
            "normal_p95":     round(p95, 4),
            "threshold_used": round(p95, 4),
        })

    for col in lower_metrics:
        p05 = normal[col].quantile(0.05)
        p50 = normal[col].quantile(0.50)
        thresholds[col] = round(p05, 4)
        stats_rows.append({
            "metric":         col,
            "trigger":        "value < threshold",
            "normal_median":  round(p50, 4),
            "normal_p95":     f"p05 = {round(p05, 4)}",
            "threshold_used": round(p05, 4),
        })

    stats_df = pd.DataFrame(stats_rows).set_index("metric")

    print("=" * 70)
    print("DATA-DRIVEN THRESHOLD JUSTIFICATION TABLE")
    print("=" * 70)
    display(stats_df)
    print(f"\nTotal NORMAL windows used for calibration : {len(normal)}")
    print(f"Total windows in dataset                  : {len(all_features)}")

    return thresholds, all_features


THRESHOLDS, all_features = compute_thresholds(feature_dir)

print("\nComputed thresholds:")
for k, v in THRESHOLDS.items():
    print(f"  {k:<25} = {v}")