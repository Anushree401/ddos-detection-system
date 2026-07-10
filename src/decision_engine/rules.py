import os
import json
import pandas as pd
from configs.thresholds import NORMAL_LABELS

NORMAL_LABELS = {"NORMAL"}
METADATA_DIR = "datasets/metadata"
THRESHOLDS_FILE = os.path.join(METADATA_DIR, "thresholds.json")

def compute_thresholds(feature_dir, force_recalibrate=False):
    if not force_recalibrate and os.path.exists(THRESHOLDS_FILE):
        print(f"Loading cached feature thresholds from {THRESHOLDS_FILE}")
        with open(THRESHOLDS_FILE, "r") as f:
            thresholds = json.load(f)
        
        # We only return the feature thresholds here
        # Score bands might not be in this dict if this is an older file, 
        # but compute_score_bands will handle that.
        dfs = []
        for fname in sorted(os.listdir(feature_dir)):
            if fname.endswith(".csv"):
                dfs.append(pd.read_csv(os.path.join(feature_dir, fname)))
        all_features = pd.concat(dfs, ignore_index=True)
        return thresholds, all_features

    dfs = []
    for fname in sorted(os.listdir(feature_dir)):
        if fname.endswith(".csv"):
            dfs.append(pd.read_csv(os.path.join(feature_dir, fname)))

    if not dfs:
        raise ValueError(f"No feature CSVs found in {feature_dir}")

    all_features = pd.concat(dfs, ignore_index=True)
    normal = all_features[all_features["attack_type"].isin(NORMAL_LABELS)]

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
        p99 = normal[col].quantile(0.99)
        clipped_normal = normal[normal[col] <= p99]
        p95 = clipped_normal[col].quantile(0.95)
        
        thresholds[col] = float(round(p95, 4))
        stats_rows.append({
            "metric":         col,
            "trigger":        "value > threshold",
            "normal_median":  round(p50, 4),
            "normal_p95":     round(p95, 4),
            "threshold_used": round(p95, 4),
        })

    for col in lower_metrics:
        p50 = normal[col].quantile(0.50)
        p10 = normal[col].quantile(0.10)
        
        if col == "dst_ip_entropy":
            t = max(p10, 0.1)
        else:
            t = max(p10, 1.0)
            
        thresholds[col] = float(round(t, 4))
        stats_rows.append({
            "metric":         col,
            "trigger":        "value < threshold",
            "normal_median":  round(p50, 4),
            "normal_p10":     round(p10, 4),
            "threshold_used": round(t, 4),
        })

    stats_df = pd.DataFrame(stats_rows).set_index("metric")

    print("=" * 70)
    print("DATA-DRIVEN FEATURE THRESHOLD JUSTIFICATION")
    print("=" * 70)
    print(stats_df)
    print(f"\nTotal NORMAL windows used for calibration : {len(normal)}")
    
    os.makedirs(METADATA_DIR, exist_ok=True)
    with open(THRESHOLDS_FILE, "w") as f:
        json.dump(thresholds, f, indent=4)
        
    print(f"Saved feature thresholds to {THRESHOLDS_FILE}")

    return thresholds, all_features

def compute_score_bands(scored_features, force_recalibrate=False):
    """
    Given a DataFrame that already has a 'heuristic_score' column,
    compute the optimal score thresholds for SUSPICIOUS and ATTACK.
    """
    if not force_recalibrate and os.path.exists(THRESHOLDS_FILE):
        with open(THRESHOLDS_FILE, "r") as f:
            thresholds = json.load(f)
        if "band_suspicious" in thresholds and "band_attack" in thresholds:
            print(f"Loaded score bands from {THRESHOLDS_FILE}")
            return thresholds["band_suspicious"], thresholds["band_attack"]
            
    normal_scores = scored_features[scored_features["attack_type"].isin(NORMAL_LABELS)]["heuristic_score"]
    attack_scores = scored_features[~scored_features["attack_type"].isin(NORMAL_LABELS)]["heuristic_score"]
    
    # 99th percentile of normal scores is the baseline for suspicious to maintain high precision
    p99_normal = normal_scores.quantile(0.99)
    
    band_suspicious = float(round(p99_normal, 2))
    
    if attack_scores.empty:
        band_attack = band_suspicious + 10.0
    else:
        attack_p25 = attack_scores.quantile(0.25)
        # Ensure attack band is higher than suspicious band
        band_attack = float(round(max(attack_p25, band_suspicious + 5.0), 2))
        
    print("\n=" * 70)
    print("DATA-DRIVEN SCORE BANDS JUSTIFICATION")
    print("=" * 70)
    print(f"Normal Score P99 : {p99_normal:.2f}")
    if not attack_scores.empty:
        print(f"Attack Score P25 : {attack_p25:.2f}")
    print(f"\nCalculated BANDS:")
    print(f"  SUSPICIOUS -> {band_suspicious}")
    print(f"  ATTACK     -> {band_attack}")
    
    # Update JSON
    if os.path.exists(THRESHOLDS_FILE):
        with open(THRESHOLDS_FILE, "r") as f:
            thresholds = json.load(f)
    else:
        thresholds = {}
        
    thresholds["band_suspicious"] = band_suspicious
    thresholds["band_attack"] = band_attack
    
    with open(THRESHOLDS_FILE, "w") as f:
        json.dump(thresholds, f, indent=4)
        
    return band_suspicious, band_attack
