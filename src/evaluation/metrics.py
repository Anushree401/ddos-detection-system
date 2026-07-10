import os
import pandas as pd
from IPython.display import display

def test_feature_pipeline(feature_dir):
    print("=" * 60)
    print("RUNNING FEATURE ENGINEERING TESTS")
    print("=" * 60)
    files = sorted(
        [f for f in os.listdir(feature_dir) if f.endswith(".csv")]
    )
    assert len(files) > 0, "No feature CSVs generated."
    required_columns = [
      "feature_id",
      "file_id",
      "filename",
      "dataset",
      "attack_type",
      "window_id",
      "window_start",
      "window_end",
      "window_size",
      "packet_count",
      "packet_rate",
      "byte_rate",
      "avg_packet_size",
      "packet_size_variance",
      "syn_rate",
      "ack_rate",
      "syn_ack_ratio",
      "udp_rate",
      "icmp_rate",
      "src_ip_entropy",
      "dst_ip_entropy",
      "unique_src_ips",
      "unique_dst_ips",
      "mean_interarrival"
    ]
    for file in files:
        print(f"\nTesting {file}")
        df = pd.read_csv(os.path.join(feature_dir, file))
        assert not df.empty, "Feature file is empty."
        missing = set(required_columns) - set(df.columns)
        assert len(missing) == 0, \
            f"Missing columns: {missing}"
        assert df["window_id"].is_monotonic_increasing, \
            "Windows are not sorted."
        assert np.allclose(
            df["window_end"] - df["window_start"],
            1.0
        ), "Window duration should be exactly 1 second."
        assert (df["packet_count"] >= 0).all()
        assert (df["byte_rate"] >= 0).all()
        assert (df["src_ip_entropy"] >= 0).all() # Renamed entropy column
        assert (df["dst_ip_entropy"] >= 0).all() # Renamed entropy column
        assert (df["avg_packet_size"] > 0).all()
        # Removed assertions for counts as they are no longer in the final feature set
        assert (df["unique_src_ips"] >= 1).all()
        assert (df["unique_dst_ips"] >= 1).all()
        assert not df.isnull().values.any(), \
            "NaN values detected."
        numeric = df.select_dtypes(include=np.number)
        assert np.isfinite(numeric.to_numpy()).all(), \
            "Infinite values detected."
        print("PASS")
    print("\n")
    print("=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)

def semantic_tests(feature_dir):
    print("="*60)
    print("RUNNING SEMANTIC TESTS")
    print("="*60)
    files = sorted(
        [f for f in os.listdir(feature_dir) if f.endswith(".csv")]
    )
    for file in files:
        print(f"\nTesting {file}")
        df = pd.read_csv(os.path.join(feature_dir, file))
        assert (df["window_size"] > 0).all()
        assert np.allclose(
            df["window_end"] - df["window_start"],
            df["window_size"]
        )
        assert (df["packet_rate"] == df["packet_count"]).all(), \
            "Packet rate mismatch."
        assert (df["byte_rate"] == df["byte_rate"]).all(), \
            "Byte rate mismatch."
        assert (df["syn_rate"] == df["syn_rate"]).all(), \
            "SYN rate mismatch."
        assert (df["ack_rate"] == df["ack_rate"]).all(), \
            "ACK rate mismatch."
        assert (df["udp_rate"] == df["udp_rate"]).all(), \
            "UDP rate mismatch."
        assert (df["icmp_rate"] == df["icmp_rate"]).all(), \
            "ICMP rate mismatch."
        assert (df["syn_ack_ratio"] >= 0).all()
        assert (df["avg_packet_size"] > 0).all()
        assert (df["packet_size_variance"] >= 0).all()
        max_src_entropy = np.log2(
            df["unique_src_ips"].clip(lower=1)
        )
        max_dst_entropy = np.log2(
            df["unique_dst_ips"].clip(lower=1)
        )
        assert (
            df["src_ip_entropy"] <= max_src_entropy + 1e-9
        ).all(), "Invalid source IP entropy."
        assert (
            df["dst_ip_entropy"] <= max_dst_entropy + 1e-9
        ).all(), "Invalid destination IP entropy."
        assert (df["mean_interarrival"] >= 0).all()
        print("PASS")
    print("\nAll semantic tests passed.")

def feature_profile(feature_dir):
    dfs = []
    for file in sorted(os.listdir(feature_dir)):
        if file.endswith(".csv"):
            dfs.append(
                pd.read_csv(
                    os.path.join(feature_dir, file)
                )
            )
    features = pd.concat(dfs, ignore_index=True)
    numeric_columns = [
        "packet_count",
        "packet_rate",
        "byte_rate",
        "avg_packet_size",
        "packet_size_variance",
        "syn_rate",
        "ack_rate",
        "syn_ack_ratio",
        "udp_rate",
        "icmp_rate",
        "src_ip_entropy",
        "dst_ip_entropy",
        "unique_src_ips",
        "unique_dst_ips",
        "mean_interarrival"
    ]
    print("Number of windows:", len(features))
    print("Datasets:")
    print(features["dataset"].value_counts())
    print()
    print("Attack Types:")
    print(features["attack_type"].value_counts())
    print("="*70)
    print("OVERALL FEATURE PROFILE")
    print("="*70)
    display(features[numeric_columns].describe())
    print("\n")
    print("="*70)
    print("PROFILE BY ATTACK TYPE")
    print("="*70)
    display(
        features.groupby("attack_type")[numeric_columns]
        .mean()
        .round(2)
    )
    print("\n")
    print("="*70)
    print("PROFILE BY DATASET")
    print("="*70)
    display(
        features.groupby("dataset")[numeric_columns]
        .mean()
        .round(2)
    )
    return features

# after cic-ddos2019
'''
def attack_behavior_tests(df):
    normal = df[df["attack_type"] == "NORMAL"]
    syn = df[df["attack_type"] == "SYN_FLOOD"]
    print("Normal Packet Rate:",
          normal["packet_rate"].mean())
    print("SYN Flood Packet Rate:",
          syn["packet_rate"].mean())
    print("Normal SYN/ACK:",
          normal["syn_ack_ratio"].mean())
    print("SYN Flood SYN/ACK:",
          syn["syn_ack_ratio"].mean())
'''