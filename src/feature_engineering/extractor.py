import os
import pandas as pd
import numpy as np
from src.feature_engineering.entropy import entropy

def generate_features(parsed_dir, output_dir, dataset_index):
    os.makedirs(output_dir, exist_ok=True)
    WINDOW_SIZE = 1.0
    parsed_files = sorted(
        [f for f in os.listdir(parsed_dir) if f.endswith(".csv")]
    )
    for file in parsed_files:
        df = pd.read_csv(os.path.join(parsed_dir, file))
        if df.empty:
            continue
        meta = dataset_index[
            dataset_index["file_id"] == file.replace(".csv", "")
        ].iloc[0]
        file_id = meta["file_id"]
        dataset = meta["dataset"]
        attack_type = meta["attack_type"]
        filename = meta["filename"]
        df["window_id"] = (
            df["timestamp"] // WINDOW_SIZE
        ).astype(int)
        feature_rows = []
        for window_id, group in df.groupby("window_id"):
            window_start = window_id * WINDOW_SIZE
            window_end = window_start + WINDOW_SIZE

            packet_count = len(group)
            byte_count = group["packet_length"].sum() # Still needed for byte_rate
            packet_rate = packet_count
            byte_rate = byte_count
            avg_packet_size = group["packet_length"].mean()
            packet_size_variance = group[
                "packet_length"
            ].var(ddof=0)
            if pd.isna(packet_size_variance):
                packet_size_variance = 0.0

            syn_count = group["syn"].sum() # Still needed for syn_rate, syn_ack_ratio
            ack_count = group["ack"].sum() # Still needed for ack_rate, syn_ack_ratio
            udp_count = (
                group["protocol"] == "UDP"
            ).sum() # Still needed for udp_rate
            icmp_count = (
                group["protocol"] == "ICMP"
            ).sum() # Still needed for icmp_rate

            syn_rate = syn_count
            ack_rate = ack_count
            udp_rate = udp_count
            icmp_rate = icmp_count

            syn_ack_ratio = syn_count / max(ack_count, 1)

            unique_src_ips = group["src_ip"].nunique()
            unique_dst_ips = group["dst_ip"].nunique()

            src_ip_entropy = entropy(group["src_ip"])
            dst_ip_entropy = entropy(group["dst_ip"])

            # flow_count and std_interarrival are removed as requested
            timestamps = np.array(
                group["timestamp"].values
            )
            if len(timestamps) > 1:
                interarrival = np.diff(timestamps)
                mean_interarrival = interarrival.mean()
            else:
                mean_interarrival = 0

            feature_rows.append({
                "feature_id": f"{file_id}_W{window_id:06d}",
                "file_id": file_id,
                "filename": filename,
                "dataset": dataset,
                "attack_type": attack_type,
                "window_id": window_id,
                "window_start": window_start,
                "window_end": window_end,
                "window_size": window_end - window_start,
                "packet_count": packet_count,
                "packet_rate": packet_rate,
                "byte_rate": byte_rate,
                "avg_packet_size": avg_packet_size,
                "packet_size_variance": packet_size_variance,
                "syn_rate": syn_rate,
                "ack_rate": ack_rate,
                "syn_ack_ratio": syn_ack_ratio,
                "udp_rate": udp_rate,
                "icmp_rate": icmp_rate,
                "src_ip_entropy": src_ip_entropy,
                "dst_ip_entropy": dst_ip_entropy,
                "unique_src_ips": unique_src_ips,
                "unique_dst_ips": unique_dst_ips,
                "mean_interarrival": mean_interarrival
            })
        features = pd.DataFrame(feature_rows)
        features.to_csv(
            os.path.join(output_dir, file),
            index=False
        )