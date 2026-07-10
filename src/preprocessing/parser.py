import os
import subprocess
import pandas as pd
# pyrefly: ignore [missing-import]
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP

def parse_pcaps(dataset_root, dataset_index, validation_report, parsed_dir=None):
    if parsed_dir is None:
        parsed_dir = os.path.join(dataset_root, "../parsed")
    os.makedirs(parsed_dir, exist_ok=True)
    valid_files = validation_report[
        validation_report["validation"] == "PASS"
    ]
    for _, row in valid_files.iterrows():
        csv_path = os.path.join(parsed_dir, f"{row['file_id']}.csv")
        if os.path.exists(csv_path):
            continue
        metadata = dataset_index[
            dataset_index["file_id"] == row["file_id"]
        ].iloc[0]
        pcap_path = os.path.join(
            dataset_root,
            metadata["file_path"]
        )
        packets = []
        reader = PcapReader(pcap_path)
        start_time = None
        packet_number = 1
        for packet in reader:
            if not (
                IP in packet
                or IPv6 in packet
                or TCP in packet
                or UDP in packet
                or ICMP in packet
            ):
                continue
            if start_time is None:
                start_time = float(packet.time)
            timestamp = float(packet.time) - start_time
            src_ip = None
            dst_ip = None
            ttl = None
            identification = None
            fragment_offset = None
            df_flag = False
            mf_flag = False
            protocol = None
            src_port = None
            dst_port = None
            syn = False
            ack = False
            fin = False
            rst = False
            psh = False
            urg = False
            window_size = None
            icmp_type = None
            icmp_code = None
            if IP in packet:
                ip = packet[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                ttl = ip.ttl
                identification = ip.id
                fragment_offset = ip.frag
                df_flag = bool(ip.flags.DF)
                mf_flag = bool(ip.flags.MF)
                protocol = "IPv4"
            elif IPv6 in packet:
                ip = packet[IPv6]
                src_ip = ip.src
                dst_ip = ip.dst
                ttl = ip.hlim
                protocol = "IPv6"
            if TCP in packet:
                tcp = packet[TCP]
                protocol = "TCP"
                src_port = tcp.sport
                dst_port = tcp.dport
                syn = tcp.flags.S
                ack = tcp.flags.A
                fin = tcp.flags.F
                rst = tcp.flags.R
                psh = tcp.flags.P
                urg = tcp.flags.U
                window_size = tcp.window
            elif UDP in packet:
                udp = packet[UDP]
                protocol = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
            elif ICMP in packet:
                icmp = packet[ICMP]
                protocol = "ICMP"
                icmp_type = icmp.type
                icmp_code = icmp.code
            packets.append({
                "file_id": row["file_id"],
                "packet_number": packet_number,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "src_port": src_port,
                "dst_port": dst_port,
                "packet_length": len(packet),
                "ttl": ttl,
                "identification": identification,
                "fragment_offset": fragment_offset,
                "df_flag": df_flag,
                "mf_flag": mf_flag,
                "syn": syn,
                "ack": ack,
                "fin": fin,
                "rst": rst,
                "psh": psh,
                "urg": urg,
                "window_size": window_size,
                "icmp_type": icmp_type,
                "icmp_code": icmp_code
            })
            packet_number += 1
        reader.close()
        df = pd.DataFrame(packets)
        df = df.sort_values("timestamp")
        df.to_csv(
            os.path.join(
                parsed_dir,
                f"{row['file_id']}.csv"
            ),
            index=False
        )