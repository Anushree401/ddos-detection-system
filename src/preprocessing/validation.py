import os
import pandas as pd
import subprocess

def validate_pcaps(dataset_root,dataset_index):
  report = []
  for _,row in dataset_index.iterrows():
    file_path = os.path.join(dataset_root,row["file_path"])
    packet_count = 0
    ipv4 = False
    ipv6 = False
    tcp = False
    udp = False
    icmp = False
    malformed = False
    validation = "PASS"
    reason = "OK"
    try:
      reader = PcapReader(file_path)
      for packet in reader:
        packet_count += 1
        try:
          if IP in packet:
            ipv4 = True
          if IPv6 in packet:
            ipv6 = True
          if TCP in packet:
            tcp = True
          if UDP in packet:
            udp = True
          if ICMP in packet:
            icmp = True
        except Exception:
          malformed += 1
      reader.close()
      if packet_count == 0:
        validation = "FAIL"
        reason = "EMPTY PCAP"
    except Exception as e:
      validation = "FAIL"
      reason = str(e)
    report.append({
      "file_id": row["file_id"],
      "filename": row["filename"],
      "validation": validation,
      "packet_count": packet_count,
      "ipv4": ipv4,
      "ipv6": ipv6,
      "tcp": tcp,
      "udp": udp,
      "icmp": icmp,
      "malformed_packets": malformed,
      "reason": reason
    })
  return pd.DataFrame(report)