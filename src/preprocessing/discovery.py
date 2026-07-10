import os
import pandas as pd
from configs.settings import SUPPORTED_EXTENSIONS
from src.decision_engine.attack_identifier import identify_attack

def identify_dataset(path):
  path = path.lower()
  if "m57_patents" in path:
    return "M57_PATENTS"
  elif "malware_traffic_analysis" in path:
    return "MALWARE_TRAFFIC_ANALYSIS"
  elif "bot_iot" in path:
      return "BOT_IOT"
  elif "cic_ddos2019" in path:
      return "CIC_DDOS2019"
  elif "synthetic" in path:
      return "SYNTHETIC"
  return "UNKNOWN"

def scan_datasets(dataset_root):
  records = []
  file_counter = 1
  for root,_,files in os.walk(dataset_root):
    for file in files:
      if not file.endswith(tuple(SUPPORTED_EXTENSIONS)):
        continue
      absolute_path = os.path.join(root, file)
      relative_path = os.path.relpath(
        absolute_path,
        dataset_root
      )
      dataset = identify_dataset(relative_path)
      attack = identify_attack(dataset, relative_path)
      records.append({
          "file_id": f"FILE{file_counter:04d}",
          "filename": file,
          "dataset": dataset,
          "attack_type": attack,
          "file_path": relative_path,
          "file_size_bytes": os.path.getsize(absolute_path)
      })
      file_counter += 1
  return pd.DataFrame(records)
