def identify_attack(dataset, path):
  path = path.lower()
  if dataset == "CIC_DDOS2019":
      if "benign" in path:
          return "NORMAL"
      elif "synflood" in path or "syn" in path:
          return "SYN_FLOOD"
      elif "udplag" in path or "udp" in path:
          return "UDP_FLOOD"
      else:
          return "DDOS"
  
  mapping = {
    "M57_PATENTS": "NORMAL",
    "MALWARE_TRAFFIC_ANALYSIS": "MALWARE",
    "BOT_IOT": "UNKNOWN"
  }
  return mapping.get(dataset,"UNKNOWN")