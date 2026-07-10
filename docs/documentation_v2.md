# System Architecture Design: Rule-Based/Heuristic DDoS Detection Pipeline

---

## 1. Dataset Selection and Registry Triage

Transitioning from a Machine Learning (ML) classifier to a heuristic/rule-based system changes the data validation requirements. Instead of requiring massive feature matrices for statistical pattern matching, the heuristic approach requires raw, structured network captures to establish explicit rule thresholds (e.g., baseline packets-per-second limits) and validate the deterministic logic of the parser.

The existing data registry must be truncated to eliminate high-level application logs and wireless-specific protocols, retaining only standard Ethernet/IP network traffic.

### 1.1 Recommended Datasets (Retained)

| Dataset Name                                     | Relevance | Strategic Engineering Purpose                                                                                                                                            |
| ------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Bot-IoT Dataset**                        | High      | Contains volumetric DoS/DDoS traffic profiles (UDP, TCP, and MQTT floods) along with raw network captures. This is the primary benchmark for defining metric thresholds. |
| **Malware Traffic Analysis**               | High      | Contains authentic PCAP files demonstrating malware-driven communication patterns. Useful for isolating anomalous operational baselines.                                 |
| **Network Packet Dumps (Digital Corpora)** | High      | A massive repository of raw PCAP captures representing standard user behavior. Used to define normal network baseline limits and false-positive thresholds.              |
| **IoT-23 Dataset**                         | Partial   | Contains mixed IoT malware captures. The raw PCAP subsets are used to extract benign background traffic profiles.                                                        |

### 1.2 Excluded Datasets

- **Wireless-Specific Data (AWID, 802.11 Attack Dataset):** Excluded because they focus on Layer 2 Wi-Fi mechanisms (e.g., deauthentication frames, WEP/WPA vulnerabilities) rather than Layer 3/4 Ethernet/IP volumetric floods.
- **System & Application Logs (Kaggle Logs, Web Server Logs, NASA HTTP Logs, LogHub, SSH Illegal Login Attempts):** Excluded because they capture post-execution application events rather than raw, real-time packet byte streams.
- **Documentation & Supply Chain Data (WiFi Release Notes, OSSF Malicious Packages):** Excluded as text files and package dependencies contain no network packet data.

---

## 2. PCAP File Format Specification

A Packet Capture (PCAP) file is a structured binary stream consisting of a single global header followed by sequential blocks of packet-specific headers and raw payload data. This structural hierarchy is maintained whether parsed programmatically via Scapy or visualized through an analyzer like Wireshark.

### 2.1 File Structure Hierarchy

```text
┌────────────────────────────────────────────────────────┐
│                  PCAP Global Header                    │
│      (Appears once at the beginning of the file)       │
├────────────────────────────────────────────────────────┤
│                    Packet 1 Block                      │
│  ├── Per-Packet Header (Metadata: Timestamps, Length)  │
│  └── Raw Packet Data (Ethernet Header → IP → L4 → Raw) │
├────────────────────────────────────────────────────────┤
│                    Packet 2 Block                      │
│  ├── Per-Packet Header                                 │
│  └── Raw Packet Data                                   │
├────────────────────────────────────────────────────────┤
│                          ...                           │
└────────────────────────────────────────────────────────┘
```

### 2.2 Global Header Layout

The global header spans exactly 24 bytes and establishes the environmental context for the entire capture file.

| Field Name                          | Size (Bytes) | Engineering Purpose                                                                        |
| ----------------------------------- | -----------: | ------------------------------------------------------------------------------------------ |
| **Magic Number**              |            4 | Identifies the file type and byte ordering (endianness) format (e.g.,`0xa1b2c3d4`).      |
| **Version Major**             |            2 | Major version number of the PCAP format library (typically 2).                             |
| **Version Minor**             |            2 | Minor version number of the PCAP format library (typically 4).                             |
| **Timezone**                  |            4 | Timezone correction offset in seconds from GMT (typically set to 0).                       |
| **Timestamp Accuracy**        |            4 | Accuracy of the packet capture timestamps (typically set to 0).                            |
| **Snapshot Length (SnapLen)** |            4 | Max byte length captured per packet. Traffic beyond this limit is truncated.               |
| **Link Layer Type**           |            4 | Identifies the underlying data link protocol (e.g.,`1` specifies `LinkType_Ethernet`). |

### 2.3 Per-Packet Header Layout

Every individual packet block is prefixed with a 16-byte metadata header describing its acquisition properties.

| Field Name                          | Size (Bytes) | Engineering Purpose                                                                 |
| ----------------------------------- | -----------: | ----------------------------------------------------------------------------------- |
| **Timestamp Seconds**         |            4 | Epoch timestamp integer indicating when the packet was captured.                    |
| **Timestamp Microseconds**    |            4 | Microsecond or nanosecond offset matching the precision of the capture environment. |
| **Captured Length (CapLen)**  |            4 | The actual number of packet bytes saved into the file.                              |
| **Original Length (OrigLen)** |            4 | The true length of the packet as it traveled across the network medium.             |

---

## 3. Hierarchical Network Layer Decomposition

The raw byte array following the per-packet header is systematically unpacked down the OSI stack based on conditional flag values.

```text
┌──────────────────────────────────────────────────────────────────────────┐
│                             Ethernet Header                              │
│         Destination MAC  │  Source MAC  │  EtherType (0x0800 = IPv4)     │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                                IP Header                                 │
│ Version │ Header Len │ Total Len │ TTL │ Protocol (TCP=6, UDP=17, ICMP=1)│
│                 Source IP Address  │  Destination IP Address             │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 ▼                   ▼                   ▼
     ┌───────────────────────┐ ┌───────────┐ ┌───────────────────────┐
     │      TCP Header       │ │UDP Header │ │      ICMP Header      │
     │ Ports, Sequence, Flags│ │Ports, Len │ │ Type, Code, Checksum  │
     └───────────────────────┘ └───────────┘ └───────────────────────┘
```

### 3.1 Layer 2: Ethernet Header

- **Destination MAC Address (6 bytes):** Physical hardware address of the receiving interface.
- **Source MAC Address (6 bytes):** Physical hardware address of the transmitting interface.
- **EtherType (2 bytes):** Determines the next layer protocol. A value of `0x0800` explicitly indicates IPv4 encapsulation.

### 3.2 Layer 3: Internet Protocol (IPv4) Header

Parsed only if the EtherType matches `0x0800`.

- **Version (4 bits):** IP version identifier, configured to 4.
- **Internet Header Length (IHL) (4 bits):** Length of the IP header, indicating where the payload begins.
- **Total Length (2 bytes):** Total size of the IP datagram (header plus payload) in bytes.
- **Time to Live (TTL) (1 byte):** The remaining hop limit for the packet.
- **Protocol (1 byte):** Identifies the Layer 4 transport layer protocol. Standard operational keys:
  - `6` → Transmission Control Protocol (TCP)
  - `17` → User Datagram Protocol (UDP)
  - `1` → Internet Control Message Protocol (ICMP)
- **Source IP Address (4 bytes):** Layer 3 source node tracking coordinate.
- **Destination IP Address (4 bytes):** Layer 3 target node tracking coordinate.

### 3.3 Layer 4: Transport Protocols

#### Transmission Control Protocol (TCP)

Parsed when the IP `Protocol` field equals `6`.

- **Source Port (2 bytes) / Destination Port (2 bytes):** Maps application communication endpoints.
- **Sequence / Acknowledgment Numbers (4 bytes each):** Monitors connection state tracking.
- **Flags (9 bits total, focusing on lower 6 bits):** Control bits mapping connection lifecycle states:
  - `SYN` (Synchronize): Initiates connection handshakes
  - `ACK` (Acknowledge): Confirms receipt of prior segments
  - `FIN` (Finish): Gracefully terminates an active connection session
  - `RST` (Reset): Abruptly terminates an unstable connection pathway
  - `PSH` (Push) and `URG` (Urgent): Secondary data priority controls
- **Window Size (2 bytes):** Advertised receive buffer size.

#### User Datagram Protocol (UDP)

Parsed when the IP `Protocol` field equals `17`.

- **Source Port (2 bytes) / Destination Port (2 bytes):** Unconnected endpoints routing data payloads.
- **Length (2 bytes):** Specifies the total size of the UDP header and data segment.

#### Internet Control Message Protocol (ICMP)

Parsed when the IP `Protocol` field equals `1`.

- **Type (1 byte):** General category of the control message (e.g., Type `8` for Echo Request).
- **Code (1 byte):** Sub-category details modifying the primary operational type.

---

## 4. Heuristic Feature Extraction Matrix

Unlike an ML pipeline that processes abstract statistical derivations, a heuristic engine uses explicit, direct packet fields to feed deterministic detection rules.

| Extracted Field                         | Direct Operational Purpose in Rule Engine                                          |
| --------------------------------------- | ---------------------------------------------------------------------------------- |
| **Timestamp**                     | Evaluates sliding time window limits\(\Delta t\) and computes traffic rates.       |
| **Source IP (\(IP_{src}\))**      | Identifies the offending node to issue automated block listings.                   |
| **Destination IP (\(IP_{dst}\))** | Identifies the local target node experiencing the anomaly.                         |
| **Protocol Type**                 | Branches traffic directly to protocol-specific evaluation modules.                 |
| **Source / Destination Port**     | Detects application-specific volumetric targeting (e.g., port scans, HTTP floods). |
| **Packet Length (\(L_p\))**       | Measures immediate traffic volume to flag high-bandwidth anomalies.                |
| **TCP Control Flags**             | Tracks the balance of control flags to flag anomalies like SYN floods.             |
| **Time-to-Live (TTL)**            | Flags potential spoofing anomalies based on sudden distribution shifts.            |
| **ICMP Type**                     | Flags ping sweep behavior and volumetric ICMP flood attempts.                      |

---

## 5. Algorithmic Metric Engineering and Detection Rules

The rule-based detection engine transforms these raw metrics into aggregated window tallies across a configurable time window \(\Delta t\). If any metric breaches a predefined threshold, the engine immediately flags the attack.

### 5.1 Metric Calculation Formulas

- **Packets Per Second (PPS):**\[
  \text{PPS} = \frac{N_{\text{packets}}}{\Delta t}
  \]
- **Bytes Per Second (BPS):**\[
  \text{BPS} = \frac{\sum L_p}{\Delta t}
  \]
- **SYN Count:**\[
  \sum \text{Packets where } \text{TCP}_{\text{flags}} = \text{SYN}
  \]
- **SYN/ACK Ratio:**\[
  \text{Ratio}_{\text{SYN/ACK}} = \frac{\sum \text{SYN}}{\sum \text{ACK} + 1}
  \]
- **UDP Count:**\[
  \sum \text{Packets where } \text{Protocol} = 17
  \]
- **ICMP Count:**\[
  \sum \text{Packets where } \text{Protocol} = 1
  \]
- **Unique Source IPs:**Cardinality of the unique source IP set:
  \[
  \left| \{ IP_{src_1}, IP_{src_2}, \dots \} \right|
  \]
- **Average Packet Size (\(\mu_L\)):**\[
  \mu_L = \frac{\sum L_p}{N_{\text{packets}}}
  \]
- **Active Flows:**
  Count of unique connection tuples:
  \[
  \left| \{ (IP_{src}, Port_{src}, IP_{dst}, Port_{dst}) \} \right|
  \]

### 5.2 Deterministic Heuristic Engine Rule Matrix

The aggregated window metrics are continuously checked against the following deterministic logic rules:

```text
                  [ Compute Windows Metrics every Δt ]
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         ▼                         ▼                         ▼
  [ Rule: SYN Flood ]       [ Rule: UDP Flood ]      [ Rule: ICMP Flood ]
  - PPS > Threshold_A       - PPS > Threshold_B      - PPS > Threshold_C
  - SYN/ACK > Ratio_Limit   - UDP Count > Limit_B    - ICMP Count > Limit_C
         │                         │                         │
         └─────────────────────────┼─────────────────────────┘
                                   │ (If Any Rule Matches TRUE)
                                   ▼
                       [ Trigger Alert & Mitigation ]
```

| Target Vector                  | Operational Detection Logic Rules                                                                                                                                                   | Mitigation Directive                        |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| **SYN Flood Attack**     | `IF` \(\text{PPS} > \theta_{\text{pps}}\) `AND` \(\text{Ratio}_{\text{SYN/ACK}} > \theta_{\text{syn_ratio}}\) `THEN` Alert SYN Attack                                       | Deploy SYN Cookies / Rate-Limit\(IP_{src}\) |
| **UDP Volumetric Flood** | `IF` \(\text{BPS} > \theta_{\text{bps}}\) `AND` \(\text{Count}_{\text{UDP}} > \theta_{\text{udp_count}}\) `AND` \(\mu_L \approx \text{Constant}\) `THEN` Alert UDP Attack | Drop UDP fragments targeting\(Port_{dst}\)  |
| **ICMP Ping Flood**      | `IF` \(\text{Count}_{\text{ICMP}} > \theta_{\text{icmp}}\) `AND` \(\text{ICMP}_{\text{type}} = 8\) `THEN` Alert ICMP Attack                                                 | Implement firewall drop rules for ICMP Echo |
| **DDoS (Distributed)**   | `IF` \(\text{PPS} > \theta_{\text{pps}}\) `AND` \(\text{Unique Source IPs} > \theta_{\text{hosts}}\) `THEN` Alert Distributed Flood                                           | Engage border gateway protocol scrubbing    |