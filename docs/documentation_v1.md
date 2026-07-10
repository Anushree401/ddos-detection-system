# System Architecture Design: Real-Time DDoS Detection and Mitigation Pipeline

---

## 1. Architectural Overview and Workflow

To build a robust, real-time Distributed Denial of Service (DDoS) detection system, the processing pipeline must decouple offline model training from online live inference. While model training relies on historical, labeled datasets, live detection processes raw network traffic under strict time constraints.

### 1.1 High-Level Detection Workflow

```text
[ Internet Traffic ]
        │
        ▼
[ Scapy Live Capture ]
        │
        ▼
[ Raw Network Packets ]
        │
        ▼
[ Real-Time Feature Extraction ] ◄─── (Sliding Time Window: Δt = 1s / 5s)
        │
        ▼
[ Trained Random Forest Classifier ]
        │
        ▼
┌───────────────────────┴───────────────────────┐
│                                               │
▼                                               ▼
[ Class: Normal ]                       [ Class: Attack ]
│                                               │
▼                                               ▼
[ Continue Monitoring ]                 [ Trigger Mitigation Pipeline ]
```

### 1.2 Data Source Segmentation

| Operational Mode  | Purpose                     | Primary Data Source   | Input Format                      | Output Target            |
| ----------------- | --------------------------- | --------------------- | --------------------------------- | ------------------------ |
| **Offline** | Model Training & Validation | CIC-DDoS2019 Dataset  | PCAP + Labeled CSV                | Static Feature Matrices  |
| **Online**  | Live Network Detection      | Scapy Socket Sniffing | Raw Byte Stream / Network Packets | Real-Time Classification |

---

## 2. Real-Time Ingestion and Data Format

To maintain low latency and low memory utilization at runtime, the system avoids storing raw Packet Capture (PCAP) data to disk. Instead, an in-memory streaming architecture extracts specific header fields instantly upon packet arrival.

### 2.1 Runtime Packet Processing Lifecycle

```text
[ Raw PCAP / Live Stream ]
           │
           ▼
     (Read Packet)
           │
           ▼
[ Extract Protocol Layer Fields ]
           │
           ▼
[ Append to In-Memory Buffer ]
           │
           ▼
[ Evaluate Time Window (Δt) ] ───( Every N Seconds )───► [ Compute Aggregated Vector ]
                                                                     │
                                                                     ▼
                                                         [ Machine Learning Model ]
```

### 2.2 Protocol Layer Decomposition

Network packets are parsed hierarchically using Scapy to extract features across the OSI model layers:

```text
┌────────────────────────────────────────────────────────┐
│ Ethernet Layer                                         │
├────────────────────────────────────────────────────────┤
│ IP Layer (Source IP, Destination IP, TTL, Protocol)   │
├────────────────────────────────────────────────────────┤
│ Transport Layer (TCP: Flags, Ports / UDP / ICMP)      │
├────────────────────────────────────────────────────────┤
│ Payload (Raw Byte Stream Length)                       │
└────────────────────────────────────────────────────────┘
```

---

## 3. Network Field Extraction Schema

The feature extraction module isolates specific fields from the Network and Transport layers. These metrics provide the raw data required for downstream statistical aggregation.

### 3.1 Network Layer Extraction

- **Timestamp:** Precision epoch time of packet arrival used to evaluate sliding windows.
- **Source IP Address ($IP_{src}$):** Identifies the originating node; critical for tracking distributed anomalies.
- **Destination IP Address ($IP_{dst}$):** Identifies the target node under inspection.
- **Protocol:** Identifies the transport layer protocol (TCP, UDP, or ICMP).
- **Time-to-Live (TTL):** Indicates routing hop limits; abrupt variances can indicate spoofing.
- **Total Packet Length ($L_p$):** Total size of the packet in bytes, used to monitor bandwidth.

### 3.2 Transport Layer Extraction

#### Transmission Control Protocol (TCP)

- **Source / Destination Ports:** Identify specific application services and mapping behaviors.
- **Control Flags (SYN, ACK, FIN, RST):** Monitor state transitions. Flooding implementations typically manipulate these flags.
- **Window Size:** Monitors buffer availability configurations between host connections.
- **Sequence Number:** Tracks stream continuity and anomalous gaps.

#### User Datagram Protocol (UDP)

- **Source / Destination Ports:** Monitor connectionless data flows.
- **Length:** Measures individual datagram sizes to identify volumetric amplification attacks.

#### Internet Control Message Protocol (ICMP)

- **Type / Code:** Detects specific control signals (e.g., Echo Requests) used in ping floods or network scanning.

### 3.3 Intermediate Data Representation

Extracted packet properties are parsed into an in-memory structured table before feature engineering:

| Timestamp    | Source IP | Destination IP | Protocol | Size (Bytes) | SYN | ACK | UDP | ICMP |
| ------------ | --------- | -------------- | -------- | ------------ | --- | --- | --- | ---- |
| 10:01:01.002 | 1.1.1.1   | 192.168.1.5    | TCP      | 60           | 1   | 0   | 0   | 0    |
| 10:01:01.045 | 2.2.2.2   | 192.168.1.5    | UDP      | 512          | 0   | 0   | 1   | 0    |
| 10:01:01.090 | 3.3.3.3   | 192.168.1.5    | ICMP     | 74           | 0   | 0   | 0   | 1    |

---

## 4. Feature Engineering and Mathematical Formulations

Individual packets do not provide enough context to reliably detect a distributed attack. Packets are grouped into a time-based window ($\Delta t$) to calculate statistical metrics.

### A. Packets Per Second (PPS)

Measures the frequency of incoming packets over the time window.

$$
PPS = \frac{N_{\text{packets}}}{\Delta t}
$$

### B. Bytes Per Second (BPS)

Measures the total bandwidth consumption over the time window.

$$
BPS = \frac{\sum_{i=1}^{N} L_i}{\Delta t}
$$

### C. Average Packet Size

Identifies the average payload footprint, separating small-packet floods from large volumetric attacks.

$$
\mu_L = \frac{\sum_{i=1}^{N} L_i}{N}
$$

### D. Packet Size Variance

Measures the dispersion of packet sizes. Volumetric automated floods typically use uniform packet sizes, resulting in a variance close to zero.

$$
\sigma^2_L = \frac{\sum_{i=1}^{N} (L_i - \mu_L)^2}{N}
$$

### E. SYN Flag Ratio

Calculates the proportion of SYN packets relative to all TCP traffic. High ratios indicate SYN flood behavior.

$$
Ratio_{\text{SYN}} = \frac{\sum SYN_{\text{packets}}}{\sum TCP_{\text{packets}}}
$$

### F. SYN-to-ACK Ratio

Evaluates connection symmetry. Normal handshakes maintain a balanced ratio, whereas an anomalous spike indicates half-open connection exploits.

$$
Ratio_{\text{SYN/ACK}} = \frac{\sum SYN_{\text{packets}}}{\left(\sum ACK_{\text{packets}}\right) + 1}
$$

### G. Protocol Multi-Counters

Tracks separate volume counts for specific protocols to identify structural shifts in traffic.

$$
Count_{\text{UDP}} = \sum UDP_{\text{packets}}
$$

$$
Count_{\text{ICMP}} = \sum ICMP_{\text{packets}}
$$

### H. Host Cardinalities

Tracks the number of unique source IP addresses ($|IP_{src}|$) and unique destination ports ($|Port_{dst}|$) within the time window to identify distributed scanning or targeting behavior.

### I. Source IP Entropy

Measures the distribution and uncertainty of originating addresses. Low entropy indicates a single high-volume attacker, while high entropy indicates a distributed botnet attack.

$$
H(IP) = -\sum_{i=1}^{K} p(ip_i) \log_2 p(ip_i)
$$

Where $p(ip_i)$ represents the probability mass function of the $i$-th unique source IP within the current sampling window.

### J. Average Packet Inter-Arrival Time (Avg IAT)

Calculates the mean time gap between consecutive arrivals. Automated high-rate attacks significantly compress this interval.

$$
AvgIAT = \frac{\sum_{i=2}^{N} (t_i - t_{i-1})}{N - 1}
$$

### K. Destination Concentration Factor

Measures the proportion of traffic targeted at the most active host destination, identifying focused intent against a victim.

$$
Concentration_{dst} = \frac{\max\left(Count(IP_{dst})\right)}{N}
$$

---

## 5. Unified ML Input Feature Vector

Every $\Delta t$ seconds, the feature extraction module outputs a single standardized vector to the Random Forest model.

```text
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           Standardized Feature Vector                           │
├───────────────┬────────────────┬────────────────┬───────────────┬───────────────┤
│ PPS           │ BPS            │ Avg Packet Size│ Size Variance │ SYN Count     │
├───────────────┼────────────────┼────────────────┼───────────────┼───────────────┤
│ ACK Count     │ SYN Ratio      │ SYN/ACK Ratio  │ UDP Count     │ ICMP Count    │
├───────────────┼────────────────┼────────────────┼───────────────┼───────────────┤
│ Unique Src IP │ Unique Dst Port│ Average TTL    │ Src IP Entropy│ Avg IAT       │
├───────────────┼────────────────┼────────────────┼───────────────┴───────────────┤
│ Flow Duration │ Active Flows   │ Dst Concen.    │                               │
└───────────────┴────────────────┴────────────────┴───────────────────────────────┘
```

This structural alignment ensures that the inference engine processes real-time network streams using the exact statistical formats derived during offline training on the CIC-DDoS2019 dataset.