# Technical Specification: Packet-Level Heuristic DDoS Detection and Progressive Mitigation Pipeline

---

## 1. Pipeline Architecture

To elevate this system into a technically rigorous cybersecurity platform, operations must be anchored at the deep packet level. The pipeline ingests raw network frames, parses structural anomalies across the OSI stack, aggregates them into stateful bidirectional network flows, applies multi-tiered behavioral heuristics, and routes decisions to an automated, progressive mitigation engine.

### 1.1 Structural Workflow

```
       [ Raw Traffic Ingestion ] (Live Interface / PCAP Stream)
                   │
                   ▼
         [ Packet Decoder ] (Layer 2, 3, & 4 Header Unpacking)
                   │
                   ▼
      [ Packet-Level Analysis ] (L3/L4 Micro-Anomaly Verification)
                   │
                   ▼
        [ Flow Construction ] (Stateful 5-Tuple Connection Tracking)
                   │
                   ▼
       [ Traffic Statistics ] (Sliding-Window Matrix Aggregation)
                   │
                   ▼
   [ Heuristic Detection Engine ] (Multi-Criteria Confidence Scoring)
                   │
                   ▼
       [ Confidence Scoring ] (Normal / Suspicious / Attack Classification)
                   │
                   ▼
       [ Mitigation Engine ] (Proportional Remediation Escalation)
                   │
                   ▼
 [ Firewall / ACL / Rate Limiter ] (System-Level Operational Enforcement)

```

---

## 2. Low-Level Protocol Field Analysis

### 2.1 Stage 1 — Layer 2 and Layer 3 Inspection

Every incoming data link frame is parsed to evaluate protocol integrity and detect early signs of manipulation.

```
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 2: Ethernet Frame                                                │
│ ├── Source MAC      ├── Destination MAC                                │
│ └── EtherType       └── VLAN Tag (Optional 802.1Q Multiplexing)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ (If EtherType == 0x0800)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ Layer 3: IPv4 Datagram                                                 │
│ ├── Source / Destination IP  ├── Version & IHL   ├── Total Length      │
│ ├── TTL                      ├── Identification  ├── Protocol Identifier│
│ └── Fragmentation Fields (Fragment Offset, Flags: DF, MF)               │
└────────────────────────────────────────────────────────────────────────┘

```

#### Layer 2 (Ethernet) Operational Metrics

* **Source MAC / Destination MAC:** Tracks hardware-level hops. Used to identify local MAC address spoofing and anomalous frame sources.
* **EtherType:** Verifies encapsulate layer routing (e.g., `0x0800` for IPv4). Unsupported values are discarded at the boundary.
* **VLAN Tag (IEEE 802.1Q):** Evaluates inner-frame tagging to protect against VLAN hopping exploits.

#### Layer 3 (Internet Protocol) Engineering Metrics

* **Source IP / Destination IP:** Primary tracking coordinates for targeting and origin analysis.
* **IP Version & Internet Header Length (IHL):** Verifies formatting conformance. Malformed header configurations are dropped instantly.
* **Total Length ($L_p$):** Evaluates individual packet sizing. Continuous streams of uniform byte sizes indicate automated flood generation.
* **Time-to-Live (TTL):** Tracks remaining router hops. Monitored for rigid uniformity (e.g., thousands of incoming packets possessing an unvarying TTL of exactly `64` or `128`), which indicates scripted botnet traffic.
* **Identification / Fragment Offset / Flags (DF - Don't Fragment, MF - More Fragments):** Analyzed to detect fragmentation exploits, such as Teardrop or tiny-fragment smuggling attacks.
* **Protocol:** Routes payloads to Layer 4 processing queues (TCP = `6`, UDP = `17`, ICMP = `1`).

---

### 2.2 Stage 2 — Layer 4 Transport Layer Analysis

Most volumetric and state-exhaustion anomalies target Layer 4 protocols. The pipeline evaluates the state characteristics of individual protocols.

#### Transmission Control Protocol (TCP) State Tracking

The system maps individual TCP control flags bitwise to evaluate connection integrity:

$$\text{Flags} = \{\text{URG}, \text{ACK}, \text{PSH}, \text{RST}, \text{SYN}, \text{FIN}\}$$

```
    [ Legitimate Connection ]               [ SYN Flood Anomaly ]
       Client         Server                   Client         Server
         │              │                         │              │
         │─── SYN ─────>│                         │─── SYN ─────>│
         │<── SYN/ACK ──│                         │─── SYN ─────>│
         │─── ACK ─────>│ (Established)           │─── SYN ─────>│ (State Exhaustion)

```

The system maintains an in-memory **Connection State Table** indexed by connection parameters. If an address transmits repeated `SYN` frames without responding to the server's `SYN-ACK` replies, the state tracking engine marks the connection as *half-open*. If timeouts occur across thousands of concurrent half-open sessions, a SYN Flood exploit is flagged.

#### User Datagram Protocol (UDP) Characterization

Because UDP is connectionless, analysis relies on structural consistency rather than state changes. The detection engine flags an anomaly if it detects a high packet frequency directed at specific application ports, combined with minimal payload variance and a sudden increase in overall bandwidth.

#### Internet Control Message Protocol (ICMP) Evaluation

The engine pairs Echo Requests (Type `8`, Code `0`) with their corresponding Echo Replies (Type `0`, Code `0`). A continuous stream of Echo Requests without any matching responses indicates an active ICMP flood or ping sweep.

---

## 3. Stateful Flow Construction and Statistics

### 3.1 Stage 3 — Flow Extraction

Packets are grouped into stateful network flows using a unique **5-Tuple Key**:

$$\text{Flow Key} = \langle \text{Source IP}, \text{Destination IP}, \text{Source Port}, \text{Destination Port}, \text{Protocol} \rangle$$

For every identified flow, the cache updates a live metrics block tracking structural behavior:

```
┌────────────────────────────────────────────────────────────────────────┐
│                          Stateful Flow Record                          │
├────────────────────────────────────────────────────────────────────────┤
│ 5-Tuple: <192.168.1.20, 10.0.0.5, 49201, 443, TCP>                     │
├────────────────────────────────────────────────────────────────────────┤
│ Metrics:                                                               │
│  ├── Packet Counter: 14,200 frames  ├── Byte Counter: 852,000 bytes    │
│  ├── Initial Timestamp: t_0         ├── Last Seen Timestamp: t_n       │
│  ├── Avg Packet Size: 60 bytes      ├── Retransmission Rate: 12%       │
│  └── Window Size Advertised: 1024   └── Inter-arrival Vector: [Δt]     │
└────────────────────────────────────────────────────────────────────────┘

```

---

### 3.2 Stage 4 — Sliding-Window Statistical Calculations

Every sampling interval ($\Delta t$), the system calculates the following aggregate statistical metrics across all active flows:

* **Volumetric Rates:**

$$\text{PPS} = \frac{N_{\text{packets}}}{\Delta t} \quad , \quad \text{BPS} = \frac{\sum L_p}{\Delta t}$$


* **Protocol Frequency Ratios:**

$$\text{Rate}_{\text{SYN}} = \frac{\sum \text{SYN}_{\text{packets}}}{\Delta t} \quad , \quad \text{Ratio}_{\text{SYN/ACK}} = \frac{\sum \text{SYN}_{\text{packets}}}{\left(\sum \text{ACK}_{\text{packets}}\right) + 1}$$


* **Packet Uniformity Variance ($\sigma^2_L$):**

$$\mu_L = \frac{\sum_{i=1}^{N} L_i}{N} \quad \Longrightarrow \quad \sigma^2_L = \frac{\sum_{i=1}^{N} (L_i - \mu_L)^2}{N}$$



*A variance value approaching zero indicates highly uniform, automated flood scripts.*
* **Source Address Information Entropy ($H_{\text{src}}$):**
Calculates the distribution randomness of originating addresses to separate single-source attacks from distributed botnets.

$$H_{\text{src}} = -\sum_{i=1}^{K} p(ip_i) \log_2 p(ip_i)$$



*Where $p(ip_i)$ is the ratio of packets sent by source $ip_i$ to the total packets received during the window.*
* **Destination Port Information Entropy ($H_{\text{dst\_port}}$):**
Measures port distribution to distinguish between multi-port network scanning and focused application-layer targeting.
* **Packet Inter-Arrival Time (IAT):**

$$\text{IAT} = t_n - t_{n-1}$$



*Highly consistent, sub-millisecond intervals indicate automated script transmission.*

---

## 4. Heuristic Decision Engine and Mitigation

### 4.1 Stage 5 — Multi-Criteria Confidence Scoring Matrix

To avoid the false positives common with single-threshold rules, the engine uses a weighted scoring matrix. Individual anomalies add to a cumulative confidence score ($S_{\text{conf}}$).

| Operational Metric Category | Measured Boundary Trigger Condition | Heuristic Weight Value |
| --- | --- | --- |
| **Volumetric Load Spike** | $\text{PPS} > 2000 \text{ packets/sec}$ | $+30$ |
| **Handshake Asymmetry** | $\text{Ratio}_{\text{SYN/ACK}} > 5.0$ | $+25$ |
| **Volumetric UDP Influx** | $\text{UDP Rate} > 1000 \text{ datagrams/sec}$ | $+20$ |
| **Payload Structural Rigidity** | $\sigma^2_L < 10.0 \text{ (High Uniformity)}$ | $+15$ |
| **Source Address Dispersion** | Unique Source Address Cardinality $> 100$ | $+20$ |
| **Target Port Concentration** | $H_{\text{dst\_port}} \to 0 \text{ (Single Port Influx)}$ | $+15$ |

#### Categorization Logic

$$\text{Pipeline Status} = \begin{cases} 
\text{Normal Operational Baseline} & 0 \le S_{\text{conf}} < 40 \\
\text{Suspicious Configuration Target} & 40 \le S_{\text{conf}} < 70 \\
\text{Active Attack Verification} & S_{\text{conf}} \ge 70 
\end{cases}$$

---

### 4.2 Stage 6 — Progressive Mitigation Escalation Model

When an attack state is verified ($S_{\text{conf}} \ge 70$), the mitigation engine deploys a multi-stage defensive strategy rather than executing a hard drop of all traffic. This helps maintain service availability for legitimate users during traffic bursts.

```
[ Normal State ]
       │
       ▼ (Score >= 40)
[ Level 1 & 2: Log & Alert ] ──► Record metrics; update administration UI.
       │
       ▼ (Score >= 70; Moderate Severity)
[ Level 3: Traffic Rate Limiting ] ──► Enforce maximum packet rates per source.
       │
       ▼ (Score >= 70; High Severity / Persistent)
[ Level 4: Temporary Firewall Block ] ──► Inject drop rules via iptables for 300s.
       │
       ▼ (Repeated Failures / Known Botnet IP)
[ Level 5: Permanent Blacklist ] ──► Persist block to persistent storage layer.

```

* **Level 1 & 2: Logging & Alerting:** Generates telemetry logs containing the attack signature, confidence values, and target ports, while updating the management dashboard.
* **Level 3: Traffic Rate Limiting (Throttling):** Enforces a strict bandwidth ceiling (e.g., maximum 100 packets/sec per source IP). Traffic below this threshold passes through normally, preserving connectivity during sudden usage spikes.
* **Level 4: Temporary Operational Blocking:** Dynamically injects kernel-level firewall rules (using `iptables` or `nftables`) to drop all packets from the offending source IP for a set period (e.g., $\Delta t_{\text{block}} = 300 \text{ seconds}$). An automated background timer clears the rule after the timeout to mitigate false positives.
* **Level 5: Long-Term Blacklisting:** If an IP address repeatedly triggers temporary blocks, the system moves it to a permanent blacklist in persistent storage.
* **Level 6: Structural Whitelisting:** Protects critical infrastructure (such as administrative subnets, core routers, and internal application servers). Traffic from these sources bypasses the heuristic block lists unless clear indicators of host compromise are detected.

---

### 4.3 Stage 7 — Incident Forensics Logging Schema

When a mitigation action is triggered, the pipeline exports a structured forensic log entry for post-incident analysis and heuristic tuning:

```json
{
  "incident_metadata": {
    "timestamp": "2026-06-27T18:07:45.102Z",
    "attack_classification": "Distributed TCP SYN Flood",
    "heuristic_score": 85,
    "rules_triggered": ["PPS_LIMIT_BREACH", "HIGH_SYN_ACK_ASYMMETRY", "LOW_SIZE_VARIANCE"]
  },
  "network_signature": {
    "target_victim_ip": "10.0.0.5",
    "targeted_port": 443,
    "transport_protocol": "TCP",
    "unique_attacker_source_count": 142,
    "aggregated_flow_metrics": {
      "packets_per_second": 4500,
      "bytes_per_second": 270000,
      "average_packet_size_bytes": 60,
      "packet_size_variance": 1.2,
      "source_ip_entropy": 6.8
    }
  },
  "enforced_mitigation": {
    "action_executed": "KERNEL_FIREWALL_TEMPORARY_DROP",
    "target_block_range": "182.54.23.1/32",
    "execution_epoch_start": 1777402065,
    "automated_cleanup_epoch_end": 1777402365
  }
}

```