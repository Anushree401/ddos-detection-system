# Feature Engineering for DDoS Detection

This document outlines the features extracted from network traffic for the purpose of DDoS (Distributed Denial of Service) detection. Features are calculated over a fixed time window $T$ (currently configured as $T = 1.0$ seconds). 

Let $N$ be the total number of packets in the given time window, and let $P$ represent the set of packets in that window.

---

## 1. Volume and Rate Features

Volume-based features help identify volumetric attacks, such as UDP or ICMP floods, which aim to overwhelm the target's bandwidth or processing capacity.

### Packet Rate (`packet_rate`)
* **What**: The number of packets observed per second.
* **Why**: An unusually high packet rate is a primary indicator of a volumetric attack.
* **Math**: 
  $$ R_p = \frac{N}{T} $$
  *(Since $T=1.0$, this is simply equivalent to the packet count $N$)*

### Byte Rate (`byte_rate`)
* **What**: The total number of bytes transferred per second.
* **Why**: Along with packet rate, byte rate helps measure the bandwidth consumed by an attack. Some attacks use a low number of large packets, while others use a huge number of small packets.
* **Math**: 
  $$ R_b = \frac{1}{T} \sum_{i=1}^{N} L_i $$
  where $L_i$ is the length (in bytes) of the $i$-th packet.

---

## 2. Packet Size Features

Analyzing packet sizes helps identify attacks that use highly uniform packets (e.g., botnets running simple scripts) versus legitimate, varied traffic.

### Average Packet Size (`avg_packet_size`)
* **What**: The mean length of packets in the time window.
* **Why**: Certain attacks (like SYN floods) use very small packets, while amplification attacks use large packets. A sudden shift in the average packet size indicates a potential anomaly.
* **Math**: 
  $$ \mu_L = \frac{1}{N} \sum_{i=1}^{N} L_i $$

### Packet Size Variance (`packet_size_variance`)
* **What**: The variance (spread) of packet lengths around the mean.
* **Why**: Legitimate traffic consists of various packet sizes (small ACKs, large data payloads). Automated attacks often generate packets of identical size, leading to a variance close to 0.
* **Math**: 
  $$ \sigma_L^2 = \frac{1}{N} \sum_{i=1}^{N} (L_i - \mu_L)^2 $$

---

## 3. TCP Flag Features

These features specifically target stateful exhaustion attacks, such as TCP SYN floods.

### SYN Rate (`syn_rate`) & ACK Rate (`ack_rate`)
* **What**: The number of packets per second with the SYN or ACK flags set.
* **Why**: A SYN flood aims to exhaust server resources by sending continuous SYN requests without completing the TCP handshake.
* **Math**: 
  $$ R_{SYN} = \frac{N_{SYN}}{T}, \quad R_{ACK} = \frac{N_{ACK}}{T} $$

### SYN/ACK Ratio (`syn_ack_ratio`)
* **What**: The ratio of SYN packets to ACK packets.
* **Why**: In normal TCP traffic, the number of SYN and ACK packets should be somewhat balanced as connections are opened and data is transferred. An extreme spike in this ratio strongly indicates a SYN flood attack.
* **Math**: 
  $$ \text{Ratio} = \frac{N_{SYN}}{\max(N_{ACK}, 1)} $$

---

## 4. Protocol Specific Features

### UDP Rate (`udp_rate`) & ICMP Rate (`icmp_rate`)
* **What**: The number of UDP or ICMP packets observed per second.
* **Why**: Categorizes the type of volumetric attack (e.g., UDP Flood, ICMP Ping Flood). Sudden spikes in non-TCP traffic are highly suspicious if the server primarily serves TCP traffic (like HTTP/HTTPS).
* **Math**: 
  $$ R_{UDP} = \frac{N_{UDP}}{T}, \quad R_{ICMP} = \frac{N_{ICMP}}{T} $$

---

## 5. IP Address Features

These features help analyze the distribution of sources and targets, crucial for differentiating between legitimate traffic bursts (flash crowds) and distributed attacks (DDoS).

### Unique Source/Destination IPs (`unique_src_ips`, `unique_dst_ips`)
* **What**: The absolute count of unique source and destination IP addresses.
* **Why**: A high number of unique source IPs indicates a highly distributed botnet or spoofed source addresses. A low number of unique destination IPs means a specific target is being isolated.

### Source IP Entropy (`src_ip_entropy`)
* **What**: The Shannon entropy of the source IP addresses.
* **Why**: Measures the randomness or dispersion of source IPs. High entropy means traffic is coming from a very diverse set of IPs (typical of DDoS with spoofed IPs). Low entropy means traffic is dominated by a few sources.
* **Math**: 
  $$ H(S) = - \sum_{s \in S} P(s) \log_2 P(s) $$
  Where $S$ is the set of unique source IPs, and $P(s)$ is the probability (relative frequency) of encountering IP $s$ in the window.

### Destination IP Entropy (`dst_ip_entropy`)
* **What**: The Shannon entropy of the destination IP addresses.
* **Why**: Measures the dispersion of target IPs. In a targeted DDoS attack against a single server, the destination IP entropy drops significantly (approaching 0) because all malicious traffic is directed at one IP.
* **Math**: 
  $$ H(D) = - \sum_{d \in D} P(d) \log_2 P(d) $$
  Where $D$ is the set of unique destination IPs, and $P(d)$ is the relative frequency of IP $d$.

---

## 6. Timing Features

### Mean Interarrival Time (`mean_interarrival`)
* **What**: The average time difference between consecutive packets in the window.
* **Why**: During an attack, the network is flooded with packets arriving much closer together than in normal operations, causing the interarrival time to drop drastically.
* **Math**: 
  Given timestamps $t_1, t_2, \dots, t_N$ sorted in ascending order:
  $$ \mu_{\Delta t} = \frac{1}{N-1} \sum_{i=2}^{N} (t_i - t_{i-1}) $$
