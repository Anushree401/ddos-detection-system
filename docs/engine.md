# Decision Engine Architecture

This document explains the heuristic-based decision engine (`src/decision_engine/scorer.py`) used to detect and classify DDoS attacks based on the extracted network features.

## Core Scoring Mechanism

The engine calculates a `heuristic_score` between 0 and 100 for each time window of network traffic. This score determines the likelihood of an attack.

### Weighted Rules System
The score is composed of 6 heavily weighted rules. The total weight sums to 100, allowing the score to read naturally out of 100.

| Feature Evaluated | Assigned Weight | Rule Trigger Condition |
| :--- | :--- | :--- |
| **Packet Rate** | 25 | Upper limit (High volume indicates flood) |
| **SYN/ACK Ratio** | 20 | Upper limit (High ratio indicates SYN flood) |
| **UDP Rate** | 15 | Upper limit (High UDP volume) |
| **Unique Source IPs** | 15 | Upper limit (Highly distributed sources) |
| **Destination IP Entropy** | 15 | Lower limit (Low entropy = highly targeted) |
| **Packet Size Variance** | 10 | Lower limit (Low variance = automated bot traffic) |

### Severity Scaling
When a rule threshold is crossed, the engine doesn't just assign the weight; it scales it based on **severity**. 
*   A mild violation yields a partial weight contribution.
*   An extreme violation can yield up to $2.0\times$ the assigned weight.
*   This means the raw score can occasionally exceed 100 during massive multi-vector attacks, but it is normalized back to a 100-point scale.

## Attack Probability Calculation

Once the raw score is calculated, it is passed through a **Sigmoid function** to generate an `attack_probability` between 0.0 and 1.0.

The Sigmoid is tuned with a steepness of $K=12.0$ and centered at $0.55$ to create distinct classification boundaries:
*   Score of ~40: Probability hits ~0.45 (Suspicious Boundary).
*   Score of ~55: Probability hits ~0.50 (Midpoint).
*   Score of ~70: Probability hits ~0.87 (Attack Boundary).

## Attack Classification

Beyond a simple probability score, the engine identifies the specific attack type by analyzing which rules triggered in the `decision_trace`:
*   `DDOS_DISTRIBUTED`: High packet rate + High source dispersion.
*   `SYN_FLOOD`: High packet rate + High SYN/ACK ratio.
*   `UDP_FLOOD`: High UDP rate threshold crossed.
*   `ICMP_FLOOD`: ICMP traffic dominates the packet rate.
*   `UNKNOWN_ATTACK`: Other anomalies that crossed threshold limits.
*   `NORMAL`: Clean traffic.
