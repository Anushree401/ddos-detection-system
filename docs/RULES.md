# Heuristic Rules for DDoS Detection System

This document outlines the heuristic rules and thresholds used by the decision engine to evaluate network traffic windows, calculate the `heuristic_score`, and classify potential DDoS attacks. 

The heuristic engine uses a weighted scoring mechanism based on 6 core rules. The rules are applied deterministically based on data-driven thresholds dynamically calculated from normal traffic baselines.

## 1. Core Heuristic Rules

The final score is a composite of these 6 rules, which are evaluated for each time window. The weights sum to exactly 100.

### Rule 1: Volumetric Load Spike (`packet_rate`)
*   **Description**: Detects overall abnormal spikes in packet volume per second.
*   **Trigger Condition**: `packet_rate > threshold` (Upper trigger)
*   **Weight**: 25
*   **Severity Calculation**: Scales with how far the rate exceeds the threshold, up to a maximum multiplier of 2.0.

### Rule 2: Handshake Asymmetry / SYN Flood (`syn_ack_ratio`)
*   **Description**: Detects imbalances in TCP handshakes (e.g., massive number of SYN packets without corresponding ACKs), indicative of SYN floods.
*   **Trigger Condition**: `syn_ack_ratio > threshold` (Upper trigger)
*   **Weight**: 20
*   **Severity Calculation**: Scales with the ratio exceedance, up to a maximum multiplier of 2.0.

### Rule 3: Volumetric UDP Influx (`udp_rate`)
*   **Description**: Detects abnormal spikes in UDP traffic.
*   **Trigger Condition**: `udp_rate > threshold` (Upper trigger)
*   **Weight**: 15
*   **Severity Calculation**: Scales with the rate exceedance, up to a maximum multiplier of 2.0.

### Rule 4: Payload Structural Rigidity (`packet_size_variance`)
*   **Description**: Detects highly uniform packet sizes. Legitimate traffic typically has varying packet sizes, while automated floods (like botnets) often use identical packet sizes for maximum efficiency.
*   **Trigger Condition**: `packet_size_variance < threshold` (Lower trigger)
*   **Weight**: 10
*   **Severity Calculation**: Inverse severity, scoring higher as the variance drops below the threshold.

### Rule 5: Source Address Dispersion (`unique_src_ips`)
*   **Description**: Detects sudden influxes of traffic from a massive number of unique source IPs, heavily indicating a distributed (DDoS) attack.
*   **Trigger Condition**: `unique_src_ips > threshold` (Upper trigger)
*   **Weight**: 15
*   **Severity Calculation**: Scales with the number of unique IPs above the threshold, up to a maximum multiplier of 2.0.

### Rule 6: Target Port Concentration (`dst_ip_entropy`)
*   **Description**: Detects traffic focused on a small number of target destinations/ports. Low entropy signifies highly concentrated, focused targeting rather than normal, dispersed network behavior.
*   **Trigger Condition**: `dst_ip_entropy < threshold` (Lower trigger)
*   **Weight**: 15
*   **Severity Calculation**: Inverse severity, scoring higher as entropy drops.

---

## 2. Threshold Calibration Methodology

Thresholds are not hardcoded but are strictly data-driven, computed automatically from baseline `NORMAL` traffic:

*   **Upper-bound triggers** (`packet_rate`, `syn_ack_ratio`, `udp_rate`, `unique_src_ips`): Calibrated based on the **95th percentile (p95)** of the normal baseline data.
*   **Lower-bound triggers** (`packet_size_variance`, `dst_ip_entropy`): Calibrated based on the **10th percentile (p10)** of the normal baseline data, ensuring uniformity or high concentration triggers the rules.

## 3. Probability Normalization and Sigmoid Curve

Once the raw score is aggregated:
1.  **Normalization**: The score is normalized using a theoretical `MAX_SCORE` of 100.
2.  **Sigmoid Transformation**: A tuned Sigmoid curve translates the normalized score into an absolute probability (0.0 - 1.0) of an attack.
    *   `Score of 40` ≈ 0.45 Probability (Suspicious Boundary)
    *   `Score of 55` ≈ 0.50 Probability (Midpoint)
    *   `Score of 70` ≈ 0.87 Probability (Attack Boundary)
    *   `Score of 100` ≈ 0.98 Probability (All rules triggered)

## 4. Secondary Attack Classification

Based on which rules are triggered, the engine dynamically classifies the specific type of attack using the following matrix:

| Attack Type Classification | Condition(s) |
| :--- | :--- |
| **`DDOS_DISTRIBUTED`** | `packet_rate` AND `unique_src_ips` rules triggered. |
| **`SYN_FLOOD`** | `packet_rate` AND `syn_ack_ratio` rules triggered. |
| **`UDP_FLOOD`** | `udp_rate` rule triggered. |
| **`ICMP_FLOOD`** | `icmp_rate > (packet_rate * 0.5)` AND `packet_rate > 0`. |
| **`UNKNOWN_ATTACK`** | Any other rule triggered without meeting the specific above conditions. |
| **`NORMAL`** | No rules triggered. |
