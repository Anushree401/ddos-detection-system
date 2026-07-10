import math
from configs.weights import WEIGHTS
from configs.thresholds import MAX_SCORE, SIGMOID_K, SIGMOID_CENTRE


# Weights must sum to 100 so score reads naturally as a /100 value
WEIGHTS = {
    "packet_rate":          25,
    "syn_ack_ratio":        20,
    "udp_rate":             15,
    "packet_size_variance": 10,
    "unique_src_ips":       15,
    "dst_ip_entropy":       15,
}
assert sum(WEIGHTS.values()) == 100, "Weights must sum to 100"

MAX_SCORE       = 100   # clean reference for normalisation

# Sigmoid tuned on normalised [0,1] input:
#   p(0.40) ≈ 0.45  (suspicious boundary)  ← score of 40
#   p(0.55) ≈ 0.50  (centre / midpoint)
#   p(0.70) ≈ 0.87  (attack boundary)       ← score of 70
#   p(1.00) ≈ 0.98  (all rules triggered)   ← score of 100
SIGMOID_K      = 12.0
SIGMOID_CENTRE = 0.55


def _sigmoid(x):
    return 1.0 / (1.0 + math.exp(-x))


def heuristic_score(row, thresholds, weights=WEIGHTS):
    """
    dict:
        decision_trace      : per-rule breakdown (value, threshold, weight,
                              triggered, severity, contribution)
        heuristic_score     : float 0-200 (approx)
        normalized_score    : float 0.0-2.0  (score / MAX_SCORE)
        attack_probability  : float 0.0-1.0  (sigmoid of normalized_score)
        attack_type_detected: finer attack label
    """

    decision_trace = {}
    score = 0.0

    # Rule 1 – Volumetric Load Spike  (upper trigger)
    v = row["packet_rate"]
    t = thresholds["packet_rate"]
    w = weights["packet_rate"]
    fired = bool(v > t)
    severity = min(v / t, 2.0) if fired and t > 0 else (2.0 if fired else 0.0)
    contribution = w * severity
    decision_trace["packet_rate"] = {
        "value": round(float(v), 4), "threshold": t,
        "weight": w, "triggered": fired, "severity": round(severity, 4),
        "contribution": round(contribution, 4)
    }
    score += contribution

    # Rule 2 – Handshake Asymmetry / SYN Flood  (upper trigger)
    v = row["syn_ack_ratio"]
    t = thresholds["syn_ack_ratio"]
    w = weights["syn_ack_ratio"]
    fired = bool(v > t)
    severity = min(v / t, 2.0) if fired and t > 0 else (2.0 if fired else 0.0)
    contribution = w * severity
    decision_trace["syn_ack_ratio"] = {
        "value": round(float(v), 4), "threshold": t,
        "weight": w, "triggered": fired, "severity": round(severity, 4),
        "contribution": round(contribution, 4)
    }
    score += contribution

    # Rule 3 – Volumetric UDP Influx  (upper trigger)
    v = row["udp_rate"]
    t = thresholds["udp_rate"]
    w = weights["udp_rate"]
    fired = bool(v > t)
    severity = min(v / t, 2.0) if fired and t > 0 else (2.0 if fired else 0.0)
    contribution = w * severity
    decision_trace["udp_rate"] = {
        "value": round(float(v), 4), "threshold": t,
        "weight": w, "triggered": fired, "severity": round(severity, 4),
        "contribution": round(contribution, 4)
    }
    score += contribution

    # Rule 4 – Payload Structural Rigidity  (lower trigger: low variance = automated flood)
    v = row["packet_size_variance"]
    t = thresholds["packet_size_variance"]
    w = weights["packet_size_variance"]
    fired = bool(v < t)
    severity = min(1.0 + (t - v) / t, 2.0) if fired and t > 0 else 0.0
    contribution = w * severity
    decision_trace["packet_size_variance"] = {
        "value": round(float(v), 4), "threshold": t,
        "weight": w, "triggered": fired, "severity": round(severity, 4),
        "contribution": round(contribution, 4)
    }
    score += contribution

    # Rule 5 – Source Address Dispersion  (upper trigger)
    v = row["unique_src_ips"]
    t = thresholds["unique_src_ips"]
    w = weights["unique_src_ips"]
    fired = bool(v > t)
    severity = min(v / t, 2.0) if fired and t > 0 else (2.0 if fired else 0.0)
    contribution = w * severity
    decision_trace["unique_src_ips"] = {
        "value": round(float(v), 4), "threshold": t,
        "weight": w, "triggered": fired, "severity": round(severity, 4),
        "contribution": round(contribution, 4)
    }
    score += contribution

    # Rule 6 – Target Port Concentration  (lower trigger: low entropy = focused targeting)
    v = row["dst_ip_entropy"]
    t = thresholds["dst_ip_entropy"]
    w = weights["dst_ip_entropy"]
    fired = bool(v < t)
    severity = min(1.0 + (t - v) / t, 2.0) if fired and t > 0 else 0.0
    contribution = w * severity
    decision_trace["dst_ip_entropy"] = {
        "value": round(float(v), 4), "threshold": t,
        "weight": w, "triggered": fired, "severity": round(severity, 4),
        "contribution": round(contribution, 4)
    }
    score += contribution

    # ── Probability: normalize first, then sigmoid  (independent path) ────────
    #   Step 1: normalize score to [0, max(MAX_SCORE, actual)]
    normalized_score = score / MAX_SCORE
    #   Step 2: sigmoid — steepness k=12, centre=0.55
    attack_probability = round(
        _sigmoid(SIGMOID_K * (normalized_score - SIGMOID_CENTRE)), 4
    )

    # ── Attack type: secondary classification from decision_trace ────────────
    attack_type_detected = _identify_attack_type(row, decision_trace)

    return {
        "decision_trace":       decision_trace,
        "heuristic_score":      round(score, 4),
        "normalized_score":     round(normalized_score, 4),
        "attack_probability":   attack_probability,
        "attack_type_detected": attack_type_detected,
    }


def _identify_attack_type(row, trace):
    """Secondary classification using decision_trace state."""
    pps_fired  = trace["packet_rate"]["triggered"]
    syn_fired  = trace["syn_ack_ratio"]["triggered"]
    udp_fired  = trace["udp_rate"]["triggered"]
    disp_fired = trace["unique_src_ips"]["triggered"]
    icmp_high  = (
        row.get("icmp_rate", 0) > row.get("packet_rate", 1) * 0.5
        and row.get("packet_rate", 0) > 0
    )

    if pps_fired and disp_fired:
        return "DDOS_DISTRIBUTED"
    elif pps_fired and syn_fired:
        return "SYN_FLOOD"
    elif udp_fired:
        return "UDP_FLOOD"
    elif icmp_high:
        return "ICMP_FLOOD"
    elif any(v["triggered"] for v in trace.values()):
        return "UNKNOWN_ATTACK"
    else:
        return "NORMAL"


print("heuristic_score() and decision_trace ready.")
print(f"Weights: {WEIGHTS}")
print(f"Total weight: {sum(WEIGHTS.values())} / 100")