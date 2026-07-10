import pandas as pd
# pyrefly: ignore [missing-import]
from IPython.display import display

def evaluate_engine(decisions):
    decisions = decisions.copy()
    decisions["gt_is_attack"]   = decisions["ground_truth"] != "NORMAL"
    decisions["pred_is_attack"] = decisions["classification"].isin(["ATTACK", "SUSPICIOUS"])

    tp = int(( decisions["gt_is_attack"] &  decisions["pred_is_attack"]).sum())
    tn = int((~decisions["gt_is_attack"] & ~decisions["pred_is_attack"]).sum())
    fp = int((~decisions["gt_is_attack"] &  decisions["pred_is_attack"]).sum())
    fn = int(( decisions["gt_is_attack"] & ~decisions["pred_is_attack"]).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0 else 0.0
    )

    print("=" * 60)
    print("DECISION ENGINE EVALUATION")
    print("=" * 60)
    print(f"  True Positives  (correctly flagged attacks):  {tp}")
    print(f"  True Negatives  (correctly passed normal):    {tn}")
    print(f"  False Positives (wrong alerts on normal):     {fp}")
    print(f"  False Negatives (missed attacks):             {fn}")
    print()
    print(f"  Precision  : {precision:.3f}")
    print(f"  Recall     : {recall:.3f}")
    print(f"  F1 Score   : {f1:.3f}")
    print()
    print("Probability & score distribution by classification:")
    print(
        decisions.groupby("classification")[
            ["heuristic_score", "normalized_score", "attack_probability"]
        ].describe().round(3)
    )

    return decisions