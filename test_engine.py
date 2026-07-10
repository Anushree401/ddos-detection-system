from configs.settings import FEATURES_DIR
from src.decision_engine.rules import compute_thresholds, compute_score_bands
from src.decision_engine.classifier import compute_scores, classify
from src.evaluation.reports import evaluate_engine

print("\n=== 4. Decision Engine ===")
thresholds, all_features = compute_thresholds(FEATURES_DIR, force_recalibrate=True)

print("\n[Scoring Windows]")
scores_df = compute_scores(FEATURES_DIR, thresholds)

print("\n[Computing Score Bands]")
band_suspicious, band_attack = compute_score_bands(scores_df, force_recalibrate=True)

print("\n[Classifying Windows]")
decisions = classify(scores_df, band_suspicious, band_attack)

print("\n=== 5. Evaluation ===")
decisions = evaluate_engine(decisions)
