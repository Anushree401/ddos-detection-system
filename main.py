import argparse
import os
from configs.settings import DATASETS_ROOT, RAW_DIR, FEATURES_DIR, DATASET_INDEX, PARSED_DIR

# Import the core pipeline functions
from src.preprocessing.discovery import scan_datasets
from src.preprocessing.validation import validate_pcaps
from src.preprocessing.parser import parse_pcaps
from src.feature_engineering.extractor import generate_features
from src.decision_engine.rules import compute_thresholds
from src.decision_engine.classifier import run_decision_engine
from src.evaluation.reports import evaluate_engine
from src.visualization.metrics import plot_all_diagnostics

def run_pipeline():
    print("=== 1. Discovery & Validation ===")
    dataset_index = scan_datasets(RAW_DIR)
    dataset_index.to_csv(DATASET_INDEX, index=False)
    print(f"Scanned {len(dataset_index)} files. Saved index to {DATASET_INDEX}")
    
    validation_report = validate_pcaps(RAW_DIR, dataset_index)
    
    print("\n=== 2. Parsing PCAPs ===")
    parse_pcaps(RAW_DIR, dataset_index, validation_report)
    
    print("\n=== 3. Feature Engineering ===")
    generate_features(PARSED_DIR, FEATURES_DIR, dataset_index)
    
    print("\n=== 4. Decision Engine ===")
    thresholds, _ = compute_thresholds(FEATURES_DIR)
    decisions = run_decision_engine(FEATURES_DIR, thresholds)
    
    print("\n=== 5. Evaluation ===")
    decisions = evaluate_engine(decisions)
    
    print("\n=== 6. Visualization ===")
    plot_all_diagnostics(decisions)
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Detection Pipeline")
    parser.add_argument("--run", action="store_true", help="Run the full pipeline")
    args = parser.parse_args()
    
    if args.run:
        run_pipeline()
    else:
        print("Use --run to execute the full pipeline.")
