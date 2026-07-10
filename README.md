# DDoS Detection System

A highly modular, data-driven heuristic detection system for volumetric DDoS attacks (SYN floods, UDP floods, etc.).

## Setup

```bash
# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Running the Pipeline

You can run the entire pipeline end-to-end (discovery -> parsing -> features -> decision engine -> evaluation -> visualizations) using the `main.py` entry point:

```bash
python main.py --run
```

## Project Structure

- `configs/` - Contains weights, thresholds, and path constants.
- `datasets/` - Contains raw PCAPs, parsed CSVs, engineered features, and logs.
- `src/` - The core application logic broken into modules:
  - `preprocessing/` - Finds and parses PCAPs using `tshark`.
  - `feature_engineering/` - Calculates sliding window flow metrics.
  - `decision_engine/` - Applies heuristic rule matrix and scores traffic.
  - `evaluation/` - Validates the accuracy of the model (TP/TN, F1 score).
  - `visualization/` - Generates ROC/KDE plots and confusion matrices.
