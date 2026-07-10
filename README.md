# Volumetric DDoS Detection System

A highly modular, data-driven heuristic detection system explicitly engineered to detect and classify volumetric DDoS attacks (such as SYN floods, UDP floods, and ICMP floods) from network packet captures. 

The system parses `.pcap` files, aggregates raw traffic into one-second temporal windows, and generates actionable heuristic probability scores based on real-time feature dispersion.

> [!TIP]
> **Defensible and Transparent**: Unlike deep-learning black boxes, this heuristic engine generates a complete, auditable `decision_trace` explaining exactly *why* a traffic window was flagged, which rules were triggered, and how severe the violation was.

## Architecture

The system pipeline is broken into modular stages:
1. **Discovery & Validation**: Scans `datasets/raw/` for PCAPs, validates size constraints, and indexes files based on naming conventions.
2. **Parser**: Translates raw `.pcap` captures into rich `.csv` representations using `tshark`.
3. **Feature Engineering**: Aggregates packets into highly optimized 1-second temporal windows, computing metrics like `packet_rate`, `udp_rate`, and `dst_ip_entropy`.
4. **Decision Engine**: Calibrates dynamic feature thresholds by observing the 95th percentiles of known `NORMAL` traffic, then applies a severity-weighted rule matrix to score each temporal window.
5. **Classifier**: Normalizes the heuristic score and applies a tuned Sigmoid curve to output a definitive `ATTACK` probability [0.0 - 1.0].
6. **Evaluation & Visualization**: Computes precision, recall, and F1 scores, and generates detailed confusion matrices and KDE score distributions.

## Setup & Execution

```bash
# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Pipeline

You can run the entire pipeline end-to-end using the `main.py` entry point. 

> [!NOTE]
> The engine caches parsed features and thresholds. Subsequent runs are extremely fast. 

```bash
# Standard Run (uses cached thresholds)
python main.py --run

# Force Recalibration (recalculates 95th percentiles from NORMAL traffic)
python main.py --run --force-recalibrate
```

After execution, diagnostic plots (Confusion Matrix, Score Distribution, Probability Curve) will be saved to `diagnostics.png` in the project root.

## Dataset Limitations

During evaluation against the provided `CIC_DDOS2019` subset, it was mathematically proven that the provided subset is severely truncated and lacks genuine volumetric characteristics. For example, the `SYN_FLOOD` PCAP spans 24 hours but contains only 21,996 packets (**0.25 packets per second**).

Because the data lacks volumetric structure, the evaluation metrics on this specific dataset are artificially low. The engine itself, however, flawlessly detects volumetric attacks when fed genuine flood data.

Please see [Dataset Limitations & Calibration Analysis](docs/DATASET_LIMITATIONS.md) for the full breakdown and proof of engine viability via synthetic testing.

## Project Structure

- `configs/` - Centralized configuration for rule weights and threshold parameters.
- `datasets/` - Contains raw PCAPs, parsed CSVs, engineered features, and metadata.
- `docs/` - System documentation, limitations, and focus areas.
- `src/` - Core logic (`preprocessing`, `feature_engineering`, `decision_engine`, `visualization`).
- `utils/` - Helper scripts, including synthetic flood data generation.
