# Video Presentation Baseline: Project Structure Walkthrough

*Use this document as a script/baseline for presenting the system architecture in a video presentation, mapping the conceptual flow to the actual files and folders in the repository.*

---

## 1. Introduction to the Repository

"Welcome to the DDoS Detection System. To understand how the system identifies malicious traffic, we need to look at how the data flows through our project structure, starting from raw network captures to a final classification."

*   **Point to `/datasets/`**: "This is where our raw network traffic captures (PCAPs) or parsed CSVs live. We have both normal traffic and various DDoS attack vectors."
*   **Point to `main.py`**: "This is the primary orchestrator that triggers the entire pipeline."

---

## 2. Phase 1: Feature Extraction

"We can't analyze packets one by one; we need to aggregate them. That happens here in the source directory."

*   **Open `/src/feature_engineering/`**: "This module handles the heavy lifting."
*   **Highlight `extractor.py`**: "This script groups the raw packets into 1-second time windows. It extracts volume metrics, protocol distributions, and statistical variances."
*   **Highlight `entropy.py`**: "It also calls this script to calculate the Shannon entropy of IP addresses, which is crucial for identifying highly distributed botnets."

---

## 3. Phase 2: The Core Decision Engine

"Once we have windowed features, they are passed into our detection core."

*   **Open `/src/decision_engine/`**: "This is the brain of the operation."
*   **Highlight `scorer.py`**: "This script applies a heuristic algorithm. It evaluates the extracted features against 6 weighted rules. For example, a spike in packet rate mixed with high source IP dispersion heavily increases the score."
*   **Highlight `classifier.py` and `attack_identifier.py`**: "Based on which specific rules were triggered, these scripts classify the exact nature of the attack—whether it's a TCP SYN flood or a volumetric UDP attack."
*   **Open `/configs/`**: "The weights and thresholds used by the scorer aren't hardcoded; they are centrally managed here so they can be easily tuned."

---

## 4. Phase 3: Evaluation and Output

"Finally, we need to prove that the engine works."

*   **Open `/src/visualization/`**: "This directory contains our graphing tools."
*   **Highlight `distributions.py` and `confusion.py`**: "These scripts generate Kernel Density plots and Confusion Matrices to visually demonstrate the engine's accuracy."
*   **Point to `diagnostics.png`**: "The final output is compiled into diagnostic images like this one, providing an immediate visual health check of the detection system against the dataset."

---

## Conclusion
"By structuring the project modularly—separating extraction, decision making, and evaluation—we ensure the system is both highly tunable and easy to expand with new attack vectors in the future."
