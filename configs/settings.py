import os

# Project Roots
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Dataset Directories
DATASETS_ROOT = os.path.join(BASE_DIR, "datasets")
RAW_DIR       = os.path.join(DATASETS_ROOT, "raw")
CLEANED_DIR   = os.path.join(DATASETS_ROOT, "cleaned")
PARSED_DIR    = os.path.join(DATASETS_ROOT, "parsed")
FEATURES_DIR  = os.path.join(DATASETS_ROOT, "features")
METADATA_DIR  = os.path.join(DATASETS_ROOT, "metadata")
REPORTS_DIR   = os.path.join(DATASETS_ROOT, "reports")

# File Index
DATASET_INDEX = os.path.join(METADATA_DIR, "dataset_index.csv")

# Supported file extensions for parsing
SUPPORTED_EXTENSIONS = [".pcap", ".pcapng", ".cap"]
