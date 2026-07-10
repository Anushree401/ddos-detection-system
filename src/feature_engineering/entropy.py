import math
from collections import Counter
# pyrefly: ignore [missing-import]
import numpy as np

def entropy(series):
    if len(series) == 0:
        return 0
    probabilities = series.value_counts(normalize=True)
    return -(probabilities * np.log2(probabilities)).sum()