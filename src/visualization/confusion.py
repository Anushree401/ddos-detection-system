# pyrefly: ignore [missing-import]
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix
# pyrefly: ignore [missing-import]
import numpy as np

def plot_confusion_matrix(decisions, ax=None):
    if ax is None:
        fig, ax = plt.subplots(figsize=(6, 5))
        
    y_true = decisions["gt_is_attack"].astype(bool)
    y_pred = decisions["pred_is_attack"].astype(bool)

    cm = confusion_matrix(y_true, y_pred, labels=[True, False])

    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues", ax=ax,
        xticklabels=["Flagged Attack", "Flagged Normal"],
        yticklabels=["True Attack", "True Normal"]
    )
    ax.set_title("Detection Confusion Matrix", fontsize=14)
    return ax
