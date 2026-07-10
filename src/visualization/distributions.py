# pyrefly: ignore [missing-import]
import matplotlib.pyplot as plt
import seaborn as sns

def plot_score_distribution(decisions, ax=None):
    if ax is None:
        fig, ax = plt.subplots(figsize=(8, 6))
        
    sns.kdeplot(
        data=decisions, x="heuristic_score", hue="gt_is_attack", 
        fill=True, common_norm=False, palette={False: "green", True: "red"},
        ax=ax, alpha=0.5
    )
    ax.axvline(40, color="orange", linestyle="--", label="SUSPICIOUS Threshold (40)")
    ax.axvline(70, color="darkred", linestyle="--", label="ATTACK Threshold (70)")

    handles, labels = ax.get_legend_handles_labels()
    new_labels = ["Attack Traffic" if l == "True" else "Normal Traffic" if l == "False" else l for l in labels]
    ax.legend(handles, new_labels, title="Ground Truth", loc="upper right")

    ax.set_title("Heuristic Score Distribution", fontsize=14)
    ax.set_xlabel("Heuristic Score (0-100)")
    ax.set_ylabel("Density")
    ax.set_xlim(0, 100)
    return ax
