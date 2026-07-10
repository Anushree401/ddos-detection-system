# pyrefly: ignore [missing-import]
import matplotlib.pyplot as plt
import seaborn as sns

def plot_probability_calibration(decisions, ax=None):
    if ax is None:
        fig, ax = plt.subplots(figsize=(6, 5))
        
    sample_size = min(10000, len(decisions))
    
    sns.scatterplot(
        data=decisions.sample(sample_size, random_state=42), 
        x="heuristic_score", y="attack_probability", hue="gt_is_attack",
        palette={False: "green", True: "red"}, alpha=0.3, ax=ax, legend=False
    )
    ax.set_title("Final Attack Probability Curve", fontsize=14)
    ax.set_xlabel("Heuristic Score")
    ax.set_ylabel("Probability of Attack (0.0 - 1.0)")
    ax.set_xlim(0, 100)
    ax.set_ylim(-0.05, 1.05)
    ax.axhline(0.5, color="grey", linestyle=":")
    return ax

def plot_all_diagnostics(decisions):
    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(1, 3, figsize=(20, 6))
    
    from src.visualization.confusion import plot_confusion_matrix
    from src.visualization.distributions import plot_score_distribution
    
    plot_confusion_matrix(decisions, ax=axes[0])
    plot_score_distribution(decisions, ax=axes[1])
    plot_probability_calibration(decisions, ax=axes[2])
    
    plt.tight_layout()
    plt.savefig("diagnostics.png")
