"""Chỉ số đánh giá và biểu đồ cho Data Mining."""
import matplotlib
matplotlib.use("Agg")  # vẽ ra file, không cần giao diện
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)


def binary_metrics(y_true, y_pred, score=None):
    """Lớp dương = tấn công (1). FPR = tỷ lệ traffic bình thường bị báo nhầm là tấn công."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    out = {"accuracy": accuracy_score(y_true, y_pred),
           "precision_attack": precision_score(y_true, y_pred, zero_division=0),
           "recall_attack": recall_score(y_true, y_pred, zero_division=0),
           "f1_attack": f1_score(y_true, y_pred, zero_division=0),
           "fpr": fp / (fp + tn) if (fp + tn) else np.nan, "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}
    try:
        out["roc_auc"] = roc_auc_score(y_true, score)
        out["pr_auc"] = average_precision_score(y_true, score)
    except ValueError:  # tập test chỉ có 1 lớp
        out["roc_auc"] = out["pr_auc"] = np.nan
    return out


def multiclass_metrics(y_true, y_pred):
    return {"accuracy": accuracy_score(y_true, y_pred),
            "macro_precision": precision_score(y_true, y_pred, average="macro", zero_division=0),
            "macro_recall": recall_score(y_true, y_pred, average="macro", zero_division=0),
            "macro_f1": f1_score(y_true, y_pred, average="macro", zero_division=0),
            "weighted_f1": f1_score(y_true, y_pred, average="weighted", zero_division=0)}


def per_class_report(y_true, y_pred, labels):
    rep = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    df = pd.DataFrame(rep).T
    return df.reset_index().rename(columns={"index": "class"})


def plot_confusion(y_true, y_pred, labels, title, path):
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    norm = cm / np.maximum(cm.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(1.0 + 0.9 * len(labels), 0.8 + 0.8 * len(labels)))
    im = ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("Dự đoán")
    ax.set_ylabel("Thực tế")
    ax.set_title(title)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{cm[i, j]:,}\n({norm[i, j]:.1%})", ha="center", va="center", fontsize=7,
                    color="white" if norm[i, j] > 0.5 else "black")
    fig.colorbar(im, ax=ax, fraction=0.046, label="Tỷ lệ theo hàng")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_importance(series, title, path, top=15):
    s = series.sort_values(ascending=False).head(top)[::-1]
    fig, ax = plt.subplots(figsize=(7, 0.35 * len(s) + 1.2))
    ax.barh(s.index, s.values, color="#3b7dd8")
    ax.set_title(title)
    ax.set_xlabel("Mức quan trọng")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_model_comparison(df, metrics, title, path):
    fig, ax = plt.subplots(figsize=(1.6 * len(df) + 3, 4))
    x = np.arange(len(df))
    w = 0.8 / len(metrics)
    for k, m in enumerate(metrics):
        ax.bar(x + k * w, df[m].astype(float), w, label=m)
    ax.set_xticks(x + w * (len(metrics) - 1) / 2, df["model"])
    ax.set_ylim(0, 1.05)
    ax.set_title(title)
    ax.legend(fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)