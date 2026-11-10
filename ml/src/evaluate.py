"""A6 – Đánh giá mô hình bằng nhãn red team (ground truth của LANL).

Dữ liệu cực kỳ mất cân bằng (vài trăm user-ngày tấn công / hàng trăm nghìn) nên:
  * không dùng accuracy; dùng ROC-AUC, PR-AUC (average precision)
  * precision@k / recall@k: analyst SOC chỉ xem được k cảnh báo đầu mỗi ngày
  * FPR ở ngưỡng cảnh báo: SOC rất sợ false positive (alert fatigue)
"""
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve

from config import REPORTS_DIR

TOP_K = (50, 100, 500, 1000)


def metrics_for(y: np.ndarray, score: np.ndarray, threshold: float) -> dict:
    order = np.argsort(-score)
    out = {
        "roc_auc": float(roc_auc_score(y, score)),
        "pr_auc": float(average_precision_score(y, score)),
        "positives": int(y.sum()), "total": int(len(y)),
    }
    for k in TOP_K:
        hit = y[order[:k]].sum()
        out[f"precision@{k}"] = float(hit / k)
        out[f"recall@{k}"] = float(hit / max(y.sum(), 1))
    pred = score >= threshold
    tp, fp = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
    out.update({
        "threshold": threshold, "alerts": int(pred.sum()), "tp": tp, "fp": fp,
        "recall_at_threshold": tp / max(int(y.sum()), 1),
        "fpr_at_threshold": fp / max(int((y == 0).sum()), 1),
    })
    return out


def evaluate(scores: pd.DataFrame, score_cols, label_col="is_redteam", threshold=0.99,
             name="lanl_test") -> dict:
    y = scores[label_col].astype(int).values
    results = {c: metrics_for(y, scores[c].values, threshold) for c in score_cols}
    (REPORTS_DIR / f"{name}_metrics.json").write_text(json.dumps(results, indent=2),
                                                     encoding="utf-8")
    table = pd.DataFrame(results).T[["roc_auc", "pr_auc", "precision@100", "recall@100",
                                     "recall@1000", "alerts", "recall_at_threshold",
                                     "fpr_at_threshold"]]
    table.to_csv(REPORTS_DIR / f"{name}_metrics.csv")
    print(table.round(4).to_string())
    _plot(y, scores, score_cols, name)
    return results


def _plot(y, scores, score_cols, name):
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))
    for c in score_cols:
        fpr, tpr, _ = roc_curve(y, scores[c])
        p, r, _ = precision_recall_curve(y, scores[c])
        axes[0].plot(fpr, tpr, label=f"{c} (AUC={roc_auc_score(y, scores[c]):.3f})")
        axes[1].plot(r, p, label=f"{c} (AP={average_precision_score(y, scores[c]):.3f})")
    axes[0].plot([0, 1], [0, 1], "k--", lw=0.8)
    axes[0].set(title="ROC", xlabel="False positive rate", ylabel="True positive rate")
    axes[1].set(title="Precision–Recall", xlabel="Recall", ylabel="Precision", yscale="log")
    for ax in axes:
        ax.legend(fontsize=8)
        ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / f"{name}_roc_pr.png", dpi=130)
    plt.close(fig)
