"""Trực quan hoá quá trình train và cách model chấm điểm (cho báo cáo + slide bảo vệ).

  1. *_train_loss.png      – loss train/validation của Autoencoder theo epoch (chỉ CERT)
  2. *_score_dist.png      – phân bố điểm bất thường: bình thường vs độc hại, train vs test
  3. *_feature_importance.png – feature nào liên quan nhất tới điểm cảnh báo
  4. *_user_timeline.png   – điểm theo thời gian của 1 insider/red team user: bị bắt lúc nào?

Chạy:  python src/visualize.py cert   |   python src/visualize.py lanl
"""
import sys

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from config import MODELS_DIR, PROCESSED_DIR, REPORTS_DIR
from features import FEATURE_COLS as LANL_FEATURES

CFG = {
    "cert": {"scores": "cert_scores.parquet", "label": "is_malicious", "user": "user",
             "x": "date", "score": "alert_score", "thr": 0.995, "loss": True,
             "parts": ["stat_score", "iforest_score", "ae_score"]},
    "lanl": {"scores": "lanl_scores.parquet", "label": "is_redteam", "user": "src_user",
             "x": "day", "score": "alert_score", "thr": 0.99, "loss": False,
             "parts": ["ecod_score", "iforest_lateral_score", "alert_score"]},
}


def plot_loss(ds):
    hist = joblib.load(MODELS_DIR / f"{ds}_anomaly.joblib").get("ae_loss_history", [])
    if not hist or not isinstance(hist[0], dict):
        print("  (chưa có lịch sử loss – chạy lại pipeline để ghi)")
        return
    h = pd.DataFrame(hist)
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(h["epoch"], h["train_loss"], "o-", ms=3, label="train loss")
    ax.plot(h["epoch"], h["val_loss"], "s-", ms=3, label="validation loss (10% giữ lại)")
    ax.set(title=f"{ds.upper()} – Autoencoder: lỗi tái tạo (MSE) theo epoch",
           xlabel="epoch", ylabel="MSE")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / f"{ds}_train_loss.png", dpi=130)
    plt.close(fig)
    gap = h["val_loss"].iat[-1] / h["train_loss"].iat[-1]
    print(f"  loss cuối: train={h['train_loss'].iat[-1]:.4f}, val={h['val_loss'].iat[-1]:.4f} "
          f"(val/train={gap:.2f} → {'ổn, không overfit' if gap < 1.3 else 'có dấu hiệu overfit'})")


def plot_score_dist(s, c):
    fig, axes = plt.subplots(1, 3, figsize=(16, 4))
    for ax, col in zip(axes, c["parts"]):
        bins = np.linspace(0, 1, 51)
        for split, style in (("train", "--"), ("test", "-")):
            part = s[s["split"] == split]
            ax.hist(part.loc[~part[c["label"]], col], bins=bins, density=True, histtype="step",
                    ls=style, label=f"bình thường ({split})")
            if part[c["label"]].any():
                ax.hist(part.loc[part[c["label"]], col], bins=bins, density=True,
                        histtype="step", lw=2, ls=style, label=f"độc hại ({split})")
        ax.set(title=col, xlabel="điểm (percentile so với train)", yscale="log")
        ax.legend(fontsize=7)
    fig.suptitle("Phân bố điểm: user-ngày độc hại dồn về phía điểm cao (gần 1) mới là model tốt")
    fig.tight_layout()
    return fig


def plot_importance(ds, s, c):
    """Tương quan giữa từng feature và điểm cảnh báo trên tập test – feature nào 'đẩy' điểm lên."""
    cols = (joblib.load(MODELS_DIR / f"{ds}_anomaly.joblib")["cols"] if ds == "cert"
            else LANL_FEATURES)
    cols = [x for x in cols if x in s.columns]
    test = s[s["split"] == "test"]
    imp = test[cols].corrwith(test[c["score"]], method="spearman").abs().dropna() \
        .sort_values()[-15:]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh(imp.index, imp.values)
    ax.set(title=f"{ds.upper()}: feature liên quan nhất tới điểm cảnh báo (|Spearman|)",
           xlabel="|tương quan hạng|")
    fig.tight_layout()
    return fig


def plot_timeline(s, c):
    bad = s[s[c["label"]] & (s["split"] == "test")]
    if bad.empty:
        return None
    user = bad.groupby(c["user"])[c["score"]].max().sort_values().index[len(bad[c["user"]].unique()) // 2]
    u = s[s[c["user"]] == user].sort_values(c["x"])
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.plot(u[c["x"]], u[c["score"]], lw=1, label="điểm bất thường")
    ax.scatter(u.loc[u[c["label"]], c["x"]], u.loc[u[c["label"]], c["score"]], color="red",
               zorder=3, label="ngày có hành vi độc hại thật")
    ax.axhline(c["thr"], color="gray", ls="--", label="ngưỡng cảnh báo")
    ax.set(title=f"Dòng thời gian của {user}: model có bắt được không?", ylabel=c["score"],
           ylim=(0, 1.02))
    ax.legend(loc="lower left")
    fig.tight_layout()
    return fig


def main():
    ds = sys.argv[1] if len(sys.argv) > 1 else "cert"
    c = CFG[ds]
    s = pd.read_parquet(PROCESSED_DIR / c["scores"])
    print(f"[{ds}] vẽ biểu đồ")
    if c["loss"]:
        plot_loss(ds)
    for name, fig in (("score_dist", plot_score_dist(s, c)),
                      ("feature_importance", plot_importance(ds, s, c)),
                      ("user_timeline", plot_timeline(s, c))):
        if fig is not None:
            fig.savefig(REPORTS_DIR / f"{ds}_{name}.png", dpi=130)
            plt.close(fig)
    print("  →", ", ".join(sorted(p.name for p in REPORTS_DIR.glob(f"{ds}_*.png"))))


if __name__ == "__main__":
    main()
