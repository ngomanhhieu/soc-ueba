"""A6 – Đánh giá: Precision/Recall/F1, ROC-AUC, PR-AUC, confusion matrix,
so sánh thống kê vs IF vs AE vs LOF vs rule-only vs kết hợp, ablation theo nhóm feature,
và một bộ phân loại có giám sát (Random Forest trên nhãn red team) làm cận trên.

Ngưỡng cảnh báo = percentile điểm trên TRAIN (--alert-quantile), tức không dùng nhãn
-> giống vận hành thật. Cột best_f1 là tham khảo (chọn ngưỡng nhìn nhãn test).

  python src/evaluate.py --alert-quantile 0.995
"""
from __future__ import annotations

import argparse

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.metrics import (average_precision_score, confusion_matrix,  # noqa: E402
                             precision_recall_curve, precision_recall_fscore_support,
                             roc_auc_score, roc_curve)

from common import ALL_FEATURES, FEATURE_GROUPS, MODELS, REPORTS, load_df, load_json  # noqa: E402
from models import IFModel, Prep  # noqa: E402

METHODS = {"zscore": "Z-score (user)", "iqr": "IQR (user)", "peer_z": "Peer group z",
           "stat": "Thống kê tổng hợp", "rule": "Rule-only", "if": "Isolation Forest",
           "ae": "Autoencoder", "lof": "LOF", "combined": "Kết hợp (rule+thống kê+ML)"}


def metrics(y, s, thr):
    pred = (s >= thr).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    pc, rc, _ = precision_recall_curve(y, s)
    f_all = 2 * pc * rc / np.clip(pc + rc, 1e-12, None)
    two = len(np.unique(y)) > 1
    return {"roc_auc": roc_auc_score(y, s) if two else np.nan,
            "pr_auc": average_precision_score(y, s) if two else np.nan,
            "precision": p, "recall": r, "f1": f, "n_alerts": int(pred.sum()),
            "best_f1": float(np.nanmax(f_all)) if two else np.nan}


def _md(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(map(str, cols)) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(str(v) for v in r) + " |" for r in df.itertuples(index=False)]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-quantile", type=float, default=0.995)
    ap.add_argument("--no-ablation", action="store_true")
    a = ap.parse_args()

    df = load_df("scores")
    cfg = load_json(MODELS / "train_config.json")
    tr, te = df[df.split == "train"], df[df.split == "test"]
    y = te.label.to_numpy()
    print(f"Test: {len(te):,} cửa sổ, {y.sum()} red team (tỉ lệ {y.mean():.5f})")
    if y.sum() == 0:
        raise SystemExit("Test không có nhãn dương – chỉnh --train-end-day/--val-end-day ở train.py")

    rows, curves = [], {}
    for k, name in METHODS.items():
        col = "score_combined" if k == "combined" else f"score_{k}"
        s_tr, s_te = tr[col].to_numpy(), te[col].to_numpy()
        thr = 1e-9 if k == "rule" else np.quantile(s_tr, a.alert_quantile)
        rows.append({"method": name, **metrics(y, s_te, thr)})
        curves[name] = s_te

    # cận trên có giám sát (dùng nhãn red team của giai đoạn train)
    if tr.label.sum() > 0:
        rf = RandomForestClassifier(400, min_samples_leaf=2, class_weight="balanced_subsample",
                                    n_jobs=-1, random_state=42)
        rf.fit(tr[ALL_FEATURES], tr.label)
        s_tr = rf.predict_proba(tr[ALL_FEATURES])[:, 1]
        s_te = rf.predict_proba(te[ALL_FEATURES])[:, 1]
        name = "Random Forest (có giám sát)"
        rows.append({"method": name, **metrics(y, s_te, 0.5)})
        curves[name] = s_te

    res = pd.DataFrame(rows).round(4)
    res.to_csv(REPORTS / "metrics.csv", index=False)
    print("\n== Mức cửa sổ user×giờ (test) ==")
    print(res.to_string(index=False))

    # đánh giá mức user: điểm max của user trong giai đoạn test
    ul = te.groupby("user").agg(label=("label", "max"),
                               **{k: (f"score_{k}" if k != "combined" else "score_combined", "max")
                                  for k in METHODS})
    urows = [{"method": n, "roc_auc": roc_auc_score(ul.label, ul[k]),
              "pr_auc": average_precision_score(ul.label, ul[k])}
             for k, n in METHODS.items() if ul.label.nunique() > 1]
    ures = pd.DataFrame(urows).round(4)
    ures.to_csv(REPORTS / "metrics_user_level.csv", index=False)
    print(f"\n== Mức user ({len(ul)} user, {int(ul.label.sum())} bị red team) ==")
    print(ures.to_string(index=False))

    # biểu đồ ROC / PR
    fig, ax = plt.subplots(1, 2, figsize=(13, 5))
    for name, s in curves.items():
        if name in ("Rule-only",):
            continue
        fpr, tpr, _ = roc_curve(y, s)
        pc, rc, _ = precision_recall_curve(y, s)
        ax[0].plot(fpr, tpr, label=name, lw=1.3)
        ax[1].plot(rc, pc, label=name, lw=1.3)
    ax[0].plot([0, 1], [0, 1], "k--", lw=0.8)
    ax[0].set(title="ROC (test)", xlabel="FPR", ylabel="TPR")
    ax[1].set(title="Precision–Recall (test)", xlabel="Recall", ylabel="Precision")
    ax[1].legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(REPORTS / "roc_pr.png", dpi=150)

    thr = np.quantile(tr.score_combined, a.alert_quantile)
    cm = confusion_matrix(y, (te.score_combined >= thr).astype(int))
    fig, axc = plt.subplots(figsize=(4, 4))
    axc.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm):
        axc.text(j, i, f"{v:,}", ha="center", va="center")
    axc.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["bình thường", "cảnh báo"],
            yticklabels=["bình thường", "red team"], title="Confusion matrix – Kết hợp")
    fig.tight_layout()
    fig.savefig(REPORTS / "confusion_combined.png", dpi=150)

    # ablation: bỏ từng nhóm feature, train lại Isolation Forest
    if not a.no_ablation:
        print("\n== Ablation (Isolation Forest, test) ==")
        trc = tr[tr.label == 0] if cfg.get("clean_train") else tr
        p_if = cfg["params"].get("if", {})
        abl = []
        for g in ["(đầy đủ)"] + list(FEATURE_GROUPS):
            feats = ALL_FEATURES if g == "(đầy đủ)" else [f for f in ALL_FEATURES if f not in FEATURE_GROUPS[g]]
            prep = Prep(feats).fit(trc)
            s = IFModel(**p_if).fit(prep.transform(trc)).score(prep.transform(te))
            abl.append({"bỏ nhóm": g, "roc_auc": roc_auc_score(y, s), "pr_auc": average_precision_score(y, s)})
            print(f"  {abl[-1]}")
        abl = pd.DataFrame(abl).round(4)
        abl["delta_pr_auc"] = (abl.pr_auc - abl.pr_auc.iloc[0]).round(4)
        abl.to_csv(REPORTS / "ablation.csv", index=False)

    md = ["# Kết quả đánh giá (tự sinh bởi evaluate.py)", "",
          f"Train < ngày {cfg['train_end_day']}, val < ngày {cfg['val_end_day']}, test còn lại. "
          f"Ngưỡng = percentile {a.alert_quantile} điểm train.", "",
          "## Mức cửa sổ user × giờ", _md(res), "", "## Mức user", _md(ures)]
    if not a.no_ablation:
        md += ["", "## Ablation", _md(abl)]
    (REPORTS / "metrics.md").write_text("\n".join(md), encoding="utf-8")
    print(f"\nĐã lưu bảng + biểu đồ vào {REPORTS}")


if __name__ == "__main__":
    main()
