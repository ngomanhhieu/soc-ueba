"""A3+A4+A5 – Huấn luyện toàn bộ: thống kê, rule baseline, Isolation Forest,
Autoencoder, LOF, bộ phân loại người/bot; tinh chỉnh trên tập validation;
lưu model và bảng điểm cho evaluate.py / export_alerts.py.

Chia train/val/test THEO THỜI GIAN (không shuffle):
  python src/train.py --train-end-day 15 --val-end-day 22
"""
from __future__ import annotations

import argparse
import itertools
import json

import joblib
import numpy as np
from sklearn.metrics import average_precision_score

from common import ALL_FEATURES, MODELS, load_df, save_df, save_json
from human_bot import HumanBotClassifier
from models import AEModel, ECDF, IFModel, LOFModel, Prep
from rules import apply_rules
from statistical import StatBaseline

DEFAULT_WEIGHTS = {"if": 0.35, "ae": 0.25, "stat": 0.25, "rule": 0.15}


def split_days(feat, train_end, val_end):
    days = np.sort(feat.day.unique())
    if train_end is None:
        train_end = days[int(len(days) * 0.6)]
    if val_end is None:
        val_end = days[int(len(days) * 0.8)]
    split = np.where(feat.day < train_end, "train", np.where(feat.day < val_end, "val", "test"))
    return split, int(train_end), int(val_end)


def pr_auc(y, s):
    return float(average_precision_score(y, s)) if y.sum() > 0 else float("nan")


def tune(Xtr, Xva, yva, quick=False):
    """Chọn tham số theo PR-AUC trên validation (nếu val có nhãn red team)."""
    best = {"if": dict(n_estimators=300, max_samples=256, max_features=1.0), "ae": dict(bottleneck=4)}
    log = []
    if yva.sum() == 0:
        print("  [tune] validation không có cửa sổ red team -> dùng tham số mặc định")
        return best, log
    grid_if = list(itertools.product([200, 400], [256, 1024], [1.0, 0.7]))
    if quick:
        grid_if = grid_if[:2]
    best_s = -1
    for ne, ms, mf in grid_if:
        s = pr_auc(yva, IFModel(ne, min(ms, len(Xtr)), mf).fit(Xtr).score(Xva))
        log.append({"model": "if", "n_estimators": ne, "max_samples": ms, "max_features": mf, "val_pr_auc": s})
        if s > best_s:
            best_s, best["if"] = s, dict(n_estimators=ne, max_samples=ms, max_features=mf)
    best_s = -1
    for b in ([4] if quick else [2, 4, 8]):
        s = pr_auc(yva, AEModel(bottleneck=b).fit(Xtr).score(Xva))
        log.append({"model": "ae", "bottleneck": b, "val_pr_auc": s})
        if s > best_s:
            best_s, best["ae"] = s, dict(bottleneck=b)
    print(f"  [tune] IF={best['if']} | AE={best['ae']}")
    return best, log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp", default="features")
    ap.add_argument("--train-end-day", type=int, default=None)
    ap.add_argument("--val-end-day", type=int, default=None)
    ap.add_argument("--clean-train", action="store_true",
                    help="bỏ cửa sổ red team khỏi train (giả định baseline sạch)")
    ap.add_argument("--no-tune", action="store_true")
    ap.add_argument("--quick", action="store_true", help="grid tinh chỉnh nhỏ (chạy thử)")
    ap.add_argument("--weights", type=json.loads, default=DEFAULT_WEIGHTS)
    a = ap.parse_args()

    feat = load_df(a.inp)
    feat["split"], tr_end, va_end = split_days(feat, a.train_end_day, a.val_end_day)
    hum = feat[~feat.is_machine].copy()  # phát hiện bất thường trên tài khoản người
    for s in ["train", "val", "test"]:
        part = hum[hum.split == s]
        print(f"  {s:5s}: {len(part):>9,} cửa sổ, {part.label.sum():>5} red team, "
              f"{part.user.nunique():,} user")
    if hum.loc[hum.split == "test", "label"].sum() == 0:
        print("  CẢNH BÁO: test không có red team -> chỉnh --train-end-day/--val-end-day")

    tr = hum[hum.split == "train"]
    if a.clean_train:
        tr = tr[tr.label == 0]

    print("[1/5] Baseline thống kê")
    stat = StatBaseline().fit(tr)
    st = stat.score(hum)
    rl = apply_rules(hum)

    print("[2/5] Chuẩn hoá feature + tinh chỉnh")
    prep = Prep(ALL_FEATURES).fit(tr)
    Xtr, Xall = prep.transform(tr), prep.transform(hum)
    va = hum.split == "val"
    params, tune_log = ({"if": {}, "ae": {}}, []) if a.no_tune else \
        tune(Xtr, Xall[va.values], hum.label[va].to_numpy(), a.quick)

    print("[3/5] Isolation Forest / Autoencoder / LOF")
    m_if = IFModel(**params["if"]).fit(Xtr)
    m_ae = AEModel(**params["ae"]).fit(Xtr, verbose=True)
    print(f"    AE backend: {m_ae.backend}")
    m_lof = LOFModel().fit(Xtr)
    raw = {"if": m_if.score(Xall), "ae": m_ae.score(Xall), "lof": m_lof.score(Xall),
           "zscore": st.zscore.to_numpy(), "iqr": st.iqr.to_numpy(), "peer_z": st.peer_z.to_numpy(),
           "stat": st.stat.to_numpy(), "rule": rl.rule.to_numpy()}

    # chuẩn hoá về [0,1] theo train rồi kết hợp có trọng số
    is_tr = (hum.split == "train").to_numpy()
    if a.clean_train:
        is_tr &= (hum.label == 0).to_numpy()
    ecdf = {k: ECDF().fit(v[is_tr]) for k, v in raw.items() if k != "rule"}
    norm = {k: (ecdf[k](v) if k in ecdf else v) for k, v in raw.items()}
    w = a.weights
    comb = sum(w[k] * norm[k] for k in w) / sum(w.values())
    ecdf["combined"] = ECDF().fit(comb[is_tr])

    print("[4/5] Bộ phân loại người thật / bot")
    hb = HumanBotClassifier().fit(feat[feat.split == "train"])
    print(f"    {hb.report}")

    print("[5/5] Lưu kết quả")
    out = hum.copy()
    for k, v in raw.items():
        out[f"score_{k}"] = v
        out[f"norm_{k}"] = norm[k]
    out["score_combined"] = comb
    out["anomaly_score"] = ecdf["combined"](comb)
    out["is_human_prob"] = hb.predict_proba(out)
    out["top_feature"], out["top_z"], out["peer"] = st.top_feature, st.top_z, st.peer
    out["rule_id"], out["n_rules"] = rl.rule_id, rl.n_rules
    p = save_df(out, "scores")

    joblib.dump({"prep": prep, "if": m_if, "ae": m_ae, "lof": m_lof, "stat": stat,
                 "human_bot": hb, "ecdf": ecdf, "weights": w}, MODELS / "ueba_models.joblib")
    save_json({"train_end_day": tr_end, "val_end_day": va_end, "clean_train": a.clean_train,
               "params": params, "weights": w, "tune_log": tune_log, "human_bot": hb.report,
               "features": ALL_FEATURES}, MODELS / "train_config.json")
    print(f"  điểm -> {p}\n  model -> {MODELS / 'ueba_models.joblib'}")


if __name__ == "__main__":
    main()
