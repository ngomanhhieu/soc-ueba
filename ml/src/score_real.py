"""Chấm điểm log thật (đầu ra của ecs_to_auth.py) và xuất alert vào Elasticsearch.

Hai chế độ:
  local (mặc định) – học baseline ngay trên log thật: N ngày đầu làm baseline
         (thống kê theo user/peer, Isolation Forest, Autoencoder), chấm các cửa sổ sau đó.
         Đây là cách UEBA chạy thực tế: mỗi môi trường có "bình thường" riêng.
  lanl  – dùng nguyên model đã train trên LANL (models/ueba_models.joblib).
         Chỉ để so sánh: môi trường lab khác LANL nhiều nên điểm dễ lệch.

  python src/score_real.py --baseline-days 3
  python src/score_real.py --labels data/raw/attacks.csv --es https://<ip>:9200
  python src/score_real.py --mode lanl

--labels: CSV `user,start,end` (ISO 8601, vd 2026-11-07T14:00:00+07:00) ghi lại các lần
bạn tự tấn công trong lab (hydra brute force SSH, psexec, ...) để đo Precision/Recall.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd

from common import ALL_FEATURES, MODELS, REPORTS, load_df, save_df, save_json
from export_alerts import build_alerts, push_es, validate
from features import build_features
from human_bot import HumanBotClassifier, weak_labels
from models import AEModel, ECDF, IFModel, Prep
from rules import apply_rules
from statistical import StatBaseline

WEIGHTS = {"if": 0.35, "ae": 0.25, "stat": 0.25, "rule": 0.15}


def add_attack_labels(feat: pd.DataFrame, path: str | None, window: int) -> pd.DataFrame:
    feat["label"] = 0
    if not path:
        return feat
    lab = pd.read_csv(path)
    for r in lab.itertuples(index=False):
        t0 = int(pd.Timestamp(r.start).timestamp()) // window
        t1 = int(pd.Timestamp(r.end).timestamp()) // window
        m = (feat.user.str.lower() == str(r.user).lower()) & feat.win.between(t0, t1)
        feat.loc[m, "label"] = 1
    print(f"  nhãn tấn công: {int(feat.label.sum())} cửa sổ từ {len(lab)} dòng trong {path}")
    return feat


def fit_local(base: pd.DataFrame, all_feat: pd.DataFrame):
    """Học baseline trên giai đoạn đầu của chính môi trường này."""
    hum = base[~base.is_machine]
    if len(hum) < 20:
        raise SystemExit(f"Baseline chỉ có {len(hum)} cửa sổ của user người – cần thêm ngày log "
                         "(tăng --baseline-days hoặc thu log lâu hơn).")
    prep = Prep(ALL_FEATURES).fit(hum)
    Xb = prep.transform(hum)
    m = {"prep": prep, "stat": StatBaseline().fit(hum),
         "if": IFModel(n_estimators=300, max_samples=min(256, len(hum))).fit(Xb)}
    if len(hum) >= 200:
        m["ae"] = AEModel(bottleneck=4).fit(Xb)
    y = weak_labels(base)
    if y.notna().any() and y.dropna().nunique() == 2:
        m["human_bot"] = HumanBotClassifier().fit(base)
    elif (MODELS / "ueba_models.joblib").exists():
        m["human_bot"] = joblib.load(MODELS / "ueba_models.joblib")["human_bot"]
    m["weights"] = {k: v for k, v in WEIGHTS.items() if k in m or k in ("stat", "rule")}
    raw_b = raw_scores(m, hum)
    m["ecdf"] = {k: ECDF().fit(v) for k, v in raw_b.items() if k != "rule"}
    m["ecdf"]["combined"] = ECDF().fit(combine(m, raw_b))
    return m


def raw_scores(m, hum):
    st = m["stat"].score(hum)
    X = m["prep"].transform(hum)
    raw = {"stat": st.stat.to_numpy(), "zscore": st.zscore.to_numpy(),
           "rule": apply_rules(hum).rule.to_numpy(), "if": m["if"].score(X)}
    if "ae" in m:
        raw["ae"] = m["ae"].score(X)
    return raw


def combine(m, raw):
    norm = {k: (m["ecdf"][k](v) if "ecdf" in m and k in m["ecdf"] else v) for k, v in raw.items()}
    w = m["weights"]
    return sum(w[k] * norm[k] for k in w if k in norm) / sum(w[k] for k in w if k in norm)


def score(m, feat):
    hum = feat[~feat.is_machine].copy()
    st = m["stat"].score(hum)
    rl = apply_rules(hum)
    raw = raw_scores(m, hum)
    out = hum
    for k in ("if", "ae", "stat", "rule"):
        v = raw.get(k)
        out[f"norm_{k}"] = np.nan if v is None else (m["ecdf"][k](v) if k in m["ecdf"] else v)
    out["score_combined"] = combine(m, raw)
    out["anomaly_score"] = m["ecdf"]["combined"](out["score_combined"])
    out["is_human_prob"] = m["human_bot"].predict_proba(out) if "human_bot" in m else np.nan
    out["top_feature"], out["top_z"], out["peer"] = st.top_feature, st.top_z, st.peer
    out["rule_id"], out["n_rules"] = rl.rule_id, rl.n_rules
    return out


def report(out: pd.DataFrame, thr: float):
    sc = out[out.split == "test"]
    lines = [f"# Kết quả chấm log thật ({datetime.now():%Y-%m-%d %H:%M})", "",
             f"- Cửa sổ chấm: {len(sc):,} | user: {sc.user.nunique()} | ngưỡng alert: {thr}",
             f"- Số alert: {int((sc.anomaly_score >= thr).sum())}", ""]
    if sc.label.sum() > 0:
        from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
        pred = (sc.anomaly_score >= thr).astype(int)
        p, r, f, _ = precision_recall_fscore_support(sc.label, pred, average="binary", zero_division=0)
        lines += ["| Precision | Recall | F1 | ROC-AUC | PR-AUC |", "|---|---|---|---|---|",
                  f"| {p:.3f} | {r:.3f} | {f:.3f} | {roc_auc_score(sc.label, sc.anomaly_score):.3f} "
                  f"| {average_precision_score(sc.label, sc.anomaly_score):.3f} |", ""]
    top = sc.sort_values("anomaly_score", ascending=False).head(15)
    lines += ["| Thời gian (UTC) | User | Điểm | Rule | Feature lệch nhất | Nhãn |",
              "|---|---|---|---|---|---|"]
    for r in top.itertuples():
        t = datetime.fromtimestamp(int(r.ts), timezone.utc).strftime("%Y-%m-%d %H:%M")
        lines.append(f"| {t} | {r.user} | {r.anomaly_score:.4f} | {r.rule_id if isinstance(r.rule_id, str) else ''} | "
                     f"{r.top_feature} | {r.label} |")
    p = REPORTS / "real_report.md"
    p.write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines[:6]))
    print(f"  báo cáo -> {p}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inp", default="real_auth")
    ap.add_argument("--mode", choices=["local", "lanl"], default="local")
    ap.add_argument("--baseline-days", type=int, default=3)
    ap.add_argument("--window", type=int, default=3600)
    ap.add_argument("--tz-offset", type=float, default=7)
    ap.add_argument("--labels", default=None)
    ap.add_argument("--min-score", type=float, default=0.99,
                    help="ngưỡng xuất alert (lab ít user nên thấp hơn LANL)")
    ap.add_argument("--es", default=None, help="đẩy alert vào ES, vd https://<ip>:9200")
    ap.add_argument("--index", default="alerts-ueba")
    a = ap.parse_args()

    df = load_df(a.inp)
    feat = build_features(df, a.window, tz_offset=a.tz_offset)
    feat = add_attack_labels(feat, a.labels, a.window)
    d0 = feat.day.min() + a.baseline_days
    feat["split"] = np.where(feat.day < d0, "train", "test")
    n_tr, n_te = (feat.split == "train").sum(), (feat.split == "test").sum()
    d0_s = datetime.fromtimestamp(int(d0) * 86400, timezone.utc).strftime("%Y-%m-%d")
    print(f"  {len(feat):,} cửa sổ: baseline {n_tr:,} (trước {d0_s}) | chấm {n_te:,}")
    if n_te == 0:
        raise SystemExit("Không còn cửa sổ nào sau baseline – giảm --baseline-days.")

    if a.mode == "lanl":
        m = joblib.load(MODELS / "ueba_models.joblib")
    else:
        m = fit_local(feat[feat.split == "train"], feat)
        joblib.dump(m, MODELS / "ueba_real.joblib")
    out = score(m, feat)
    save_df(out, "scores_real")
    report(out, a.min_score)

    sel = out[(out.split == "test") & (out.anomaly_score >= a.min_score)]
    sel = sel.sort_values("anomaly_score", ascending=False)
    alerts = build_alerts(sel, datetime(1970, 1, 1, tzinfo=timezone.utc))  # ts là epoch UTC thật
    validate(alerts)
    save_json(alerts, REPORTS / "alerts_real.json")
    sev = pd.Series([x["severity"] for x in alerts], dtype=object).value_counts().to_dict()
    print(f"Xuất {len(alerts)} alert -> {REPORTS / 'alerts_real.json'} | severity: {sev}")
    if a.es and alerts:
        push_es(alerts, a.es, a.index)


if __name__ == "__main__":
    main()
