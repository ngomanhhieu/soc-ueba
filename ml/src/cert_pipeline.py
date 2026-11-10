"""Pipeline phát hiện insider threat trên CERT r4.2 (dùng lại các mô hình của LANL).

thống kê (self + peer theo vai trò LDAP) → Isolation Forest + Autoencoder → ensemble
→ đánh giá bằng nhãn insider (answers/) → alerts_cert.json (đúng schema chung).
Chia theo thời gian: train trước --split-date, test từ --split-date.

Chạy:  python src/cert_pipeline.py --split-date 2010-09-01
"""
import argparse
import json
from datetime import timezone

import jsonschema
import numpy as np
import pandas as pd

from cert_features import (MODEL_COLS as FEATURE_COLS, OUT_PATH as FEATURES_PATH, add_trends,
                           add_windows)
from config import MITRE_PATH, PROCESSED_DIR, REPORTS_DIR, SCHEMA_PATH
from evaluate import evaluate
from sklearn.metrics import average_precision_score
from export_alerts import severity
from models import AnomalyModels, percentile_score
from statistical import self_zscores, statistical_scores

SCORES_PATH = PROCESSED_DIR / "cert_scores.parquet"
ALERTS_PATH = REPORTS_DIR / "alerts_cert.json"
SCORE_COLS = ["stat_score", "iforest_score", "ae_score", "ensemble_score", "if_ae_score"]
SEEDS = (42, 7, 2024)
LOG_COLS = [c for c in FEATURE_COLS if not c.endswith("_hour")]   # mọi cột đếm/kích thước
STAT_COLS = ["logon_offhours", "logon_weekend", "logon_pcs", "usb_n", "usb_offhours", "file_n",
             "file_exe", "file_zip", "email_ext_rcpt", "email_attach", "http_job",
             "http_competitor", "http_rare_max", "http_n_rare", "http_n_new_domain"]

# MITRE cho insider threat: lý do bất thường → technique
CERT_MITRE = [
    (("usb_n", "usb_offhours", "file_n", "file_zip", "file_doc"),
     ("Exfiltration", "T1052.001", "Exfiltration over Physical Medium: Exfiltration over USB")),
    (("http_rare_max", "http_n_rare"),
     ("Exfiltration", "T1567", "Exfiltration Over Web Service")),
    (("file_exe",),
     ("Collection", "T1056.001", "Input Capture: Keylogging")),
    (("http_job", "http_competitor"),
     ("Collection", "T1213", "Data from Information Repositories")),
    (("email_ext_rcpt", "email_attach"),
     ("Exfiltration", "T1048", "Exfiltration Over Alternative Protocol")),
    (("logon_offhours", "logon_weekend", "logon_pcs"),
     ("Defense Evasion / Persistence", "T1078", "Valid Accounts")),
]


def cert_mitre(reasons):
    for keys, (tactic, tid, name) in CERT_MITRE:
        if any(r in keys for r in reasons):
            return {"tactic": tactic, "technique_id": tid, "technique_name": name}
    d = json.loads(MITRE_PATH.read_text(encoding="utf-8"))["default"]
    return dict(d)


def export_alerts(scores, threshold, max_alerts):
    cand = scores[(scores["split"] == "test") & (scores["alert_score"] >= threshold)]
    cand = cand.sort_values("alert_score", ascending=False).head(max_alerts)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    alerts = []
    for i, r in enumerate(cand.itertuples(index=False), start=1):
        reasons = list(r.top_reasons)
        a = {
            "alert_id": f"cert-{r.date:%Y%m%d}-{i:05d}",
            "timestamp": r.date.tz_localize(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if r.date.tzinfo is None else r.date.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "user": r.user, "src_host": None, "dst_host": None, "source": "ml", "rule_id": None,
            "anomaly_score": round(float(r.alert_score), 4), "is_human_prob": None,
            "severity": severity(float(r.alert_score)),
            "mitre": cert_mitre(reasons),
            "features": {**{c: round(float(getattr(r, c)), 3) for c in STAT_COLS},
                         "top_reasons": reasons, "role": r.role, "dataset": "CERT r4.2",
                         "ground_truth_insider": bool(r.is_malicious)},
        }
        jsonschema.validate(a, schema)
        alerts.append(a)
    ALERTS_PATH.write_text(json.dumps(alerts, indent=2, ensure_ascii=False), encoding="utf-8")
    hit = sum(a["features"]["ground_truth_insider"] for a in alerts)
    print(f"Đã xuất {len(alerts)} cảnh báo CERT ({hit} đúng insider) → {ALERTS_PATH}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split-date", default="2010-09-01")
    ap.add_argument("--ae-epochs", type=int, default=30)
    ap.add_argument("--threshold", type=float, default=0.995)
    ap.add_argument("--max-alerts", type=int, default=500)
    ap.add_argument("--warmup-days", type=int, default=30)
    args = ap.parse_args()

    feats = pd.read_parquet(FEATURES_PATH)
    # Tổng 7/30 ngày: kịch bản 2 (lấy dữ liệu dần dần) – thí nghiệm experiments_cert.py
    feats, win_cols = add_windows(feats)
    # + xu hướng 30 ngày so với 60 ngày trước (chọn trên val – experiments_cert.py)
    feats, trend_cols = add_trends(feats)
    base_cols = FEATURE_COLS + win_cols + trend_cols
    log_cols = LOG_COLS + win_cols
    stat_cols = STAT_COLS + [c for c in win_cols if c.startswith("w30_")] + trend_cols
    feats["split"] = np.where(feats["date"] < pd.Timestamp(args.split_date), "train", "test")
    # Những ngày đầu chỉ làm lịch sử (độ hiếm domain, self z-score chưa ổn định) → không học
    warm_end = feats["date"].min() + pd.Timedelta(days=args.warmup_days)
    feats.loc[feats["date"] < warm_end, "split"] = "warmup"
    print(f"CERT: {len(feats):,} user-ngày, {feats['user'].nunique()} user, "
          f"{int(feats['is_malicious'].sum())} user-ngày insider")

    print("[A3] Baseline thống kê (peer group = vai trò LDAP)")
    feats = feats.join(statistical_scores(feats, stat_cols, user_col="user", day_col="day",
                                          peer_col="role")[["stat_score", "top_reasons"]])
    print("[A4] Isolation Forest + Autoencoder (feature thô + độ lệch so với chính user)")
    # Thí nghiệm ablation: thêm self z-score làm đầu vào tăng PR-AUC của AE từ 0.045 → 0.091
    zself = self_zscores(feats, base_cols, user_col="user", day_col="day").clip(-10, 10)
    feats = feats.join(zself)
    model_cols = base_cols + list(zself.columns)

    # Chọn mô hình cảnh báo trên VALIDATION (không nhìn test): train trước val_start,
    # chấm PR-AUC trên [val_start, split_date), chọn điểm tốt nhất, rồi train lại trên cả train.
    val_start = pd.Timestamp(args.split_date) - pd.DateOffset(months=2)
    fit_part = feats[(feats["date"] < val_start) & (feats["split"] == "train")]
    val = feats[(feats["date"] >= val_start) & (feats["split"] == "train")].copy()
    def bagged(fit_df, all_df, is_fit):
        """IF + AE train với nhiều seed rồi lấy trung bình (bagging) – kết quả không phụ thuộc may
        rủi của 1 lần train; thêm if_ae_score = trung bình IF và AE (val không phân biệt rõ 2 mô
        hình – experiments_cert.py, 3 seed, chọn ens_if_ae)."""
        parts, m = [], None
        for s in SEEDS:
            m = AnomalyModels(model_cols, log_cols=log_cols, seed=s).fit(fit_df,
                                                                         ae_epochs=args.ae_epochs)
            parts.append(m.score(all_df))
        sc = sum(parts) / len(parts)
        for c in ("iforest_score", "ae_score"):      # đưa trung bình seed về lại thang percentile
            sc[c] = percentile_score(sc.loc[is_fit, c].values, sc[c].values)
        raw = (sc["iforest_score"].values + sc["ae_score"].values) / 2
        sc["if_ae_score"] = percentile_score(raw[is_fit], raw)
        return sc, m

    fv = pd.concat([fit_part, val])
    sc_v, _ = bagged(fit_part, fv, fv.index.isin(fit_part.index))
    val = val.join(sc_v.loc[val.index])
    val["stat_score"] = percentile_score(fit_part["stat_score"].values, val["stat_score"].values)
    val["ensemble_score"] = val[["stat_score", "iforest_score", "ae_score"]].mean(axis=1)
    val_pr = {c: float(average_precision_score(val["is_malicious"], val[c])) for c in SCORE_COLS}
    best = max(val_pr, key=val_pr.get)
    print(f"    PR-AUC validation ({val_start:%Y-%m-%d} → {args.split_date}): "
          + ", ".join(f"{k}={v:.3f}" for k, v in val_pr.items()) + f" → chọn {best}")

    is_train = (feats["split"] == "train").values
    sc, model = bagged(feats[is_train], feats, is_train)
    model.save("cert")       # lưu mô hình của seed cuối (tham khảo); điểm dùng trung bình 3 seed
    feats = feats.join(sc)
    # đưa stat_score về cùng thang percentile (so với train) để so sánh ngưỡng công bằng
    feats["stat_score"] = percentile_score(feats.loc[is_train, "stat_score"].values,
                                           feats["stat_score"].values)
    ens_raw = (feats["stat_score"].values + feats["iforest_score"].values
               + feats["ae_score"].values) / 3
    feats["ensemble_score"] = percentile_score(ens_raw[is_train], ens_raw)
    feats["alert_score"] = feats[best]
    (REPORTS_DIR / "cert_model_selection.json").write_text(
        json.dumps({"validation_pr_auc": val_pr, "selected": best}, indent=2), encoding="utf-8")
    feats.drop(columns=list(zself.columns)).to_parquet(SCORES_PATH, index=False)

    print("[A6] Đánh giá trên tập TEST (từ", args.split_date, ")")
    test = feats[feats["split"] == "test"]
    evaluate(test, SCORE_COLS, label_col="is_malicious", threshold=args.threshold,
             name="cert_test")
    print("[A6] Mức người dùng: bắt được insider ít nhất 1 lần?")
    summary = {"split_date": args.split_date, "alert_model": best, "user_level": {}}
    ins = test.loc[test["is_malicious"], ["user", "scenario"]].drop_duplicates("user")
    for thr in (0.99, 0.995, 0.999):
        al = test[test["alert_score"] >= thr]
        caught = set(al.loc[al["is_malicious"], "user"])
        summary["user_level"][str(thr)] = {
            "alerts": int(len(al)), "alerts_per_day": round(len(al) / test["date"].nunique(), 2),
            "insiders_caught": len(caught), "insiders_total": int(len(ins)),
            "by_scenario": {int(s): f"{len(set(g['user']) & caught)}/{len(g)}"
                            for s, g in ins.groupby("scenario")},
        }
        print(f"    ngưỡng {thr}: {len(al)} cảnh báo, bắt {len(caught)}/{len(ins)} insider, "
              f"theo kịch bản {summary['user_level'][str(thr)]['by_scenario']}")
    # Ngân sách cố định: analyst xem K cảnh báo cao nhất mỗi ngày
    for k in (2, 5):
        top = test.sort_values("alert_score", ascending=False, kind="stable") \
            .groupby("date").head(k)
        caught = set(top.loc[top["is_malicious"], "user"])
        summary["user_level"][f"top{k}/day"] = {
            "alerts": int(len(top)), "insiders_caught": len(caught),
            "insiders_total": int(len(ins)),
            "by_scenario": {int(s): f"{len(set(g['user']) & caught)}/{len(g)}"
                            for s, g in ins.groupby("scenario")}}
        print(f"    top {k}/ngày: bắt {len(caught)}/{len(ins)} insider, theo kịch bản "
              f"{summary['user_level'][f'top{k}/day']['by_scenario']}")
    (REPORTS_DIR / "cert_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("[A7+A8] Xuất cảnh báo")
    export_alerts(feats, args.threshold, args.max_alerts)


if __name__ == "__main__":
    main()
