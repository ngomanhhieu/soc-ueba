"""Chạy toàn bộ phần ML trên LANL sau khi đã có feature (features.py):

  người/máy (A5) → phát hiện bất thường chạy ONLINE từng ngày (A3+A4) → đánh giá (A6)
  → MITRE + alerts.json (A7, A8)

Mô hình (chọn trên VALIDATION trong experiments_lanl.py / lanl_online.py, không nhìn test):
  ECOD trên feature thống kê + Isolation Forest trên feature di chuyển ngang, trung bình
  percentile; lịch sử "bình thường" KHÔNG học từ user-ngày đã bị cảnh báo (chống đầu độc
  baseline), feature fan-in máy nguồn không phụ thuộc lịch sử, và độ hiếm có tần suất + suy
  giảm theo thời gian lấy max trong ngày (lanl_rarity.py).
  --ioc-feedback: mô phỏng analyst xác nhận top-K cảnh báo/ngày → máy tấn công thành IOC
  (dùng nhãn red team để mô phỏng analyst – báo cáo tách riêng, không phải "không giám sát").

Chia theo thời gian: ngày 0 chỉ làm lịch sử | train | val | test (ngày 20–29 chưa từng dùng
khi thiết kế feature/mô hình).
Chạy:  python src/run_pipeline.py [--ioc-feedback]
"""
import argparse
import json

import joblib
import pandas as pd

from config import MODELS_DIR, REPORTS_DIR
from evaluate import evaluate
from export_alerts import SCORES_PATH
from features import FEATURE_COLS, OUT_PATH as FEATURES_PATH, available_days, load_base
from human_bot import predict_human_prob, train_human_bot
from lanl_explore_redteam import load_redteam

SCORE_COLS = ["ecod_score", "iforest_lateral_score", "alert_score"]


def day_range(s: str) -> list[int]:
    a, b = (int(x) for x in s.split("-"))
    return list(range(a, b + 1))


def main():
    from lanl_online import run_variant, summarize   # tránh import vòng (lanl_online dùng day_range)

    ap = argparse.ArgumentParser()
    ap.add_argument("--train-days", default="1-7")
    ap.add_argument("--val-days", default="8-19")
    ap.add_argument("--test-days", default="20-29")
    ap.add_argument("--live-days", default="30-57",
                    help="ngày MỚI sau test (không có nhãn red team) – chỉ chấm điểm, không đánh giá")
    ap.add_argument("--threshold", type=float, default=0.99)
    ap.add_argument("--ioc-feedback", action="store_true")
    ap.add_argument("--triage-k", type=int, default=25)
    args = ap.parse_args()
    train_days = day_range(args.train_days)
    split_days = {"train": train_days, "val": day_range(args.val_days),
                  "test": day_range(args.test_days)}
    variant = "quar+fanin+rarity+ioc" if args.ioc_feedback else "quar+fanin+rarity"

    feats = pd.read_parquet(FEATURES_PATH)
    print(f"Feature: {len(feats):,} user-ngày, ngày {feats['day'].min()}–{feats['day'].max()}")

    print("[A5] Bộ phân loại người / máy (nhãn yếu theo tên tài khoản)")
    _, hb_metrics = train_human_bot(feats[feats["day"].isin(train_days)])
    feats["is_human_prob"] = predict_human_prob(feats)

    print(f"[A3+A4] Chấm điểm online từng ngày, biến thể: {variant}")
    # chấm điểm tuần tự từng ngày → thêm ngày "live" phía sau KHÔNG đổi điểm của train/val/test
    days = [d for d in available_days() if d <= max(split_days["test"] + day_range(args.live_days))]
    red = load_redteam()
    red["day"] = red["time"] // 86400
    red_hosts = red.groupby(["user", "day"])["src_comp"].agg(set).to_dict()
    sc = run_variant(variant, days, train_days, {d: load_base(d) for d in days}, red_hosts,
                     args.threshold, args.triage_k)
    joblib.dump({"scorer": sc.attrs["scorer"], "variant": variant, "train_days": train_days,
                 "threshold": args.threshold}, MODELS_DIR / "lanl_online_scorer.joblib")
    sc = sc.rename(columns={"score": "alert_score"})
    sc = sc.merge(feats[["src_user", "day", "is_human_prob"]], on=["src_user", "day"])
    sc["account_type"] = "human"
    sc["split"] = "other"
    for s, d in {**split_days, "live": day_range(args.live_days)}.items():
        sc.loc[sc["day"].isin(d), "split"] = s
    keep = ["src_user", "day", "account_type", "split", "is_redteam", "n_redteam",
            "is_human_prob", *SCORE_COLS, "ioc_hit", "top_reasons", *FEATURE_COLS]
    sc[keep].to_parquet(SCORES_PATH, index=False)
    print(f"Đã lưu điểm → {SCORES_PATH}")

    print("[A6] Đánh giá")
    summary = {"variant": variant, "train_days": args.train_days, "val_days": args.val_days,
               "test_days": args.test_days,
               "human_bot": {k: hb_metrics[k] for k in ("accuracy", "roc_auc", "rows_train",
                                                        "rows_test")}}
    for s in ("val", "test"):
        part = sc[sc["split"] == s]
        evaluate(part, SCORE_COLS, threshold=args.threshold, name=f"lanl_{s}")
        summary[s] = summarize(sc.rename(columns={"alert_score": "score"}), split_days[s],
                               args.threshold)
        rt = part[part["is_redteam"]]
        summary[s]["redteam_mean_is_human_prob"] = float(rt["is_human_prob"].mean())
        summary[s]["normal_mean_is_human_prob"] = float(
            part.loc[~part["is_redteam"], "is_human_prob"].mean())
        print(f"  {s}: ROC={summary[s]['roc_auc']:.3f} PR-AUC={summary[s]['pr_auc']:.3f} "
              f"tài khoản bắt được={summary[s]['accounts_caught']}/{summary[s]['accounts_total']} "
              f"({summary[s]['alerts_per_day']} cảnh báo/ngày)")
    (REPORTS_DIR / "lanl_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("[A7+A8] Xuất alerts.json")
    import export_alerts
    import sys
    sys.argv = ["export_alerts.py", "--threshold", str(args.threshold)]
    export_alerts.main()


if __name__ == "__main__":
    main()
