"""A6 mở rộng cho CERT r4.2 – so sánh phương án với quy trình chọn mô hình KHÔNG nhìn test.

  warm-up (--warmup-days đầu tiên): chỉ làm lịch sử (độ hiếm domain, self z-score chưa ổn định)
  train : [warm-up, --val-start)            học mô hình không giám sát
  val   : [--val-start, --split-date)       chọn phương án theo PR-AUC
  test  : [--split-date, hết)               báo cáo phương án đã chọn
Mỗi phương án dùng mạng nơ-ron/IF được chạy với nhiều seed → báo trung bình ± độ lệch chuẩn.

Hai bộ feature:
  day      – feature theo ngày + self z-score (như cert_pipeline.py)
  day+win  – thêm tổng 7 ngày và 30 ngày của các hành vi chính: nhắm kịch bản 2 (lấy dữ liệu
             dần dần nhiều tuần – mỗi ngày riêng lẻ trông bình thường, cộng dồn mới thấy lạ)

Chạy:  python src/experiments_cert.py
Kết quả: reports/cert_experiments.json, reports/cert_experiments.csv
"""
import argparse
import json

import numpy as np
import pandas as pd

from cert_features import MODEL_COLS, OUT_PATH as FEATURES_PATH, add_trends, add_windows
from cert_pipeline import LOG_COLS, STAT_COLS
from config import REPORTS_DIR
from evaluate import metrics_for
from experiments_lanl import ecod_fit, ecod_score
from models import AnomalyModels, percentile_score, to_matrix
from statistical import self_zscores, statistical_scores

BUDGETS = (2, 5)          # số cảnh báo/ngày analyst xem được (1000 nhân viên)


def score_all(f, model_cols, log_cols, stat_cols, is_fit, seed, ae_epochs):
    out = pd.DataFrame(index=f.index)
    st = statistical_scores(f, stat_cols, user_col="user", day_col="day", peer_col="role")
    out["stat"] = percentile_score(st.loc[is_fit, "stat_score"].values, st["stat_score"].values)
    X = to_matrix(f, stat_cols, log_cols=stat_cols)
    raw = ecod_score(ecod_fit(X[is_fit]), X)
    out["ecod"] = percentile_score(raw[is_fit], raw)
    m = AnomalyModels(model_cols, log_cols=log_cols, seed=seed).fit(f[is_fit],
                                                                   ae_epochs=ae_epochs)
    out = out.join(m.score(f).rename(columns={"iforest_score": "iforest", "ae_score": "ae"}))
    for name, cols in [("ens_mean", ["stat", "iforest", "ae"]), ("ens_ecod_ae", ["ecod", "ae"]),
                       ("ens_all", ["stat", "ecod", "iforest", "ae"]),
                       # val không phân biệt được IF và AE (đổi qua lại giữa các lần chạy) →
                       # lấy trung bình 2 mô hình mạnh nhất thay vì chọn 1
                       ("ens_if_ae", ["iforest", "ae"])]:
        raw = out[cols].mean(axis=1).values
        out[name] = percentile_score(raw[is_fit], raw)
    # Chuẩn hoá theo CHÍNH USER: điểm hôm nay trừ trung vị điểm 30 ngày TRƯỚC đó của user (không
    # gồm hôm nay) – giảm các tài khoản "lúc nào cũng bất thường" chiếm chỗ trong top-K.
    tmp = f[["user", "date"]].join(out[NORM_BASE]).sort_values(["user", "date"])
    med = (tmp.set_index("date").groupby("user")[NORM_BASE]
           .rolling("30D", closed="left").median().reset_index(level=0, drop=True))
    med.index = tmp.index
    for c in NORM_BASE:
        raw = out[c].values - med[c].reindex(f.index).fillna(0.5).values
        out[f"{c}_selfnorm"] = percentile_score(raw[is_fit], raw)
    # Làm mượt theo thời gian: trung bình điểm 7 ngày gần nhất của user (gồm hôm nay) – bất
    # thường KÉO DÀI (kịch bản 2) nổi lên, đột biến 1 ngày do ngẫu nhiên bị kéo xuống.
    # Cộng thêm điểm hôm nay để không làm mất đột biến thật (kịch bản 1, 3).
    tmp = f[["user", "date"]].join(out[SMOOTH_BASE]).sort_values(["user", "date"])
    sm = (tmp.set_index("date").groupby("user")[SMOOTH_BASE].rolling("7D").mean()
          .reset_index(level=0, drop=True))
    sm.index = tmp.index
    for c in SMOOTH_BASE:
        raw = (sm[c].reindex(f.index).values + out[c].values) / 2
        out[f"{c}_sm7"] = percentile_score(raw[is_fit], raw)
    return out


SMOOTH_BASE = ["iforest", "ae", "ens_mean"]
NORM_BASE = ["iforest", "ae", "ens_if_ae"]
CANDS = ["stat", "ecod", "iforest", "ae", "ens_mean", "ens_ecod_ae", "ens_all", "ens_if_ae",
         *[f"{c}_sm7" for c in SMOOTH_BASE], *[f"{c}_selfnorm" for c in NORM_BASE]]


def user_level(part, score, k_list, ins):
    """Insider bị bắt nếu có ≥1 user-ngày độc hại lọt top-K cảnh báo của ngày đó."""
    res = {}
    for k in k_list:
        top = part.assign(s=score).sort_values("s", ascending=False, kind="stable") \
            .groupby("date").head(k)
        caught = set(top.loc[top["is_malicious"], "user"])
        res[f"insiders@{k}/day"] = len(caught & set(ins["user"]))
        res[f"by_scenario@{k}/day"] = {int(s): f"{len(set(g['user']) & caught)}/{len(g)}"
                                       for s, g in ins.groupby("scenario")}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--warmup-days", type=int, default=30)
    ap.add_argument("--val-start", default="2010-07-01")
    ap.add_argument("--split-date", default="2010-09-01")
    ap.add_argument("--seeds", type=int, nargs="+", default=[42, 7, 2024])
    ap.add_argument("--ae-epochs", type=int, default=30)
    ap.add_argument("--only", nargs="*", default=None, help="chỉ chạy các bộ feature này")
    args = ap.parse_args()

    feats = pd.read_parquet(FEATURES_PATH)
    feats, win_cols = add_windows(feats)
    feats, trend_cols = add_trends(feats)
    t0 = feats["date"].min() + pd.Timedelta(days=args.warmup_days)
    vs, sp = pd.Timestamp(args.val_start), pd.Timestamp(args.split_date)
    feats["split"] = np.select([feats["date"] < t0, feats["date"] < vs, feats["date"] < sp],
                               ["warmup", "train", "val"], "test")
    print(feats.groupby("split")["is_malicious"].agg(["size", "sum"]).to_string())

    results = {}
    for fs_name, base_cols in [("day", MODEL_COLS), ("day+win", MODEL_COLS + win_cols),
                               ("day+win+trend", MODEL_COLS + win_cols + trend_cols)]:
        if args.only and fs_name not in args.only:
            continue
        zself = self_zscores(feats, base_cols, user_col="user", day_col="day").clip(-10, 10)
        f = feats.join(zself)
        model_cols = base_cols + list(zself.columns)
        log_cols = [c for c in base_cols if not c.endswith("_hour") and not c.startswith("trend_")]
        stat_cols = STAT_COLS + ([c for c in win_cols if c.startswith("w30_")]
                                 if fs_name != "day" else [])             + (trend_cols if fs_name == "day+win+trend" else [])
        is_fit = (f["split"] == "train").values
        for seed in args.seeds:
            print(f"[{fs_name}] seed {seed}")
            sc = score_all(f, model_cols, log_cols, stat_cols, is_fit, seed, args.ae_epochs)
            for split in ("val", "test"):
                part = f[f["split"] == split]
                y = part["is_malicious"].astype(int).values
                ins = part.loc[part["is_malicious"], ["user", "scenario"]].drop_duplicates("user")
                for c in CANDS:
                    s = sc.loc[part.index, c].values
                    r = metrics_for(y, s, 0.995)
                    r.update(user_level(part, s, BUDGETS, ins))
                    results.setdefault(fs_name, {}).setdefault(split, {}) \
                        .setdefault(c, []).append(r)

    rows = []
    for fs_name, by_split in results.items():
        for split, by_c in by_split.items():
            for c, runs in by_c.items():
                row = {"features": fs_name, "split": split, "method": c}
                for key in ("roc_auc", "pr_auc", "precision@100", "insiders@2/day",
                            "insiders@5/day"):
                    v = np.array([r[key] for r in runs], dtype=float)
                    row[key] = v.mean()
                    row[key + "_std"] = v.std()
                row["by_scenario@5/day"] = runs[0]["by_scenario@5/day"]
                rows.append(row)
    table = pd.DataFrame(rows)
    val = table[table["split"] == "val"]
    best = val.loc[val["pr_auc"].idxmax(), ["features", "method"]].to_dict()
    print(f"\n→ Chọn trên VAL theo PR-AUC: {best}")
    table.to_csv(REPORTS_DIR / "cert_experiments.csv", index=False)
    (REPORTS_DIR / "cert_experiments.json").write_text(
        json.dumps({"selected_on_val": best, "table": rows}, indent=2, default=str),
        encoding="utf-8")
    show = ["features", "split", "method", "roc_auc", "pr_auc", "pr_auc_std", "precision@100",
            "insiders@2/day", "insiders@5/day", "by_scenario@5/day"]
    print(table[show].round(3).to_string(index=False))


if __name__ == "__main__":
    main()
