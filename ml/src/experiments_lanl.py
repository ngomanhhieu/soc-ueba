"""A6 mở rộng – So sánh nhiều phương án phát hiện bất thường trên LANL với quy trình chọn
mô hình KHÔNG nhìn test:

  train (--train-days)  : học mô hình không giám sát (không dùng nhãn)
  val   (--val-days)    : so sánh phương án, chọn cái tốt nhất theo PR-AUC
  test  (--test-days)   : chỉ báo cáo con số của phương án đã chọn (+ bảng đầy đủ để tham khảo)

Các phương án:
  stat            – baseline thống kê self + peer z-score (statistical.py)
  ecod            – ECOD (Li et al. 2022): tổng -log xác suất đuôi phải từng feature, không tham số
  iforest / ae    – Isolation Forest / Autoencoder trên toàn bộ feature + self z-score
  iforest_lateral – Isolation Forest chỉ trên nhóm feature di chuyển ngang / mới lạ
  ens_mean        – trung bình percentile (stat, iforest, ae) – phương án cũ
  ens_max         – max percentile: chỉ cần 1 góc nhìn thấy lạ là cảnh báo
  ens_ecod_stat   – trung bình percentile (ecod, stat)
Tham chiếu "có phản hồi của analyst" (bán giám sát, KHÔNG dùng để chọn): HistGradientBoosting
học nhãn red team ở tập val rồi chấm test – cho biết trần hiệu năng nếu SOC gắn nhãn lại.

Chạy:  python src/experiments_lanl.py --train-days 1-7 --val-days 8-19 --test-days 20-29
Kết quả: reports/lanl_experiments.json, reports/lanl_experiments.csv
"""
import argparse
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

from config import REPORTS_DIR
from evaluate import metrics_for
from features import MODEL_COLS, OUT_PATH as FEATURES_PATH
from human_bot import predict_human_prob, train_human_bot
from models import SEED, AnomalyModels, percentile_score, to_matrix
from run_pipeline import day_range
from statistical import STAT_COLS, self_zscores, statistical_scores

NEW_EDGE_COLS = ["n_new_edge", "n_new_edge_src_new"]
LATERAL_COLS = ["n_src_comp", "n_dst_comp", "n_dst_user", "n_new_dst_comp", "new_dst_ratio",
                "n_new_src_comp", "n_new_src_events", "new_src_ntlm_events", "new_src_max_fanin",
                "ntlm_ratio", "remote_ratio", *NEW_EDGE_COLS]
BUDGETS = (10, 25, 50)


def ecod_fit(X: np.ndarray):
    return np.sort(X, axis=0)


def ecod_score(ref: np.ndarray, X: np.ndarray) -> np.ndarray:
    """Xác suất đuôi phải P(train ≥ x) cho từng feature (làm mượt +1), cộng -log lại."""
    n = len(ref)
    s = np.zeros(len(X))
    for j in range(X.shape[1]):
        ge = n - np.searchsorted(ref[:, j], X[:, j], side="left")
        s += -np.log((ge + 1) / (n + 1))
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-days", default="1-7")
    ap.add_argument("--val-days", default="8-19")
    ap.add_argument("--test-days", default="20-29")
    ap.add_argument("--ae-epochs", type=int, default=30)
    ap.add_argument("--threshold", type=float, default=0.99)
    args = ap.parse_args()
    days = {k: day_range(getattr(args, f"{k}_days")) for k in ("train", "val", "test")}

    feats = pd.read_parquet(FEATURES_PATH)
    model_cols = [c for c in MODEL_COLS if c in feats]
    lateral = [c for c in LATERAL_COLS if c in feats]
    stat_cols = [c for c in STAT_COLS + NEW_EDGE_COLS if c in feats]
    h = feats[feats["account_type"] == "human"].copy()
    h["split"] = "other"
    for k, d in days.items():
        h.loc[h["day"].isin(d), "split"] = k
    have = h.groupby("split")["is_redteam"].agg(["size", "sum"])
    print("Số user-ngày / user-ngày red team theo tập:\n", have.to_string())

    h = h.join(statistical_scores(h, stat_cols)[["stat_score"]])
    zself = self_zscores(h, model_cols).clip(-10, 10)
    h = h.join(zself)
    is_tr = (h["split"] == "train").values
    tr = h[is_tr]

    print("Huấn luyện IF + AE (toàn bộ feature)...")
    m = AnomalyModels(model_cols + list(zself.columns)).fit(tr, ae_epochs=args.ae_epochs)
    h = h.join(m.score(h).rename(columns={"iforest_score": "iforest", "ae_score": "ae"}))

    print("Isolation Forest trên nhóm feature di chuyển ngang:", lateral)
    Xl = to_matrix(h, lateral)
    ifl = IsolationForest(n_estimators=300, max_samples=4096, random_state=SEED, n_jobs=-1) \
        .fit(Xl[is_tr])
    raw = -ifl.score_samples(Xl)
    h["iforest_lateral"] = percentile_score(raw[is_tr], raw)

    print("ECOD...")
    Xe = to_matrix(h, stat_cols)
    raw = ecod_score(ecod_fit(Xe[is_tr]), Xe)
    h["ecod"] = percentile_score(raw[is_tr], raw)

    print("Người/máy: is_human_prob tuyệt đối và độ tụt so với thói quen của chính user...")
    train_human_bot(feats[feats["day"].isin(days["train"])])
    h["human_low"] = 1 - predict_human_prob(h)
    hs = h.sort_values(["src_user", "day"])
    prev = hs.groupby("src_user")["human_low"].transform(
        lambda s: s.shift().expanding().mean())
    raw = (hs["human_low"] - prev).fillna(0).reindex(h.index).values
    h["human_drift"] = percentile_score(raw[is_tr], raw)

    h["stat"] = percentile_score(h.loc[is_tr, "stat_score"].values, h["stat_score"].values)
    for name, cols, how in [("ens_mean", ["stat", "iforest", "ae"], "mean"),
                            ("ens_max", ["stat", "iforest", "ae"], "max"),
                            ("ens_ecod_stat", ["ecod", "stat"], "mean"),
                            ("ens_ecod_lateral", ["ecod", "iforest_lateral"], "mean")]:
        raw = getattr(h[cols], how)(axis=1).values
        h[name] = percentile_score(raw[is_tr], raw)

    cands = ["stat", "ecod", "iforest", "ae", "iforest_lateral", "ens_mean", "ens_max",
             "ens_ecod_stat", "ens_ecod_lateral", "human_low", "human_drift"]
    results = {}
    for split in ("val", "test"):
        part = h[h["split"] == split]
        if part["is_redteam"].sum() == 0:
            print(f"Tập {split} không có red team → bỏ qua")
            continue
        y = part["is_redteam"].astype(int).values
        results[split] = {c: metrics_for(y, part[c].values, args.threshold) for c in cands}
        results[split]["_n"] = {"user_days": int(len(part)), "redteam": int(y.sum()),
                                "accounts": int(part.loc[part["is_redteam"], "src_user"]
                                                .nunique())}
        # mức tài khoản: bắt được tài khoản red team ít nhất 1 lần trong tập
        rt_users = set(part.loc[part["is_redteam"], "src_user"])
        for c in cands:
            al = part[part[c] >= args.threshold]
            caught = set(al.loc[al["is_redteam"], "src_user"])
            results[split][c]["accounts_caught"] = len(caught & rt_users)
            results[split][c]["alerts_per_day"] = round(len(al) / part["day"].nunique(), 1)
            # so sánh công bằng: cùng ngân sách K cảnh báo/ngày (analyst chỉ xem được K cái)
            for k in BUDGETS:
                top = part.sort_values(c, ascending=False, kind="stable").groupby("day").head(k)
                results[split][c][f"accounts@{k}/day"] = len(
                    set(top.loc[top["is_redteam"], "src_user"]) & rt_users)

    best = max(cands, key=lambda c: results["val"][c]["pr_auc"])
    results["selected_on_val"] = best
    print(f"\n→ Chọn trên VAL theo PR-AUC: {best}")

    if "test" in results:
        # tham chiếu bán giám sát: học nhãn red team ở val, chấm test
        val, test = h[h["split"] == "val"], h[h["split"] == "test"]
        cols = model_cols + list(zself.columns)
        clf = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, max_depth=4,
                                             class_weight="balanced", random_state=SEED)
        clf.fit(to_matrix(val, cols), val["is_redteam"].astype(int))
        p = clf.predict_proba(to_matrix(test, cols))[:, 1]
        results["test"]["_semi_supervised_ref"] = metrics_for(
            test["is_redteam"].astype(int).values, p, 0.5)

    (REPORTS_DIR / "lanl_experiments.json").write_text(json.dumps(results, indent=2),
                                                       encoding="utf-8")
    rows = []
    for split in ("val", "test"):
        for c in cands + (["_semi_supervised_ref"] if split == "test" and "test" in results
                          else []):
            if split in results and c in results[split]:
                r = results[split][c]
                rows.append({"split": split, "method": c, "roc_auc": r["roc_auc"],
                             "pr_auc": r["pr_auc"], "precision@100": r["precision@100"],
                             "recall@1000": r["recall@1000"],
                             "recall@thr": r["recall_at_threshold"],
                             "fpr@thr": r["fpr_at_threshold"],
                             "accounts_caught": r.get("accounts_caught"),
                             "alerts_per_day": r.get("alerts_per_day"),
                             **{f"acc@{k}/d": r.get(f"accounts@{k}/day") for k in BUDGETS}})
    table = pd.DataFrame(rows)
    table.to_csv(REPORTS_DIR / "lanl_experiments.csv", index=False)
    print(table.round(4).to_string(index=False))
    for split in ("val", "test"):
        if split in results:
            print(split, results[split]["_n"])


if __name__ == "__main__":
    main()
