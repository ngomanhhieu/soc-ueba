"""Mô phỏng TRIỂN KHAI THẬT trên LANL: đi tuần tự từng ngày, chấm điểm, cảnh báo, rồi mới
cập nhật lịch sử – để đo và chống "đầu độc baseline".

Vấn đề (phát hiện khi đánh giá trên ngày 20–29 chưa từng nhìn): kẻ tấn công dùng lại đúng máy
C17693 và các tài khoản đã chiếm từ ngày 8–19. Feature "mới so với lịch sử" đã học các cặp
(user, máy) đó thành bình thường → red team ngày 20–29 có n_new_src_comp trung vị = 0.

Các biến thể (mô hình chấm điểm giống nhau: ECOD + IF di chuyển ngang, đã chọn trên val
trong experiments_lanl.py; train ngày 1–7, ngày 0 chỉ làm lịch sử):
  base          – lịch sử học mọi thứ (như cũ)
  quarantine    – user-ngày bị cảnh báo (điểm ≥ ngưỡng) KHÔNG được học vào lịch sử (không cần nhãn)
  fanin         – thêm src_max_fanin: fan-in của máy nguồn, không phụ thuộc lịch sử
  quar+fanin    – cả hai
  quar+fanin+ioc – thêm vòng phản hồi SOC: analyst xem top-K cảnh báo/ngày; cảnh báo đúng thì
                  máy nguồn tấn công trở thành IOC, mọi đăng nhập sau đó từ máy IOC → cảnh báo
LƯU Ý: các biến thể này được thiết kế SAU khi nhìn kết quả test → báo cáo tách riêng, và phải
cải thiện cả trên val (ngày 8–19) mới được coi là có ích.

Chạy:  python src/lanl_online.py
Kết quả: reports/lanl_online.json, reports/lanl_online.csv
"""
import argparse
import json

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from config import PROCESSED_DIR, REPORTS_DIR
from evaluate import metrics_for
from experiments_lanl import LATERAL_COLS, NEW_EDGE_COLS, ecod_fit, ecod_score
from features import NoveltyState, account_type, assemble, available_days, load_base
from lanl_explore_redteam import load_redteam
from lanl_rarity import RARITY_COLS, RarityState
from models import SEED, percentile_score, to_matrix
from run_pipeline import day_range
from statistical import STAT_COLS

VARIANTS = {   # tên: (cách ly, thêm src_max_fanin, phản hồi IOC, độ hiếm tần suất – lanl_rarity)
    "base": (False, False, False, False),
    "quarantine": (True, False, False, False),
    "fanin": (False, True, False, False),
    "quar+fanin": (True, True, False, False),
    "quar+fanin+ioc": (True, True, True, False),
    "rarity": (False, True, False, True),
    "quar+fanin+rarity": (True, True, False, True),
    "quar+fanin+rarity+ioc": (True, True, True, True),
}
BUDGETS = (10, 25, 50)


class Scorer:
    """ECOD (feature thống kê) + IF (feature di chuyển ngang), percentile so với train."""

    def __init__(self, fanin: bool, rarity: bool = False):
        extra = (["src_max_fanin"] if fanin else []) + (RARITY_COLS if rarity else [])
        self.stat_cols = STAT_COLS + NEW_EDGE_COLS + extra
        self.lat_cols = LATERAL_COLS + extra

    def fit(self, tr: pd.DataFrame):
        Xe = to_matrix(tr, self.stat_cols)
        self.ecod_ref = ecod_fit(Xe)
        self.ecod_tr = ecod_score(self.ecod_ref, Xe)
        Xl = to_matrix(tr, self.lat_cols)
        self.ifl = IsolationForest(n_estimators=300, max_samples=4096, random_state=SEED,
                                   n_jobs=-1).fit(Xl)
        self.if_tr = -self.ifl.score_samples(Xl)
        ens = (percentile_score(self.ecod_tr, self.ecod_tr)
               + percentile_score(self.if_tr, self.if_tr)) / 2
        self.ens_tr = ens
        return self

    def score(self, f: pd.DataFrame) -> pd.DataFrame:
        """Điểm thành phần + điểm cuối + lý do (feature có xác suất đuôi < 1% so với train)."""
        Xe = to_matrix(f, self.stat_cols)
        e = percentile_score(self.ecod_tr, ecod_score(self.ecod_ref, Xe))
        i = percentile_score(self.if_tr, -self.ifl.score_samples(to_matrix(f, self.lat_cols)))
        n = len(self.ecod_ref)
        contrib = np.column_stack([
            -np.log((n - np.searchsorted(self.ecod_ref[:, j], Xe[:, j], side="left") + 1)
                    / (n + 1)) for j in range(Xe.shape[1])])
        order = np.argsort(-contrib, axis=1)[:, :3]
        reasons = [[self.stat_cols[j] for j in row if contrib[k, j] > np.log(100)]
                   for k, row in enumerate(order)]
        return pd.DataFrame({"ecod_score": e, "iforest_lateral_score": i,
                             "score": percentile_score(self.ens_tr, (e + i) / 2),
                             "top_reasons": reasons}, index=f.index)


def humans(f: pd.DataFrame) -> pd.DataFrame:
    f = f[account_type(f["src_user"]) == "human"].copy()
    f["is_redteam"] = f["n_redteam"] > 0
    return f


def run_variant(name, days, train_days, bases, red_hosts, thr, triage_k):
    quarantine_on, fanin, ioc_on, rarity = VARIANTS[name]
    state, scorer, out, ioc = NoveltyState(), None, [], set()
    rstate = RarityState() if rarity else None
    for i, day in enumerate(days):
        nov, pending = state.features(day)
        f = humans(assemble(day, bases[day], nov, i))
        if rarity:
            rf, rpending = rstate.features(day)
            f = f.merge(rf, left_on="src_user", right_index=True, how="left")
            f[RARITY_COLS] = f[RARITY_COLS].fillna(0.0)
        f["ioc_hit"] = False
        if day <= max(train_days):
            out.append(f.assign(score=np.nan))
            state.commit(pending)
            if rarity:
                rstate.commit(rpending)
            if day == max(train_days):
                tr = pd.concat([o for o in out if o["day"].iat[0] in train_days])
                scorer = Scorer(fanin, rarity).fit(tr)
                # điểm cho các ngày train (để tham khảo, không dùng đánh giá)
                out = [o.drop(columns="score").join(scorer.score(o)) for o in out]
            continue
        f = f.join(scorer.score(f))
        if ioc_on and ioc:
            src = pending["src"]
            hit = set(src.loc[src["src_comp"].isin(ioc), "src_user"])
            f["ioc_hit"] = f["src_user"].isin(hit)
            f.loc[f["ioc_hit"], "score"] = 1.0
        flagged = set(f.loc[f["score"] >= thr, "src_user"])
        state.commit(pending, flagged if quarantine_on else None)
        if rarity:
            rstate.commit(rpending, flagged if quarantine_on else None)
        if ioc_on:   # analyst xem top-K, cảnh báo đúng → điều tra ra máy nguồn tấn công
            top = f.nlargest(triage_k, "score")
            for u in top.loc[top["is_redteam"], "src_user"]:
                ioc |= red_hosts.get((u, day), set())
        out.append(f)
    res = pd.concat(out, ignore_index=True)
    res.attrs["scorer"] = scorer
    return res


def summarize(scores, split_days, thr):
    part = scores[scores["day"].isin(split_days)]
    y = part["is_redteam"].astype(int).values
    r = metrics_for(y, part["score"].values, thr)
    rt = set(part.loc[part["is_redteam"], "src_user"])
    al = part[part["score"] >= thr]
    r["accounts_caught"] = len(set(al.loc[al["is_redteam"], "src_user"]) & rt)
    r["accounts_total"] = len(rt)
    r["alerts_per_day"] = round(len(al) / part["day"].nunique(), 1)
    for k in BUDGETS:
        top = part.sort_values("score", ascending=False, kind="stable").groupby("day").head(k)
        r[f"accounts@{k}/day"] = len(set(top.loc[top["is_redteam"], "src_user"]) & rt)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-days", default="1-7")
    ap.add_argument("--val-days", default="8-19")
    ap.add_argument("--test-days", default="20-29")
    ap.add_argument("--threshold", type=float, default=0.99)
    ap.add_argument("--triage-k", type=int, default=25, help="analyst xem K cảnh báo/ngày")
    ap.add_argument("--variants", nargs="+", default=list(VARIANTS))
    args = ap.parse_args()
    train_days = day_range(args.train_days)
    split_days = {"val": day_range(args.val_days), "test": day_range(args.test_days)}
    days = [d for d in available_days() if d <= max(split_days["test"])]

    red = load_redteam()
    red["day"] = red["time"] // 86400
    red_hosts = red.groupby(["user", "day"])["src_comp"].agg(set).to_dict()
    bases = {d: load_base(d) for d in days}

    results, rows = {}, []
    for name in args.variants:
        print(f"[{name}]", flush=True)
        sc = run_variant(name, days, train_days, bases, red_hosts, args.threshold, args.triage_k)
        if name == "quar+fanin+ioc":
            sc.to_parquet(PROCESSED_DIR / "lanl_online_scores.parquet", index=False)
        results[name] = {s: summarize(sc, d, args.threshold) for s, d in split_days.items()}
        for s, r in results[name].items():
            rows.append({"variant": name, "split": s, **{k: r[k] for k in (
                "roc_auc", "pr_auc", "precision@100", "recall@1000", "recall_at_threshold",
                "accounts_caught", "accounts_total", "alerts_per_day",
                *[f"accounts@{k}/day" for k in BUDGETS])}})
        print(pd.DataFrame([r for r in rows if r["variant"] == name]).round(4)
              .to_string(index=False), flush=True)
    (REPORTS_DIR / "lanl_online.json").write_text(json.dumps(results, indent=2),
                                                  encoding="utf-8")
    table = pd.DataFrame(rows)
    table.to_csv(REPORTS_DIR / "lanl_online.csv", index=False)
    print("\n" + table.round(4).to_string(index=False))


if __name__ == "__main__":
    main()
