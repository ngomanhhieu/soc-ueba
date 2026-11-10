"""Phát hiện ở MỨC MÁY cho LANL: máy bàn đạp (jump host) dùng credential đánh cắp.

Vì sao: kẻ tấn công đăng nhập từ 1 máy bằng nhiều tài khoản đã chiếm, mỗi tài khoản chỉ 1–2 lần
→ nhìn từng tài khoản rất "êm". Nhìn từ máy nguồn: trong 1 ngày có nhiều tài khoản người đăng
nhập TỪ máy đó mà với CHÍNH HỌ máy đó là lạ (lịch sử đếm suy giảm thấp). Máy chủ dùng chung bình
thường cũng có nhiều người, nhưng là người quen dùng hằng ngày → không bị tính.

Feature theo (máy nguồn, ngày):
  n_rare_users   – số tài khoản người mà máy này là máy nguồn hiếm (H_u(src) < RARE_H)
  n_users        – tổng số tài khoản người dùng máy này làm nguồn
  rare_ntlm_users – trong số đó, có đăng nhập NTLM
Điểm: percentile của n_rare_users so với các máy-ngày ở TRAIN (không dùng nhãn).

LƯU Ý: ý tưởng ra đời SAU KHI chẩn đoán lỗi trên test (ngày 20–29) → báo cáo tách riêng, phải tốt
cả trên val (ngày 8–19).

Chạy:  python src/lanl_hosts.py --train-days 1-7 --val-days 8-19 --test-days 20-29
Kết quả: data/processed/lanl_host_scores.parquet, reports/lanl_hosts.json
"""
import argparse
import json

import numpy as np
import pandas as pd

from config import PROCESSED_DIR, REPORTS_DIR
from features import available_days, daily_path
from lanl_rarity import RarityState
from models import percentile_score
from run_pipeline import day_range

RARE_H = 1.0          # đếm suy giảm < 1: chưa dùng máy này lần nào gần đây
BUDGETS = (5, 10, 25)
SCOPE_MAX = 50       # analyst rà soát được tối đa ~50 tài khoản cho 1 incident máy


def host_day(day: int, rstate: RarityState) -> pd.DataFrame:
    src = pd.read_parquet(daily_path(day, "src"))
    _, pending = rstate.features(day)
    s = pending["src"].copy()                               # có k = hash(user, src)
    s["h"] = rstate.h_src.reindex(s["k"].values).fillna(0).values
    s["ntlm"] = src["ntlm"].values
    s["rare"] = s["h"] < RARE_H
    g = s.groupby("src_comp")
    out = pd.DataFrame({
        "n_users": g["src_user"].nunique(),
        "n_rare_users": g["rare"].sum(),
        "rare_ntlm_users": s[s["rare"] & (s["ntlm"] > 0)].groupby("src_comp")["src_user"].nunique(),
    }).fillna(0)
    rn = s[s["rare"] & (s["ntlm"] > 0)]
    out["rare_user_list"] = rn.groupby("src_comp")["src_user"].agg(lambda x: sorted(set(x)))         .reindex(out.index)   # chỉ TK lạ + NTLM (trung vị 4 TK/máy) – việc của analyst vừa phải
    # Phạm vi điều tra của incident máy: máy nhỏ (≤ SCOPE_MAX tài khoản) → MỌI tài khoản đăng nhập
    # từ máy đó trong ngày (máy bàn đạp đã bị chiếm thì mọi phiên từ nó đều đáng ngờ, kể cả tài
    # khoản đã quen dùng nó vì bị chiếm từ trước); máy lớn (server) → chỉ các tài khoản lạ + NTLM.
    all_users = s.groupby("src_comp")["src_user"].agg(lambda x: sorted(set(x))).reindex(out.index)
    out["scope_user_list"] = [a if n <= SCOPE_MAX else (r if isinstance(r, list) else [])
                              for a, n, r in zip(all_users, out["n_users"], out["rare_user_list"])]
    out["day"] = day
    rstate.commit(pending)
    return out.reset_index().rename(columns={"src_comp": "host"})


def ntlm_surprise(h: pd.DataFrame) -> np.ndarray:
    """Mức bất ngờ của số tài khoản người đăng nhập NTLM từ máy mà với họ là LẠ (dấu hiệu
    pass-the-hash từ máy bàn đạp), chuẩn hoá theo cỡ máy với tỉ lệ TOÀN MẠNG trong ngày:
        surprise = -log P(X ≥ rare_ntlm_users | Poisson(tỉ lệ toàn mạng × n_users))
    Chọn trên val (ngày 8–19) giữa: Poisson theo lịch sử riêng của máy (bị "đầu độc" – máy bàn
    đạp học rằng mình vốn toàn người lạ), có/không cách ly, đếm thô – xem ml/README.md."""
    from scipy.stats import poisson
    out = np.zeros(len(h))
    for _, idx in h.groupby("day").indices.items():
        p = h.iloc[idx]
        rate = (p["rare_ntlm_users"].sum() + 1) / (p["n_users"].sum() + 10)
        out[idx] = -poisson.logsf(p["rare_ntlm_users"].values - 1,
                                  np.maximum(rate * p["n_users"].values, 1e-3))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-days", default="1-7")
    ap.add_argument("--val-days", default="8-19")
    ap.add_argument("--test-days", default="20-29")
    ap.add_argument("--live-days", default="30-57", help="ngày mới sau test – chỉ chấm điểm")
    a = ap.parse_args()
    split = {"train": day_range(a.train_days), "val": day_range(a.val_days),
             "test": day_range(a.test_days)}
    days = [d for d in available_days() if d <= max(split["test"] + day_range(a.live_days))]
    rstate, parts = RarityState(), []
    for d in days:
        parts.append(host_day(d, rstate))
        print(f"  ngày {d:02d}: {len(parts[-1]):,} máy nguồn", flush=True)
    h = pd.concat(parts, ignore_index=True)
    h = h[h["n_users"] > 0].sort_values(["day", "host"]).reset_index(drop=True)
    h["surprise"] = ntlm_surprise(h)
    is_tr = h["day"].isin(split["train"]).values
    raw = h["surprise"].values
    h["host_score"] = percentile_score(raw[is_tr], raw)
    for c in ("rare_user_list", "scope_user_list"):
        h[c] = h[c].apply(lambda x: list(x) if isinstance(x, list) else [])
    h.to_parquet(PROCESSED_DIR / "lanl_host_scores.parquet", index=False)

    f = pd.read_parquet(PROCESSED_DIR / "lanl_user_day_features.parquet",
                        columns=["src_user", "day", "is_redteam"])
    truth = set(zip(f.loc[f["is_redteam"], "src_user"], f.loc[f["is_redteam"], "day"]))
    res = {}
    for s in ("val", "test"):
        part = h[h["day"].isin(split[s])]
        t = {x for x in truth if x[1] in set(split[s])}
        r = {"redteam_user_days": len(t), "accounts": len({u for u, _ in t})}
        for k in BUDGETS:
            top = part.sort_values("host_score", ascending=False, kind="stable").groupby("day").head(k)
            hit = {(u, d) for lst, d in zip(top["scope_user_list"], top["day"]) for u in lst} & t
            r[f"user_days@{k}hosts/day"] = len(hit)
            r[f"accounts@{k}hosts/day"] = len({u for u, _ in hit})
            r[f"users_listed@{k}hosts/day"] = int(top["scope_user_list"].map(len).sum())
        res[s] = r
        print(s, json.dumps(r, ensure_ascii=False))
    top_test = h[h["day"].isin(split["test"])].nlargest(10, "host_score")[
        ["day", "host", "n_users", "n_rare_users", "rare_ntlm_users", "host_score"]]
    print(top_test.to_string(index=False))
    (REPORTS_DIR / "lanl_hosts.json").write_text(json.dumps(res, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
