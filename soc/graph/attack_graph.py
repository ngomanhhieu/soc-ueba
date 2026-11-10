"""Tái dựng chuỗi tấn công (lateral movement) trên đồ thị xác thực LANL – kiểu BloodHound nhưng
đi theo THỜI GIAN và chỉ dùng dữ liệu đến ngày của incident (nhân quả, như SOC thật).

Ý tưởng: kẻ tấn công dùng credential đánh cắp từ máy bàn đạp → để lại các cạnh "lạ":
  cạnh lạ = (tài khoản, máy nguồn) lần đầu xuất hiện trong lịch sử, đăng nhập từ xa (nguồn ≠ đích),
            xảy ra trong cửa sổ WINDOW ngày tới ngày incident.
  cặp quen = (tài khoản, máy nguồn) đã hoạt động ≥ HAB_DAYS ngày trước cửa sổ (người dùng thật
            dùng máy của mình hằng ngày).
Từ hạt giống (máy bàn đạp của incident máy, hoặc máy nguồn lạ của incident tài khoản), lặp:
  1. Tài khoản bị chiếm = mọi tài khoản đăng nhập từ xa XUẤT PHÁT từ máy tấn công trong cửa sổ,
     trừ cặp quen (máy đã bị chiếm thì credential dùng lại từ tuần trước vẫn là của kẻ tấn công).
  2. Máy bị chạm tới = đích của các cạnh đó.
  3. Mở rộng máy tấn công: máy y là nguồn cạnh lạ của ≥ MIN_SHARED tài khoản đã bị chiếm và
     chiếm ≥ MIN_SHARE số tài khoản lạ của y (dùng lại credential đánh cắp ở máy khác / pivot).
Kết quả: máy tấn công (máy bàn đạp chính = máy có nhiều tài khoản bị chiếm nhất), tài khoản bị
chiếm, máy bị chạm,
dòng thời gian từng bước gắn MITRE ATT&CK, và "bán kính ảnh hưởng" (máy mà tài khoản bị chiếm
vẫn đăng nhập hằng ngày – kẻ tấn công có thể dùng tiếp).

Nhãn red team chỉ dùng trong evaluate() để chấm điểm. Tham số chọn trên VAL (ngày 8–19): không
mở rộng / MIN_SHARED 2–5 / MIN_SHARE 0.3–0.8 → chọn (3, 0.8): F1 tài khoản cao nhất (0.59) và vẫn
tìm thêm máy tấn công C18025; ngưỡng lỏng kéo theo hàng trăm máy riêng của chính nạn nhân.

Gọi trong soc.risk.incidents (qua soc.playbooks.soar) → field attack_chain của incident LANL.
Chạy:  python -m soc.graph.attack_graph      # chấm điểm val/test → soc/reports/attack_graph_eval.json
"""
import argparse
import json
from functools import lru_cache

import numpy as np
import pandas as pd

from soc.config import SOC_REPORTS
from soc.graph.edges import GRAPH_DIR, load_edges
from features import available_days
from run_pipeline import day_range

WINDOW = 7          # ngày nhìn lại
MIN_SHARED = 3      # số tài khoản bị chiếm tối thiểu dùng chung để kết nạp máy tấn công mới
MIN_SHARE = 0.8     # và tỉ lệ trong số tài khoản lạ của máy đó (tránh kéo cả máy chủ lớn vào)
SEED_MAX_USERS = 50  # = SCOPE_MAX của bộ phát hiện máy (ml/src/lanl_hosts.py)
CONF_HIGH, CONF_MED = 0.9, 0.8   # độ tin cậy chuỗi = percentile số máy bị chạm so với chuỗi ở TRAIN
HAB_DAYS = 10       # cặp hoạt động ≥ 10 ngày trước cửa sổ = người dùng quen máy
MAX_ROUNDS = 3
MAX_TIMELINE = 150
TRAIN_DAYS = "1-7"


HORIZON = {"day": 29}      # ngày cuối được đọc (nhân quả: không đọc dữ liệu tương lai) – set_horizon()


def set_horizon(day: int):
    """Chỉ đọc đồ thị tới ngày `day` (incident xa nhất đang xử lý)."""
    HORIZON["day"] = int(day)


HISTORY_DAYS = 30   # lịch sử trước cửa sổ dùng để biết cặp (tài khoản, máy) quen / mới


def _days():
    lo = HORIZON["day"] - WINDOW - HISTORY_DAYS      # test (≤ ngày 29) vẫn đọc từ ngày 0 như cũ
    return [d for d in available_days() if lo <= d <= HORIZON["day"]]


def novel_edges() -> pd.DataFrame:
    return _novel_edges(HORIZON["day"])


def all_edges() -> pd.DataFrame:
    return _all_edges(HORIZON["day"])


def habitual() -> pd.DataFrame:
    return _habitual(HORIZON["day"])


@lru_cache(maxsize=1)
def _novel_edges(_h) -> pd.DataFrame:
    """Mọi cạnh từ xa của các cặp (tài khoản, nguồn) mới, kèm ngày cặp xuất hiện lần đầu."""
    parts = [load_edges(d) for d in _days()]
    e = pd.concat(parts, ignore_index=True)
    first = e.groupby(["user", "src"])["day"].transform("min")
    e = e[(e["src"] != e["dst"]) & (e["day"] - first < WINDOW)].copy()
    e["first_day"] = first[e.index]
    for c in ("user", "src", "dst", "auth"):
        e[c] = e[c].astype("category")
    return e.reset_index(drop=True)


@lru_cache(maxsize=1)
def _all_edges(_h) -> pd.DataFrame:
    """Mọi cạnh từ xa của mọi ngày (~8 triệu dòng, cột categorical)."""
    parts = []
    for d in _days():
        x = load_edges(d)
        parts.append(x[x["src"] != x["dst"]])
    e = pd.concat(parts, ignore_index=True)
    for c in ("user", "src", "dst", "auth"):
        e[c] = e[c].astype("category")
    return e


def chain_edges(attackers: set, day: int, lo: int) -> pd.DataFrame:
    """Cạnh xuất phát từ máy tấn công trong [lo, day], bỏ cặp quen (dùng ≥ HAB_DAYS ngày trước)."""
    ae = all_edges()
    a = ae[ae["src"].isin(attackers) & (ae["day"] <= day)]
    hist = a[a["day"] < lo].groupby(["user", "src"], observed=True)["day"].nunique()
    hab = set(hist[hist >= HAB_DAYS].index)
    w = a[a["day"] >= lo]
    keep = np.array([(u, s) not in hab for u, s in zip(w["user"], w["src"])], dtype=bool)
    return w[keep]


@lru_cache(maxsize=1)
def _habitual(_h) -> pd.DataFrame:
    """(tài khoản, máy đích, ngày) bình thường – để tính bán kính ảnh hưởng."""
    parts = []
    for d in _days():
        x = load_edges(d)
        parts.append(x.loc[x["src"] != x["dst"], ["user", "dst"]].drop_duplicates().assign(day=d))
    h = pd.concat(parts, ignore_index=True)
    h["user"] = h["user"].astype("category")
    return h


def chain_reference() -> np.ndarray:
    """Phân phối số máy bị chạm tới của chuỗi dựng từ các hạt giống ở TRAIN (ngày 1–7, không nhãn)
    – thang đo để biết chuỗi hôm nay lớn bất thường cỡ nào (như percentile của điểm ML)."""
    p = GRAPH_DIR / "chain_size_train.json"
    if p.exists():
        return np.array(json.loads(p.read_text()))
    ref = sorted(len(reconstruct(f"host:{r.host}", int(r.day), conf=False)["touched_hosts"])
                 for r in seeds(day_range(TRAIN_DAYS)).itertuples())
    p.write_text(json.dumps(ref))
    return np.array(ref)


def confidence(n_touched: int) -> tuple[float, str]:
    ref = chain_reference()
    q = float(np.searchsorted(ref, n_touched, side="right") / len(ref))
    return q, "high" if q >= CONF_HIGH else "medium" if q >= CONF_MED else "low"


def technique(auth: str) -> str:
    return "T1550.002" if auth == "NTLM" else "T1021"


def reconstruct(entity: str, day: int, first_day: int | None = None, conf: bool = True) -> dict:
    """Tái dựng chuỗi tấn công cho incident (entity = 'host:Cxxx' hoặc tài khoản) kéo dài
    [first_day, day]; cửa sổ = WINDOW ngày tới `day`, nới ra để phủ cả incident."""
    lo = min(day - WINDOW + 1, first_day if first_day is not None else day)
    ne = novel_edges()
    w = ne[(ne["day"] <= day) & (ne["day"] >= lo)]
    if entity.startswith("host:"):
        attackers = {entity.removeprefix("host:")}
    else:
        # máy nguồn KHÔNG QUEN của tài khoản trong incident; nhiều máy → giữ máy có nhiều tài
        # khoản lạ nhất (đặc trưng máy bàn đạp)
        ae = all_edges()
        own = ae[(ae["user"] == entity) & (ae["day"] <= day)]
        hist = {str(k): v for k, v in own[own["day"] < lo].groupby("src", observed=True)["day"].nunique().items()}
        cur = own[own["day"] >= (first_day if first_day is not None else day)]
        srcs = [s for s in cur["src"].astype(str).unique() if hist.get(s, 0) < HAB_DAYS]
        # bỏ máy chủ dùng chung (> SEED_MAX_USERS tài khoản trong cửa sổ) – không phải máy bàn đạp
        win = ae[ae["src"].isin(srcs) & (ae["day"] >= lo) & (ae["day"] <= day)]
        size = {str(k): v for k, v in win.groupby("src", observed=True)["user"].nunique().items()}
        srcs = [s for s in srcs if size.get(s, 0) <= SEED_MAX_USERS]
        if len(srcs) > 3:
            pop = w[w["src"].isin(srcs)].groupby("src", observed=True)["user"].nunique()
            srcs = pop.sort_values(ascending=False).index[:3].astype(str).tolist()
        attackers = set(srcs)
    seed = sorted(attackers)
    rounds = []
    pairs = pd.DataFrame({"src": w["src"].astype(str).values,
                          "user": w["user"].astype(str).values}).drop_duplicates()
    n_users = pairs.groupby("src").size()
    for _ in range(MAX_ROUNDS):
        accounts = set(chain_edges(attackers, day, lo)["user"].astype(str))
        shared = pairs[pairs["user"].isin(accounts) & ~pairs["src"].isin(attackers)] \
            .groupby("src").size()
        ok = (shared >= MIN_SHARED) & (shared / n_users.reindex(shared.index) >= MIN_SHARE)
        new = set(shared.index[ok])
        rounds.append(sorted(new))
        if not new:
            break
        attackers |= new
    chain = chain_edges(attackers, day, lo).sort_values(["day", "t0"])
    accounts = sorted(set(chain["user"].astype(str)))
    targets = sorted(set(chain["dst"].astype(str)) - attackers)
    per_host = chain.groupby("src", observed=True)["user"].nunique().sort_values(ascending=False)
    hab = habitual()
    hab = hab[(hab["day"] <= day) & (hab["day"] >= lo) & hab["user"].isin(accounts)]
    reach = sorted(set(hab["dst"].astype(str)) - set(targets) - attackers)
    tl = [{"t": int(r.t0), "day": int(r.day), "user": str(r.user), "src": str(r.src),
           "dst": str(r.dst), "auth": str(r.auth), "n": int(r.n), "mitre": technique(str(r.auth))}
          for r in chain.head(MAX_TIMELINE).itertuples()]
    q, level = confidence(len(targets)) if conf else (None, None)
    return {"seed": seed, "day": int(day), "window_days": [int(lo), int(day)],
            "confidence": q, "confidence_level": level,
            "attacker_hosts": [str(h) for h in per_host.index],
            "main_host": str(per_host.index[0]) if len(per_host) else None,
            "expansion_rounds": rounds, "compromised_accounts": accounts,
            "touched_hosts": targets, "blast_radius_hosts": len(reach),
            "blast_radius_sample": reach[:30], "n_edges": int(len(chain)),
            "mitre_ids": sorted({x["mitre"] for x in tl} | ({"T1078"} if accounts else set())),
            "timeline": tl, "_rt": chain["rt"].values}


def score(g: dict, day: int) -> dict:
    """So với red team TRONG CỬA SỔ (chỉ để đánh giá)."""
    ne = novel_edges()
    rt_all = []
    for d in range(day - WINDOW + 1, day + 1):
        if d in available_days():
            x = load_edges(d)
            rt_all.append(x[x["rt"]])
    rt = pd.concat(rt_all) if rt_all else ne.iloc[:0]
    ra, rs, rd = set(rt["user"]), set(rt["src"]), set(rt["dst"]) - set(rt["src"])
    a, s, t = set(g["compromised_accounts"]), set(g["attacker_hosts"]), set(g["touched_hosts"])
    return {"rt_accounts": len(ra), "found_accounts": len(a & ra), "chain_accounts": len(a),
            "rt_src": sorted(rs), "found_src": sorted(s & rs), "chain_src": len(s),
            "rt_dst": len(rd), "found_dst": len(t & rd), "chain_dst": len(t),
            "edge_precision": float(np.mean(g["_rt"])) if len(g["_rt"]) else 0.0}


def seeds(split_days) -> pd.DataFrame:
    """Hạt giống = incident MÁY trong hàng đợi (top-5 máy/ngày, không dùng nhãn)."""
    from soc.risk.risk import host_queue
    hq = host_queue("lanl")
    return hq[hq["day"].isin(split_days)][["host", "day"]].drop_duplicates()


def evaluate(split: str, days) -> dict:
    s = seeds(days)
    rows = []
    for r in s.itertuples():
        g = reconstruct(f"host:{r.host}", int(r.day))
        rows.append({"host": r.host, "day": int(r.day), "confidence": g["confidence"],
                     **score(g, int(r.day))})
    df = pd.DataFrame(rows)
    df["is_attacker_seed"] = [h in rs for h, rs in zip(df["host"], df["rt_src"])]
    tp, fp = df[df["is_attacker_seed"]], df[~df["is_attacker_seed"]]
    out = {"split": split, "seeds": len(df), "attacker_seeds": len(tp)}
    if len(tp):
        out.update({
            "account_recall": float((tp["found_accounts"] / tp["rt_accounts"].clip(lower=1)).mean()),
            "account_precision": float((tp["found_accounts"] / tp["chain_accounts"].clip(lower=1)).mean()),
            "dst_recall": float((tp["found_dst"] / tp["rt_dst"].clip(lower=1)).mean()),
            "src_found": float((tp["found_src"].str.len() / tp["rt_src"].str.len()).mean()),
            "edge_precision": float(tp["edge_precision"].mean()),
            "median_chain_accounts": float(tp["chain_accounts"].median())})
    if len(fp):
        out["benign_seed_median_accounts"] = float(fp["chain_accounts"].median())
    flag = df["confidence"] >= CONF_MED
    out["block_recommended_attacker"] = f"{int((flag & df['is_attacker_seed']).sum())}/{len(tp)}"
    out["block_recommended_benign"] = f"{int((flag & ~df['is_attacker_seed']).sum())}/{len(fp)}"
    # danh sách chi tiết cho báo cáo
    out["attacker_seed_detail"] = tp[["host", "day", "found_accounts", "rt_accounts",
                                     "chain_accounts", "found_src", "rt_src", "found_dst", "rt_dst"]].to_dict("records")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--val-days", default="8-19")
    ap.add_argument("--test-days", default="20-29")
    a = ap.parse_args()
    res = {"params": {"window": WINDOW, "min_shared": MIN_SHARED, "min_share": MIN_SHARE},
           "val": evaluate("val", day_range(a.val_days)),
           "test": evaluate("test", day_range(a.test_days))}
    for s in ("val", "test"):
        r = {k: v for k, v in res[s].items() if k != "attacker_seed_detail"}
        print(s, json.dumps(r, ensure_ascii=False))
    (SOC_REPORTS / "attack_graph_eval.json").write_text(
        json.dumps(res, ensure_ascii=False, indent=1, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
