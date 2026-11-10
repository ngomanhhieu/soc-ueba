"""Lớp 4 – Tương quan + điểm rủi ro theo thực thể (giống entity risk score của UEBA thương mại).

Mỗi phát hiện (luật Sigma hoặc ML) cộng điểm vào thực thể nó trỏ tới (user, hoặc máy với luật gom
theo máy). Rủi ro suy giảm theo thời gian:
    R_e(ngày) = R_e(ngày trước) × DECAY + Σ điểm phát hiện của e trong ngày
Điểm phát hiện:   luật  = trọng số theo level (medium 20, high 40, critical 80)
                  ML    = ml_weight × (score − ml_floor) / (1 − ml_floor), chỉ khi score ≥ ml_floor
Analyst xem K thực thể rủi ro cao nhất mỗi ngày → incident. Nhờ cộng dồn, hành vi "êm nhưng kéo
dài" (nhiều phát hiện nhỏ liên tiếp) vẫn nổi lên; nhiều luật cùng chỉ vào 1 user cũng vậy.

Tham số (decay, ml_weight, ml_floor) chọn trên VALIDATION theo số tài khoản/insider bắt được
với ngân sách K; test chỉ để báo cáo. So sánh: chỉ luật / chỉ ML / luật + ML.

Chạy:  python -m soc.risk.risk
Kết quả: <STATE_DIR>/risk_{lanl,cert}.parquet, <STATE_DIR>/incidents_{lanl,cert}.parquet,
         soc/reports/risk_eval.csv
"""
import argparse
import itertools
import json

import numpy as np
import pandas as pd

from soc.config import PROCESSED_DIR, SOC_REPORTS, STATE_DIR
from soc.rules.run_rules import LANL_SPLITS, cert_split

LEVEL_W = {"informational": 0, "low": 10, "medium": 20, "high": 40, "critical": 80}
# LANL: 2 hàng đợi – tài khoản (theo rủi ro) + máy bàn đạp (theo mức bất ngờ gốc của ML mức máy).
# Điểm percentile của ML bị "kẹt" ở 1.0 khi dữ liệu trôi → xếp chung 1 hàng mất thứ tự.
HOST_BUDGET = {"lanl": 5}
HOST_DETECTOR = "ml_lanl_host"
WATCH_DAYS = 7        # theo dõi máy đã vào hàng đợi trong 1 tuần (chọn trước, không dò theo test)
SCOPE_MAX = 50        # như ml/src/lanl_hosts.py: tối đa 50 tài khoản cho 1 incident máy


def host_queue(ds: str, k: int | None = None, watch_days: int = WATCH_DAYS) -> pd.DataFrame:
    """Hàng đợi máy mỗi ngày (ml/src/lanl_hosts.py):
      * top-K máy theo mức bất ngờ;
      * + DANH SÁCH THEO DÕI: máy từng vào top-K trong `watch_days` ngày trước, hôm nay xuất hiện
        lại (≤ SCOPE_MAX tài khoản) – máy đã bị nghi là bàn đạp thì vẫn đáng ngờ dù hôm nay chỉ
        đăng nhập 1–2 tài khoản (rủi ro cộng dồn theo thực thể, không cần nhãn).
    Thiết kế sau chẩn đoán test – xem ml/README.md; đổi lại số tài khoản cần rà soát tăng."""
    p = PROCESSED_DIR / f"{ds}_host_scores.parquet"
    if ds not in HOST_BUDGET or not p.exists():
        return pd.DataFrame(columns=["host", "day", "surprise", "scope_user_list", "watch"])
    h = pd.read_parquet(p)
    top = h[h["rare_ntlm_users"] > 0].sort_values("surprise", ascending=False, kind="stable") \
        .groupby("day").head(k or HOST_BUDGET[ds]).assign(watch=False)
    if not watch_days:
        return top
    flagged = top.groupby("host")["day"].agg(list)
    small = h[h["n_users"] <= SCOPE_MAX]
    keep = [any(d - watch_days <= fd < d for fd in flagged.get(x, [])) for x, d in
            zip(small["host"], small["day"])]
    watch = small[keep].merge(top[["host", "day"]], how="left", indicator=True)
    watch = watch[watch["_merge"] == "left_only"].drop(columns="_merge").assign(watch=True)
    return pd.concat([top, watch], ignore_index=True)
GRID = {"decay": [0.5, 0.7, 0.85], "ml_weight": [20, 40, 80, 160], "ml_floor": [0.95, 0.99]}


def rule_fidelity(rules: pd.DataFrame, train_days: list) -> pd.Series:
    """Hệ số theo độ 'ồn' của luật ở giai đoạn TRAIN (không dùng nhãn): luật bắn nhiều lần mỗi
    ngày bị giảm điểm, luật hiếm được tăng – giống risk-based alerting của SIEM.
        hệ số = clip( sqrt(1 / max(số cảnh báo/ngày, 1/16)), 0.2, 4 )"""
    tr = rules[rules["day"].isin(set(train_days))]
    rate = tr.groupby("detector").size() / max(len(train_days), 1)
    rate = rate.reindex(rules["detector"].unique()).fillna(0)
    return np.clip(np.sqrt(1 / np.maximum(rate, 1 / 16)), 0.2, 4.0)
BUDGET = {"lanl": 25, "cert": 5}


# ---------------------------------------------------------------- gom phát hiện
def rule_detections(ds: str, src=None) -> pd.DataFrame:
    """Luật gom theo user → thực thể là user; luật gom theo máy (spray, nhiều tài khoản / 1
    máy) → thực thể là máy, kèm danh sách user trong ngữ cảnh (ctx.user.name)."""
    al = pd.read_parquet(src or STATE_DIR / f"rule_alerts_{ds}.parquet")
    day = al["day"] if ds == "lanl" else al["date"]
    none = pd.Series([None] * len(al), index=al.index)
    hosts = al.get("source.host", none)
    ctx_users = al.get("ctx.user.name", none)
    ents, users = [], []
    for u, h, cu in zip(al["user.name"], hosts, ctx_users):
        if isinstance(u, str):
            ents.append(u)
            users.append([u])
        else:
            ents.append(f"host:{h}")
            users.append(list(cu) if isinstance(cu, (list, np.ndarray)) else [])
    return pd.DataFrame({
        "entity": ents, "day": day.values, "source": "rule", "detector": al["rule_id"].values,
        "title": al["rule_title"].values, "level": al["level"].values,
        "points": al["level"].map(LEVEL_W).values.astype(float),
        "mitre": al["mitre"].values, "users": users,
    })


def ml_detections(ds: str) -> pd.DataFrame:
    if ds == "lanl":
        s = pd.read_parquet(PROCESSED_DIR / "lanl_scores.parquet",
                            columns=["src_user", "day", "alert_score", "top_reasons"])
        s = s.rename(columns={"src_user": "entity"})
    else:
        s = pd.read_parquet(PROCESSED_DIR / "cert_scores.parquet",
                            columns=["user", "date", "alert_score", "top_reasons"])
        s = s.rename(columns={"user": "entity", "date": "day"})
    s = s.dropna(subset=["alert_score"])
    out = pd.DataFrame({"entity": s["entity"].astype(str).values, "day": s["day"].values,
                        "source": "ml", "detector": f"ml_{ds}", "title": "Bất thường hành vi (ML)",
                        "score": s["alert_score"].values, "top_reasons": s["top_reasons"].values,
                        "users": [[u] for u in s["entity"].astype(str)]})
    host_path = PROCESSED_DIR / "lanl_host_scores.parquet"
    if ds == "lanl" and host_path.exists():
        # ML mức máy (ml/src/lanl_hosts.py): máy bàn đạp – nhiều tài khoản đăng nhập NTLM từ máy
        # mà với họ là lạ. Thực thể = máy, kèm danh sách tài khoản liên quan.
        h = pd.read_parquet(host_path, columns=["host", "day", "host_score", "scope_user_list",
                                                 "rare_ntlm_users", "n_users"])
        h = h[h["rare_ntlm_users"] > 0]
        out = pd.concat([out, pd.DataFrame({
            "entity": "host:" + h["host"].astype(str), "day": h["day"].values, "source": "ml",
            "detector": "ml_lanl_host", "title": "Máy bàn đạp: nhiều tài khoản NTLM từ máy lạ (ML)",
            "score": h["host_score"].values,
            "top_reasons": [[f"rare_ntlm_users={int(a)}", f"n_users={int(b)}"]
                            for a, b in zip(h["rare_ntlm_users"], h["n_users"])],
            "users": [list(x) for x in h["scope_user_list"]]})], ignore_index=True)
    return out


# ---------------------------------------------------------------- tính rủi ro
def daily_risk(det: pd.DataFrame, days: list, decay: float) -> pd.DataFrame:
    """det: entity, day, points → bảng (entity, day, risk) với đệ quy suy giảm theo ngày."""
    pts = det.groupby(["day", "entity"])["points"].sum()
    risk = pd.Series(dtype=float)
    out = []
    for d in days:
        risk = risk * decay
        if d in pts.index.get_level_values(0):
            risk = risk.add(pts.loc[d], fill_value=0.0)
        risk = risk[risk > 0.5]                       # bỏ thực thể đã "nguội"
        out.append(pd.DataFrame({"entity": risk.index, "day": d, "risk": risk.values}))
    return pd.concat(out, ignore_index=True)


def combine(rules: pd.DataFrame, ml: pd.DataFrame, mode: str, ml_weight: float,
            ml_floor: float) -> pd.DataFrame:
    parts = []
    if mode in ("rules", "both"):
        parts.append(rules[["entity", "day", "points", "users"]])
    if mode in ("ml", "both"):
        m = ml[ml["score"] >= ml_floor]
        parts.append(pd.DataFrame({"entity": m["entity"], "day": m["day"],
                                   "points": ml_weight * (m["score"] - ml_floor) / (1 - ml_floor)
                                   + 1e-3, "users": m["users"]}))
    return pd.concat(parts, ignore_index=True)


def evaluate(risk: pd.DataFrame, det: pd.DataFrame, truth: set, days: list, k: int,
             hosts: pd.DataFrame | None = None) -> dict:
    """Mỗi ngày analyst mở top-K thực thể (+ top máy của hàng đợi máy nếu có); bắt được tài
    khoản độc hại nếu nó là thực thể đó (hoặc trong danh sách user liên quan) đúng ngày."""
    top = risk[risk["day"].isin(days)].sort_values("risk", ascending=False, kind="stable") \
        .groupby("day").head(k)
    users_of = det.groupby(["entity", "day"])["users"].agg(
        lambda s: set(itertools.chain.from_iterable(s)))
    hit = set()
    for e, d in zip(top["entity"], top["day"]):
        us = users_of.get((e, d), set()) | ({e} if not str(e).startswith("host:") else set())
        hit |= {(u, d) for u in us if (u, d) in truth}
    n_hosts = 0
    if hosts is not None and len(hosts):
        hq = hosts[hosts["day"].isin(days)]
        n_hosts = len(hq)
        hit |= {(u, d) for lst, d in zip(hq["scope_user_list"], hq["day"]) for u in lst
                if (u, d) in truth}
    t = {x for x in truth if x[1] in set(days)}
    return {"user_days_hit": len(hit), "user_days": len(t),
            "accounts_hit": len({u for u, _ in hit}), "accounts": len({u for u, _ in t}),
            "incidents_per_day": round((len(top) + n_hosts) / max(len(days), 1), 1)}


def truth_and_splits(ds: str):
    if ds == "lanl":
        f = pd.read_parquet(PROCESSED_DIR / "lanl_user_day_features.parquet",
                            columns=["src_user", "day", "is_redteam"])
        truth = set(zip(f.loc[f["is_redteam"], "src_user"], f.loc[f["is_redteam"], "day"]))
        from features import available_days
        splits = {s: list(d) for s, d in LANL_SPLITS.items()}
        days = available_days()                       # gồm cả ngày "live" (nếu đã tải)
    else:
        f = pd.read_parquet(PROCESSED_DIR / "cert_user_day_features.parquet",
                            columns=["user", "date", "is_malicious"])
        truth = set(zip(f.loc[f["is_malicious"], "user"], f.loc[f["is_malicious"], "date"]))
        dates = pd.Series(sorted(f["date"].unique()))
        sp = cert_split(dates)
        splits = {s: list(dates[sp == s]) for s in ("train", "val", "test")}
        days = list(dates)
    return truth, splits, days


def run(ds: str) -> list[dict]:
    rules, ml = rule_detections(ds), ml_detections(ds)
    truth, splits, days = truth_and_splits(ds)
    fid = rule_fidelity(rules, splits["train"])
    rules["points"] = rules["points"] * rules["detector"].map(fid).values
    (STATE_DIR / f"rule_fidelity_{ds}.json").write_text(fid.round(3).to_json(), encoding="utf-8")
    k = BUDGET[ds]
    hosts = host_queue(ds)
    ml_user = ml[ml["detector"] != HOST_DETECTOR]       # ML theo tài khoản
    rows = []
    # chọn tham số trên VAL cho từng chế độ, báo cáo test. Chế độ "both+hosts" (LANL): hàng đợi
    # tài khoản (K − số máy) + hàng đợi máy – tổng ngân sách vẫn là K incident/ngày.
    modes = ["rules", "ml", "both"] + (["both+hosts"] if len(hosts) else [])
    for mode in modes:
        kq = k - HOST_BUDGET.get(ds, 0) if mode == "both+hosts" else k
        hq = hosts if mode == "both+hosts" else None
        base_mode = "both" if mode == "both+hosts" else mode
        best, best_val = None, -1
        grid = [dict(zip(GRID, v)) for v in itertools.product(*GRID.values())]
        if mode == "rules":
            grid = [g for g in grid if g["ml_weight"] == GRID["ml_weight"][0]
                    and g["ml_floor"] == GRID["ml_floor"][0]]
        for g in grid:
            det = combine(rules, ml_user, base_mode, g["ml_weight"], g["ml_floor"])
            r = daily_risk(det, days, g["decay"])
            v = evaluate(r, det, truth, splits["val"], kq, hq)
            key = (v["accounts_hit"], v["user_days_hit"])
            if key > (best_val if best_val != -1 else (-1, -1)):
                best, best_val = g, key
        det = combine(rules, ml_user, base_mode, best["ml_weight"], best["ml_floor"])
        r = daily_risk(det, days, best["decay"])
        for split in ("val", "test"):
            rows.append({"dataset": ds, "mode": mode, "split": split, "budget_per_day": k,
                         **best, **evaluate(r, det, truth, splits[split], kq, hq)})
        if mode == modes[-1]:          # thiết kế cuối cùng → dùng cho incident
            r.to_parquet(STATE_DIR / f"risk_{ds}.parquet", index=False)
            (STATE_DIR / f"risk_params_{ds}.json").write_text(
                json.dumps({**best, "user_queue": kq}), encoding="utf-8")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["lanl", "cert", "all"], default="all")
    a = ap.parse_args()
    rows = []
    for ds in (["lanl", "cert"] if a.dataset == "all" else [a.dataset]):
        print(f"[{ds}]", flush=True)
        rows += run(ds)
    res = pd.DataFrame(rows)
    out = SOC_REPORTS / "risk_eval.csv"
    if a.dataset != "all" and out.exists():      # giữ kết quả của bộ dữ liệu không chạy lại
        old = pd.read_csv(out)
        res = pd.concat([old[old["dataset"] != a.dataset], res], ignore_index=True)
    res.to_csv(out, index=False)
    print(res.to_string(index=False))


if __name__ == "__main__":
    main()
