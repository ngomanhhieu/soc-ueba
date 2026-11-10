"""Chạy luật Sigma trên LANL / CERT, dò ngưỡng (không nhãn) và đánh giá từng luật.

  python -m soc.rules.run_rules tune      # dò ngưỡng trên giai đoạn TRAIN chỉ theo lưu lượng
  python -m soc.rules.run_rules run       # chạy luật với ngưỡng đã chọn → cảnh báo + đánh giá

Ngưỡng: với mỗi luật tương quan có ngưỡng số, chọn giá trị NHỎ NHẤT mà số cảnh báo trung bình
mỗi ngày trên giai đoạn train ≤ --budget (mặc định 3/ngày/luật). Không nhìn nhãn → không rò rỉ.
Chia giai đoạn giống phần ML: LANL train 1–7 | val 8–19 | test 20–29;
CERT train [warm-up 30 ngày, 2010-07-01) | val [2010-07-01, 2010-09-01) | test từ 2010-09-01.

Kết quả: <STATE_DIR>/rule_alerts_{lanl,cert}.parquet, soc/reports/rules_eval.csv,
         soc/rules/thresholds.json
"""
import argparse
import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

from soc.config import PROCESSED_DIR, SOC_REPORTS, STATE_DIR
from soc.rules.datasets import cert_events, lanl_day
from soc.rules.sigma_engine import RuleSet, load_rules

RULE_DIR = Path(__file__).parent / "sigma"
THRESH_PATH = Path(__file__).parent / "thresholds.json"
LANL_SPLITS = {"train": range(1, 8), "val": range(8, 20), "test": range(20, 30)}
LANL_LIVE = range(30, 58)   # ngày mới sau test (không có nhãn red team) – demo "New days"
CERT_VAL, CERT_TEST, CERT_WARMUP = "2010-07-01", "2010-09-01", 30
FLOORS = {"event_count": 2, "value_count": 2}
CANDIDATES = [2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 25, 30, 40, 50, 75, 100, 150, 200, 300, 500,
              1000]


def ruleset(**kw) -> RuleSet:
    th = json.loads(THRESH_PATH.read_text(encoding="utf-8")) if THRESH_PATH.exists() else {}
    return RuleSet(load_rules(RULE_DIR), thresholds={k: v["threshold"] for k, v in th.items()},
                   **kw)


def ioc_hosts() -> list[str]:
    p = STATE_DIR / "ioc.json"
    return [i["value"] for i in json.loads(p.read_text(encoding="utf-8"))] if p.exists() else []


# ---------------------------------------------------------------- LANL
def _lanl_worker(args):
    day, tune = args
    rs = ruleset(label_col="is_redteam", tune=tune,
                 placeholders={"ioc_hosts": ioc_hosts()}).for_logsource("lanl")
    al = rs.run({"auth": lanl_day(day)})
    if len(al):
        al["day"] = day
    print(f"  LANL ngày {day:02d}: {len(al):,} cảnh báo", flush=True)
    return al


def is_ioc_rule(rule) -> bool:
    """Luật dùng danh sách IOC (kết quả thay đổi theo quyết định của analyst)."""
    return "IOC" in rule.title


def lanl_ioc_rules(day: int) -> pd.DataFrame:
    """Chỉ chạy các luật IOC cho 1 ngày (demo replay): các luật khác không phụ thuộc analyst nên
    dùng lại kết quả đã chạy sẵn. Chưa có IOC nào → không cần đọc log."""
    hosts = ioc_hosts()
    if not hosts:
        return pd.DataFrame()
    full = ruleset(label_col="is_redteam", placeholders={"ioc_hosts": hosts})
    ioc = [r for r in full.rules if is_ioc_rule(r)]
    rs = RuleSet(ioc, full.placeholders, full.thresholds, full.label_col).for_logsource("lanl")
    al = rs.run({"auth": lanl_day(day)})
    if len(al):
        al["day"] = day
    return al


def run_lanl(days, tune=None, workers=2) -> pd.DataFrame:
    with ProcessPoolExecutor(workers) as ex:
        parts = list(ex.map(_lanl_worker, [(d, tune) for d in days]))
    return pd.concat([p for p in parts if len(p)], ignore_index=True)


# ---------------------------------------------------------------- CERT
def cert_labels() -> set:
    f = pd.read_parquet(PROCESSED_DIR / "cert_user_day_features.parquet",
                        columns=["user", "date", "is_malicious"])
    f = f[f["is_malicious"]]
    return set(zip(f["user"].astype(str), f["date"].values.astype("datetime64[D]")))


def run_cert(tune=None) -> pd.DataFrame:
    ev = cert_events()
    mal = cert_labels()
    for df in ev.values():   # nhãn theo (user, ngày) – chỉ để đếm khi đánh giá
        day = df["@timestamp"].values.astype("datetime64[s]").astype("datetime64[D]")
        df["is_malicious"] = [(u, d) in mal for u, d in zip(df["user.name"].astype(str), day)]
    rs = ruleset(label_col="is_malicious", tune=tune).for_logsource("cert")
    al = rs.run(ev)
    al["date"] = pd.to_datetime(al["window_start"], unit="s").dt.floor("D")
    return al


def cert_split(dates: pd.Series) -> np.ndarray:
    start = dates.min() + pd.Timedelta(days=CERT_WARMUP)
    return np.select([dates < start, dates < pd.Timestamp(CERT_VAL), dates < pd.Timestamp(CERT_TEST)],
                     ["warmup", "train", "val"], "test")


# ---------------------------------------------------------------- dò ngưỡng
def tune(budget: float, workers: int):
    rules = {r.id: r for r in load_rules(RULE_DIR) if r.is_correlation
             and r.raw["correlation"]["type"] in FLOORS}
    out = {}
    lanl = run_lanl(list(LANL_SPLITS["train"]), tune={"gte": 2}, workers=workers)
    cert = run_cert(tune={"gte": 2})
    cert = cert[cert_split(cert["date"]) == "train"]
    n_days = {"lanl": len(LANL_SPLITS["train"]), "cert": cert["date"].nunique()}
    for ds, al in (("lanl", lanl), ("cert", cert)):
        for rid, g in al.groupby("rule_id"):
            if rid not in rules:
                continue
            cur = rules[rid].raw["correlation"]["condition"]["gte"]
            per_day = {n: float((g["value"] >= n).sum() / n_days[ds]) for n in CANDIDATES}
            ok = [n for n in CANDIDATES if per_day[n] <= budget]
            chosen = ok[0] if ok else CANDIDATES[-1]
            out[rid] = {"title": rules[rid].title, "dataset": ds, "threshold": int(chosen),
                        "yaml_default": cur, "alerts_per_day_train": round(per_day[chosen], 2),
                        "sweep": {str(k): round(v, 2) for k, v in per_day.items()}}
            print(f"  {ds} | {rules[rid].title[:60]:60s} ngưỡng {cur} → {chosen} "
                  f"({per_day[chosen]:.2f} cảnh báo/ngày ở train)")
    THRESH_PATH.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"→ {THRESH_PATH}")


# ---------------------------------------------------------------- đánh giá
def lanl_truth() -> pd.DataFrame:
    f = pd.read_parquet(PROCESSED_DIR / "lanl_user_day_features.parquet",
                        columns=["src_user", "day", "is_redteam", "account_type"])
    return f[f["is_redteam"]]


def entities(al: pd.DataFrame, user_col="user.name") -> set:
    """(user, ngày) mà cảnh báo trỏ tới: user của nhóm, hoặc các user có sự kiện độc hại trong
    cảnh báo gom theo máy (để biết luật gom theo máy có 'chạm' đúng tài khoản bị chiếm không)."""
    ents = set()
    day_col = "day" if "day" in al else "date"
    cols = [c for c in (user_col, "label_users", day_col) if c in al.columns]
    for row in al[cols].to_dict("records"):
        d = row[day_col]
        if isinstance(row.get(user_col), str):
            ents.add((row[user_col], d))
        lu = row.get("label_users")
        if isinstance(lu, (list, np.ndarray)):
            ents |= {(x, d) for x in lu}
    return ents


def evaluate(al: pd.DataFrame, truth: set, split_of, n_days: dict) -> list[dict]:
    rows = []
    al = al.copy()
    al["split"] = split_of(al)
    for (rid, title), g0 in list(al.groupby(["rule_id", "rule_title"])) + [(("ALL", "Mọi luật"), al)]:
        for split in ("train", "val", "test"):
            g = g0[g0["split"] == split]
            t = {e for e in truth if e[2] == split}
            t2 = {(u, d) for u, d, _ in t}
            hit = entities(g) & t2
            rows.append({"rule_id": rid, "rule": title, "split": split, "alerts": len(g),
                         "alerts_per_day": round(len(g) / n_days[split], 2),
                         "precision": round(float((g["n_label"] > 0).mean()), 3) if len(g) else None,
                         "malicious_user_days_hit": len(hit), "malicious_user_days": len(t2),
                         "accounts_hit": len({u for u, _ in hit}),
                         "accounts": len({u for u, _ in t2})})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["tune", "run"])
    ap.add_argument("--budget", type=float, default=3.0, help="cảnh báo/ngày/luật ở train")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--dataset", choices=["lanl", "cert", "all"], default="all")
    ap.add_argument("--new-days-only", action="store_true",
                    help="LANL: chỉ chạy các ngày chưa có trong kết quả cũ rồi nối vào")
    a = ap.parse_args()
    if a.cmd == "tune":
        return tune(a.budget, a.workers)

    rows = []
    if a.dataset in ("lanl", "all"):
        from features import available_days
        want = [d for d in available_days() if d >= 1]
        old_p = STATE_DIR / "rule_alerts_lanl.parquet"
        if a.new_days_only and old_p.exists():
            old = pd.read_parquet(old_p)
            want = [d for d in want if d > old["day"].max()]
            lanl = pd.concat([old, run_lanl(want, workers=a.workers)], ignore_index=True)
        else:
            lanl = run_lanl(want, workers=a.workers)
        lanl.to_parquet(STATE_DIR / "rule_alerts_lanl.parquet", index=False)
        lanl = lanl[lanl["day"] < LANL_LIVE.start]          # đánh giá chỉ trên train/val/test
        t = lanl_truth()
        split_day = {d: s for s, ds in LANL_SPLITS.items() for d in ds}
        truth = {(u, d, split_day[d]) for u, d in zip(t["src_user"], t["day"]) if d in split_day}
        rows += [dict(r, dataset="lanl") for r in evaluate(
            lanl, truth, lambda x: x["day"].map(split_day).values,
            {s: len(d) for s, d in LANL_SPLITS.items()})]
    if a.dataset in ("cert", "all"):
        cert = run_cert()
        cert.to_parquet(STATE_DIR / "rule_alerts_cert.parquet", index=False)
        f = pd.read_parquet(PROCESSED_DIR / "cert_user_day_features.parquet",
                            columns=["user", "date", "is_malicious"])
        sp = pd.Series(cert_split(f["date"]), index=f.index)
        truth = {(u, d, s) for u, d, s, m in zip(f["user"], f["date"], sp, f["is_malicious"]) if m}
        n_days = f.assign(split=sp).groupby("split")["date"].nunique().to_dict()
        rows += [dict(r, dataset="cert") for r in evaluate(
            cert, truth, lambda x: cert_split(x["date"]), n_days)]
    res = pd.DataFrame(rows)
    out = SOC_REPORTS / f"rules_eval_{a.dataset}.csv"
    res.to_csv(out, index=False)
    with pd.option_context("display.width", 220, "display.max_colwidth", 60):
        print(res.to_string(index=False))
    print(f"→ {out}")


if __name__ == "__main__":
    main()
