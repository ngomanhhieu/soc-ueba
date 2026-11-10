"""Chuẩn hoá cảnh báo (luật + ML) theo schema chung và gom thành incident theo thực thể.

Cảnh báo: mỗi phát hiện của luật Sigma / ML → 1 document theo schema/alert.schema.json (thêm
entity, dataset, mitre_ids, incident_id). MITRE tra từ ATT&CK chính thức (soc/mitre).
Incident: mỗi ngày analyst mở top-K thực thể rủi ro cao nhất (Lớp 4); các ngày liên tiếp (cách
nhau ≤ GAP ngày) của cùng thực thể gộp thành 1 incident, kèm mọi cảnh báo của thực thể trong
khoảng đó. Mặc định chỉ dựng cho giai đoạn TEST (dữ liệu "triển khai").

Chạy:  python -m soc.risk.incidents [--splits test]
Kết quả: <STATE_DIR>/alerts_{ds}.json, <STATE_DIR>/incidents_{ds}.json
"""
import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from soc.config import PROCESSED_DIR, SCHEMA_PATH, STATE_DIR
from soc.risk.risk import BUDGET, HOST_BUDGET, host_queue, truth_and_splits

ATTACK = json.loads((Path(__file__).parents[1] / "mitre" / "attack_techniques.json")
                    .read_text(encoding="utf-8"))["techniques"]
LANL_BASE = datetime(2026, 9, 1, tzinfo=timezone.utc)   # LANL ẩn danh thời gian → mốc quy đổi
GAP = 2
SEVERITY = {"informational": "low", "low": "low", "medium": "medium", "high": "high",
            "critical": "critical"}


def mitre_obj(tid: str | None) -> dict | None:
    if not tid or tid not in ATTACK:
        return None
    t = ATTACK[tid]
    return {"tactic": t["tactics"][0] if t["tactics"] else "", "technique_id": tid,
            "technique_name": t["full_name"]}


def ts(ds: str, seconds_or_date) -> str:
    if ds == "lanl":
        dt = LANL_BASE + timedelta(seconds=int(seconds_or_date))
    elif isinstance(seconds_or_date, (int, np.integer, float, np.floating)):   # epoch giây
        dt = datetime.fromtimestamp(int(seconds_or_date), tz=timezone.utc)
    else:
        dt = pd.Timestamp(seconds_or_date).to_pydatetime().replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def day_ts(ds: str, day) -> str:
    return ts(ds, int(day) * 86400) if ds == "lanl" else ts(ds, day)


def _id(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:12]


def _first(v):
    if isinstance(v, (list, np.ndarray)):
        return str(v[0]) if len(v) else None
    return None if v is None or (isinstance(v, float) and np.isnan(v)) else str(v)


def _lst(v):
    return [str(x) for x in v] if isinstance(v, (list, np.ndarray)) else []


BASELINE_DAYS = 30


def rule_titles() -> dict:
    """rule_id → tiêu đề hiện tại trong file Sigma (đổi tiêu đề không cần chạy lại luật)."""
    from soc.rules.run_rules import RULE_DIR
    from soc.rules.sigma_engine import load_rules
    return {r.id: r.title for r in load_rules(RULE_DIR)}


def baseline(s: pd.DataFrame, rows: pd.DataFrame, ucol: str, dcol: str, cols: list) -> list[dict]:
    """Mức BÌNH THƯỜNG của chính người dùng: trung vị mỗi feature trong BASELINE_DAYS ngày trước
    ngày cảnh báo (chỉ nhìn quá khứ) – để web hiện "bình thường vs hôm nay"."""
    cols = [c for c in cols if c in s.columns]
    idx = s.groupby(ucol, observed=True).indices
    out = []
    for u, d in zip(rows[ucol], rows[dcol]):
        h = s.iloc[idx.get(u, [])]
        lo = d - (BASELINE_DAYS if dcol == "day" else pd.Timedelta(days=BASELINE_DAYS))
        h = h[(h[dcol] < d) & (h[dcol] >= lo)]
        out.append({c: round(float(h[c].median()), 4) for c in cols} | {"_days": int(len(h))}
                   if len(h) else {})
    return out


# ---------------------------------------------------------------- cảnh báo
def rule_alerts(ds: str, days: set, src=None) -> list[dict]:
    titles = rule_titles()
    al = pd.read_parquet(src or STATE_DIR / f"rule_alerts_{ds}.parquet")
    dcol = "day" if ds == "lanl" else "date"
    al = al[al[dcol].isin(days)]
    out = []
    for r in al.to_dict("records"):
        user = r.get("user.name")
        is_user = isinstance(user, str)
        host = r.get("source.host")
        entity = user if is_user else f"host:{host}"
        mitre_ids = list(r["mitre"])
        ctx = {k.removeprefix("ctx."): _lst(v) for k, v in r.items()
               if k.startswith("ctx.") and isinstance(v, (list, np.ndarray))}
        out.append({
            "alert_id": f"{ds}-r-{_id(r['rule_id'], entity, r['window_start'])}",
            "timestamp": ts(ds, r["window_start"]),
            "user": entity, "entity": entity, "entity_type": "user" if is_user else "host",
            "src_host": host if isinstance(host, str) else _first(ctx.get("source.host")),
            "dst_host": _first(ctx.get("destination.host")),
            "source": "rule", "rule_id": r["rule_id"],
            "rule_title": titles.get(r["rule_id"], r["rule_title"]),
            "anomaly_score": float(r["rule_score"]), "is_human_prob": None,
            "severity": SEVERITY.get(r["level"], "medium"),
            "mitre": mitre_obj(mitre_ids[0] if mitre_ids else None), "mitre_ids": mitre_ids,
            "dataset": ds, "day": r[dcol],
            "features": {"value": float(r["value"]), "n_events": int(r["n_events"]),
                         "window_start": ts(ds, r["window_start"]),
                         "window_end": ts(ds, r["window_end"]), "context": ctx},
            "ground_truth": bool(r.get("n_label", 0) and r["n_label"] > 0),
        })
    return suppress(ds, out)


SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
MAX_CTX = 50


def suppress(ds: str, alerts: list[dict]) -> list[dict]:
    """Alert suppression: các lần bắn của CÙNG luật, CÙNG thực thể, CÙNG máy nguồn trong 1 ngày gộp
    thành 1 cảnh báo có bộ đếm (count, tổng sự kiện, lần đầu / lần cuối) – analyst thấy "×N" thay
    vì N cảnh báo giống hệt. Chỉ ở tầng hiển thị / lưu trữ: điểm rủi ro vẫn cộng mọi lần bắn."""
    groups = {}
    for a in sorted(alerts, key=lambda a: a["timestamp"]):
        k = (a["rule_id"], a["entity"], a["src_host"], str(a["day"]))
        g = groups.get(k)
        f = a["features"]
        if g is None:
            g = {**a, "alert_id": f"{ds}-r-{_id(*k)}",
                 "features": {**f, "count": 1, "first_seen": f["window_start"],
                              "last_seen": f["window_end"],
                              "context": {c: list(v) for c, v in f["context"].items()}}}
            groups[k] = g
            continue
        gf = g["features"]
        gf["count"] += 1
        gf["n_events"] += f["n_events"]
        gf["value"] = max(gf["value"], f["value"])
        gf["last_seen"] = max(gf["last_seen"], f["window_end"])
        for c, v in f["context"].items():
            cur = gf["context"].setdefault(c, [])
            cur.extend(x for x in v if x not in cur and len(cur) < MAX_CTX)
        g["anomaly_score"] = max(g["anomaly_score"], a["anomaly_score"])
        if SEV_RANK.get(a["severity"], 1) > SEV_RANK.get(g["severity"], 1):
            g["severity"] = a["severity"]
        g["ground_truth"] |= a["ground_truth"]
    return list(groups.values())


def ml_alerts(ds: str, days: set) -> list[dict]:
    """Cảnh báo ML của các ngày `days`. Không phụ thuộc quyết định của analyst → tính MỘT lần cho mọi
    ngày rồi cache (tự tính lại khi file điểm ML thay đổi); demo replay chỉ lọc theo ngày."""
    import pickle
    srcs = [PROCESSED_DIR / f"{ds}_scores.parquet"] + (
        [PROCESSED_DIR / "lanl_host_scores.parquet", PROCESSED_DIR / "lanl_user_day_features.parquet"]
        if ds == "lanl" else [])
    key = [(str(s), s.stat().st_mtime) for s in srcs if s.exists()]
    cache = STATE_DIR / f"ml_alerts_cache_{ds}.pkl"
    data = None
    if cache.exists():
        data = pickle.loads(cache.read_bytes())
        if data.get("key") != key:
            data = None
    if data is None:
        dcol = "day" if ds == "lanl" else "date"
        every = set(pd.read_parquet(srcs[0], columns=[dcol])[dcol].unique())
        data = {"key": key, "alerts": _ml_alerts(ds, every)}
        cache.write_bytes(pickle.dumps(data))
    norm = (lambda d: d) if ds == "lanl" else pd.Timestamp
    want = {norm(d) for d in days}
    return [dict(a) for a in data["alerts"] if norm(a["day"]) in want]


def _ml_alerts(ds: str, days: set) -> list[dict]:
    import sys
    sys.path.insert(0, str(Path(__file__).parents[2] / "ml" / "src"))
    if ds == "lanl":
        from export_alerts import ALERT_FEATURES, map_mitre
        mapping = json.loads((Path(__file__).parents[2] / "ml" / "src" / "mitre_mapping.json")
                             .read_text(encoding="utf-8"))
        full = pd.read_parquet(PROCESSED_DIR / "lanl_scores.parquet")
        s = full[full["day"].isin(days) & (full["alert_score"] >= 0.99)]
        ucol, dcol, label = "src_user", "day", "is_redteam"
    else:
        from cert_pipeline import STAT_COLS as ALERT_FEATURES, cert_mitre
        full = pd.read_parquet(PROCESSED_DIR / "cert_scores.parquet")
        s = full[full["date"].isin(days) & (full["alert_score"] >= 0.995)]
        ucol, dcol, label = "user", "date", "is_malicious"
    base = baseline(full, s, ucol, dcol, list(ALERT_FEATURES))
    out = []
    for r, b in zip(s.to_dict("records"), base):
        reasons = _lst(r.get("top_reasons"))
        tid = (map_mitre(reasons, mapping) if ds == "lanl" else cert_mitre(reasons))["technique_id"]
        score = float(r["alert_score"])
        out.append({
            "alert_id": f"{ds}-m-{_id(r[ucol], r[dcol])}",
            "timestamp": day_ts(ds, r[dcol]), "user": r[ucol], "entity": r[ucol],
            "entity_type": "user", "src_host": None, "dst_host": None, "source": "ml",
            "rule_id": None, "rule_title": "Behaviour unlike this user's own baseline (ML)",
            "anomaly_score": round(score, 4),
            "is_human_prob": round(float(r["is_human_prob"]), 4) if "is_human_prob" in r else None,
            "severity": "critical" if score >= 0.999 else "high" if score >= 0.995 else "medium",
            "mitre": mitre_obj(tid), "mitre_ids": [tid] if tid else [], "dataset": ds,
            "day": r[dcol],
            "features": {**{c: round(float(r[c]), 4) for c in ALERT_FEATURES if c in r},
                         "top_reasons": reasons, "baseline": b,
                         **({"role": r["role"]} if "role" in r else {})},
            "ground_truth": bool(r[label]),
        })
    if ds == "lanl":
        out += host_alerts(ds, days)
    return out


def host_alerts(ds: str, days: set) -> list[dict]:
    """Cảnh báo ML mức máy: máy bàn đạp (ml/src/lanl_hosts.py), chỉ máy trong hàng đợi máy."""
    hq = host_queue(ds)
    hq = hq[hq["day"].isin(days)]
    f = pd.read_parquet(PROCESSED_DIR / "lanl_user_day_features.parquet",
                        columns=["src_user", "day", "is_redteam"])
    bad = set(zip(f.loc[f["is_redteam"], "src_user"], f.loc[f["is_redteam"], "day"]))
    out = []
    for r in hq.to_dict("records"):
        users = [str(u) for u in r["scope_user_list"]]
        ent = f"host:{r['host']}"
        out.append({
            "alert_id": f"{ds}-h-{_id(ent, r['day'])}", "timestamp": day_ts(ds, r["day"]),
            "user": ent, "entity": ent, "entity_type": "host", "src_host": str(r["host"]),
            "dst_host": None, "source": "ml", "rule_id": None,
            "rule_title": ("Watched host (suspected jump host in the last 7 days) is active again"
                           if r.get("watch") else
                           "Jump host: many accounts sign in over NTLM from a host new to them (ML)"),
            "anomaly_score": round(float(r["host_score"]), 4), "is_human_prob": None,
            "severity": "high", "mitre": mitre_obj("T1550.002"), "mitre_ids": ["T1550.002"],
            "dataset": ds, "day": r["day"],
            "features": {"n_users": int(r["n_users"]), "n_rare_users": int(r["n_rare_users"]),
                         "rare_ntlm_users": int(r["rare_ntlm_users"]),
                         "surprise": round(float(r["surprise"]), 2),
                         "context": {"user.name": users}},
            "ground_truth": any((u, r["day"]) in bad for u in users),
        })
    return out


# ---------------------------------------------------------------- incident
def build_incidents(ds: str, alerts: list[dict], days: list, truth: set, risk_src=None) -> list[dict]:
    risk = pd.read_parquet(risk_src or STATE_DIR / f"risk_{ds}.parquet")
    risk = risk[risk["day"].isin(days)]
    k_user = BUDGET[ds] - HOST_BUDGET.get(ds, 0)
    top = risk.sort_values("risk", ascending=False, kind="stable").groupby("day").head(k_user)
    hq = host_queue(ds)
    hq = hq[hq["day"].isin(days)]
    if len(hq):     # máy bàn đạp: "rủi ro" = mức bất ngờ (thang riêng, xếp mức độ riêng)
        top = pd.concat([top, pd.DataFrame({"entity": "host:" + hq["host"].astype(str),
                                            "day": hq["day"].values, "risk": hq["surprise"].values})],
                        ignore_index=True)
    order = {d: i for i, d in enumerate(sorted(days))}
    by_ent = {}
    for a in alerts:
        by_ent.setdefault(a["entity"], []).append(a)
    incidents = []
    for ent, g in top.groupby("entity"):
        g = g.sort_values("day")
        idx = [order[d] for d in g["day"]]
        groups, cur = [], [0]
        for i in range(1, len(idx)):
            if idx[i] - idx[cur[-1]] <= GAP:
                cur.append(i)
            else:
                groups.append(cur)
                cur = [i]
        groups.append(cur)
        for grp in groups:
            d0, d1 = g["day"].iloc[grp[0]], g["day"].iloc[grp[-1]]
            lo = sorted(days)[max(order[d0] - 1, 0)]
            al = [a for a in by_ent.get(ent, []) if lo <= a["day"] <= d1]
            if not al:
                continue
            users = sorted({ent} if not ent.startswith("host:") else
                           {u for a in al for u in a["features"].get("context", {}).get("user.name", [])})
            mitre_ids = sorted({m for a in al for m in a["mitre_ids"]})
            tactics = sorted({t for m in mitre_ids if m in ATTACK for t in ATTACK[m]["tactics"]})
            max_risk = float(g["risk"].iloc[grp].max())
            inc_id = f"INC-{ds.upper()}-{_id(ent, d0)}"
            for a in al:
                a["incident_id"] = inc_id
            titles = sorted({a["rule_title"] for a in al})
            incidents.append({
                "incident_id": inc_id, "entity": ent,
                "entity_type": "host" if ent.startswith("host:") else "user", "dataset": ds,
                "users": users, "hosts": sorted({a["src_host"] for a in al if a["src_host"]}),
                "opened_at": day_ts(ds, d0), "last_seen": day_ts(ds, d1),
                "day_first": d0, "day_last": d1,
                "risk": float(g["risk"].iloc[grp[-1]]), "max_risk": max_risk,
                "status": "new", "alert_ids": [a["alert_id"] for a in al], "n_alerts": len(al),
                "mitre_ids": mitre_ids, "tactics": tactics,
                "detectors": sorted({a["rule_id"] or "ml" for a in al}),
                "title": f"{ent}: " + "; ".join(titles[:3]),
                "verdict": None,
                "ground_truth": any((u, d) in truth for u in users
                                    for d in sorted(days)[order[d0]:order[d1] + 1]),
            })
    # Mức độ theo THỨ HẠNG rủi ro trong bộ dữ liệu (thang điểm mỗi bộ khác nhau): 10% cao nhất
    # critical, 30% tiếp theo high, còn lại medium – hàng đợi luôn phân tầng được.
    for etype in ("user", "host"):     # thang điểm khác nhau → xếp hạng riêng từng loại
        ranked = sorted([i for i in incidents if i["entity_type"] == etype],
                        key=lambda i: -i["max_risk"])
        for r, inc in enumerate(ranked):
            q = r / max(len(ranked), 1)
            inc["severity"] = "critical" if q < 0.10 else "high" if q < 0.40 else "medium"
    return incidents


def _json_default(o):
    if isinstance(o, (pd.Timestamp, datetime)):
        return o.isoformat()
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    raise TypeError(type(o))


def main():
    import jsonschema
    from soc.playbooks.soar import enrich
    ap = argparse.ArgumentParser()
    ap.add_argument("--splits", nargs="+", default=["test"])
    a = ap.parse_args()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for ds in ("lanl", "cert"):
        truth, splits, _ = truth_and_splits(ds)
        days = sorted(d for s in a.splits for d in splits[s])
        alerts = rule_alerts(ds, set(days)) + ml_alerts(ds, set(days))
        incidents = build_incidents(ds, alerts, days, truth)
        enrich(ds, incidents)        # Lớp 5: chuỗi tấn công + playbook SOAR
        for x in alerts:
            jsonschema.validate({k: v for k, v in x.items() if k != "day"}, schema)
        (STATE_DIR / f"alerts_{ds}.json").write_text(
            json.dumps(alerts, default=_json_default, ensure_ascii=False), encoding="utf-8")
        (STATE_DIR / f"incidents_{ds}.json").write_text(
            json.dumps(incidents, default=_json_default, ensure_ascii=False), encoding="utf-8")
        tp = sum(i["ground_truth"] for i in incidents)
        print(f"[{ds}] {len(alerts)} cảnh báo ({sum(x['source'] == 'rule' for x in alerts)} luật, "
              f"{sum(x['source'] == 'ml' for x in alerts)} ML) → {len(incidents)} incident "
              f"({tp} chứa hoạt động độc hại thật)")


if __name__ == "__main__":
    main()
