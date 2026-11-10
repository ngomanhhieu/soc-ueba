"""A7 + A8 – Gắn MITRE ATT&CK và xuất cảnh báo ra alerts.json đúng schema/alert.schema.json.

Đây là "hợp đồng dữ liệu" (schema chung) để nạp vào Elasticsearch / web app / AI Agent (soc/).
LANL đã ẩn danh thời gian (giây tính từ 1), nên timestamp được quy đổi từ một ngày gốc
giả định (BASE_DATE) – ghi rõ điều này trong báo cáo.

Chạy:  python src/export_alerts.py [--threshold 0.99] [--es-url http://localhost:9200]
"""
import argparse
import json
from datetime import datetime, timedelta, timezone

import jsonschema
import pandas as pd
import pyarrow.parquet as pq

from config import LANL_EVENTS_DIR, MITRE_PATH, PROCESSED_DIR, REPORTS_DIR, SCHEMA_PATH

BASE_DATE = datetime(2026, 9, 1, tzinfo=timezone.utc)   # mốc quy đổi thời gian LANL
SCORES_PATH = PROCESSED_DIR / "lanl_scores.parquet"
OUT_PATH = REPORTS_DIR / "alerts.json"
ALERT_FEATURES = ["n_events", "n_dst_comp", "n_new_dst_comp", "new_dst_ratio", "n_new_src_comp",
                  "new_src_max_fanin", "src_max_fanin", "n_new_edge", "fail_ratio",
                  "ntlm_ratio", "remote_ratio", "unusual_hour_ratio", "max_per_minute"]
IOC_RULE = "ioc_known_attacker_host"


def severity(score: float) -> str:
    if score >= 0.999:
        return "critical"
    if score >= 0.995:
        return "high"
    if score >= 0.98:
        return "medium"
    return "low"


def map_mitre(reasons, mapping) -> dict:
    for rule in mapping["rules"]:
        if any(r in rule["when_any"] for r in reasons):
            return {k: rule[k] for k in ("tactic", "technique_id", "technique_name")}
    return dict(mapping["default"])


def host_context(alerts: pd.DataFrame) -> pd.DataFrame:
    """Lấy máy nguồn/đích phổ biến nhất và thời điểm sự kiện đầu tiên của user trong ngày."""
    rows = []
    for day, grp in alerts.groupby("day"):
        path = LANL_EVENTS_DIR / f"auth_day{int(day):02d}.parquet"
        if not path.exists():
            continue
        ev = pq.read_table(path, columns=["time", "src_user", "src_comp", "dst_comp"],
                           filters=[("src_user", "in", list(grp["src_user"]))]).to_pandas()
        remote = ev[ev["src_comp"] != ev["dst_comp"]]
        for user, e in ev.groupby("src_user"):
            r = remote[remote["src_user"] == user]
            base = r if len(r) else e
            rows.append({"src_user": user, "day": day, "first_time": int(e["time"].min()),
                         "src_host": base["src_comp"].mode().iat[0],
                         "dst_host": base["dst_comp"].mode().iat[0]})
    return pd.DataFrame(rows)


def build_alerts(scores: pd.DataFrame, threshold: float, max_alerts: int) -> list[dict]:
    mapping = json.loads(MITRE_PATH.read_text(encoding="utf-8"))
    cand = scores[(scores["account_type"] == "human") & (scores["alert_score"] >= threshold)]
    cand = cand.sort_values("alert_score", ascending=False).head(max_alerts).copy()
    ctx = host_context(cand)
    if len(ctx):
        cand = cand.merge(ctx, on=["src_user", "day"], how="left")

    alerts = []
    for i, r in enumerate(cand.itertuples(index=False), start=1):
        t = getattr(r, "first_time", None)
        t = int(r.day) * 86400 if pd.isna(t) else int(t)
        reasons = list(r.top_reasons) if r.top_reasons is not None else []
        ioc = bool(getattr(r, "ioc_hit", False))
        alerts.append({
            "alert_id": f"lanl-{int(r.day):02d}-{i:05d}",
            "timestamp": (BASE_DATE + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "user": r.src_user,
            "src_host": None if pd.isna(getattr(r, "src_host", None)) else r.src_host,
            "dst_host": None if pd.isna(getattr(r, "dst_host", None)) else r.dst_host,
            # đăng nhập từ máy đã được analyst xác nhận là máy tấn công → cảnh báo theo luật IOC
            "source": "rule" if ioc else "ml",
            "rule_id": IOC_RULE if ioc else None,
            "anomaly_score": round(float(r.alert_score), 4),
            "is_human_prob": round(float(r.is_human_prob), 4),
            "severity": "critical" if ioc else severity(float(r.alert_score)),
            "mitre": map_mitre(reasons, mapping),
            "features": {
                **{f: round(float(getattr(r, f)), 4) for f in ALERT_FEATURES},
                "top_reasons": reasons,
                "ecod_score": round(float(r.ecod_score), 4),
                "iforest_lateral_score": round(float(r.iforest_lateral_score), 4),
                "ioc_hit": ioc,
                "dataset": "LANL", "day": int(r.day),
                "ground_truth_redteam": bool(r.is_redteam),
            },
        })
    return alerts


def push_to_es(alerts, es_url, index="soc-alerts"):
    from elasticsearch import Elasticsearch, helpers
    es = Elasticsearch(es_url)
    helpers.bulk(es, ({"_index": index, "_id": a["alert_id"], "_source": a} for a in alerts))
    print(f"Đã đẩy {len(alerts)} cảnh báo vào {es_url}/{index}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=float, default=0.99)
    ap.add_argument("--max-alerts", type=int, default=500)
    ap.add_argument("--split", default="test", help="test | train | all")
    ap.add_argument("--es-url", default=None)
    args = ap.parse_args()

    scores = pd.read_parquet(SCORES_PATH)
    if args.split != "all":
        scores = scores[scores["split"] == args.split]
    alerts = build_alerts(scores, args.threshold, args.max_alerts)

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for a in alerts:
        jsonschema.validate(a, schema)
    OUT_PATH.write_text(json.dumps(alerts, indent=2, ensure_ascii=False), encoding="utf-8")
    hit = sum(a["features"]["ground_truth_redteam"] for a in alerts)
    print(f"Đã xuất {len(alerts)} cảnh báo (hợp lệ theo schema, {hit} trùng red team) → {OUT_PATH}")
    if args.es_url:
        push_to_es(alerts, args.es_url)


if __name__ == "__main__":
    main()
