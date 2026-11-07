"""A8 – Xuất alerts.json đúng ../schema/alert.schema.json và (tuỳ chọn) đẩy vào Elasticsearch.

  python src/export_alerts.py                       # test split, ngưỡng 0.995
  python src/export_alerts.py --split all --top 500
  python src/export_alerts.py --es http://localhost:9200 --index alerts-ueba
"""
from __future__ import annotations

import argparse
import math
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from common import MITRE, ML_DIR, SCHEMA, env, load_df, load_json, save_json

KEY_FEATURES = ["n_events", "n_fail", "fail_ratio", "distinct_dst", "distinct_src", "new_src",
                "new_dst", "ntlm_ratio", "offhours_ratio", "peak_per_min", "interval_cv",
                "active_hours_day"]
NS = uuid.UUID("6f1c2b7e-0000-4000-8000-0000000000a1")


def severity(score: float, n_rules: int) -> str:
    if score >= 0.9995 or (score >= 0.998 and n_rules > 0):
        return "critical"
    if score >= 0.998:
        return "high"
    if score >= 0.996:
        return "medium"
    return "low"


def mitre_for(row, mp) -> dict:
    beh = None
    if isinstance(row.rule_id, str):
        beh = mp["rule_to_behavior"].get(row.rule_id)
    beh = beh or mp["feature_to_behavior"].get(row.top_feature) or mp["default_behavior"]
    b = mp["behaviors"][beh]
    return {"tactic": b["tactic"], "technique_id": b["technique_id"], "technique_name": b["technique_name"]}


def _num(v):
    v = float(v)
    return None if math.isnan(v) else (int(v) if v.is_integer() else round(v, 4))


def build_alerts(df: pd.DataFrame, base: datetime) -> list[dict]:
    mp = load_json(MITRE)
    alerts = []
    for r in df.itertuples(index=False):
        feats = {k: _num(getattr(r, k)) for k in KEY_FEATURES}
        feats.update({"top_feature": r.top_feature, "top_z": _num(r.top_z),
                      "score_if": _num(r.norm_if), "score_ae": _num(r.norm_ae),
                      "score_stat": _num(r.norm_stat), "score_rule": _num(r.norm_rule),
                      "peer_group": int(r.peer)})
        hp = None if pd.isna(r.is_human_prob) else round(float(r.is_human_prob), 4)
        alerts.append({
            "alert_id": str(uuid.uuid5(NS, f"{r.user}|{r.win}")),
            "timestamp": (base + timedelta(seconds=int(r.ts))).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "user": r.user,
            "src_host": r.src_host,
            "dst_host": r.dst_host,
            "source": "ml",
            "rule_id": r.rule_id if isinstance(r.rule_id, str) else None,
            "anomaly_score": round(float(r.anomaly_score), 4),
            "is_human_prob": hp,
            "severity": severity(float(r.anomaly_score), int(r.n_rules)),
            "mitre": mitre_for(r, mp),
            "features": feats,
            "agent_analysis": None,
        })
    return alerts


def validate(alerts):
    try:
        import jsonschema
    except ImportError:
        print("  (chưa cài jsonschema – bỏ qua kiểm tra schema)")
        return
    if not SCHEMA.exists():
        print(f"  (không thấy {SCHEMA} – bỏ qua kiểm tra schema)")
        return
    schema = load_json(SCHEMA)
    for a in alerts:
        jsonschema.validate(a, schema)
    print(f"  {len(alerts)} alert hợp lệ theo {SCHEMA.name}")


def push_es(alerts, url, index):
    try:
        from elasticsearch import Elasticsearch, helpers
    except ImportError:
        raise SystemExit("pip install elasticsearch  (đã có trong requirements.txt)")
    es = Elasticsearch(url, basic_auth=("elastic", env("ELASTIC_PASSWORD", "changeme")),
                       verify_certs=False)
    ok, _ = helpers.bulk(es, ({"_index": index, "_id": a["alert_id"], "_source": a} for a in alerts))
    print(f"  đẩy {ok} alert vào {url}/{index}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="test", choices=["train", "val", "test", "all"])
    ap.add_argument("--min-score", type=float, default=0.995)
    ap.add_argument("--top", type=int, default=None, help="chỉ lấy N alert điểm cao nhất")
    ap.add_argument("--base-date", default="2026-10-01T00:00:00Z",
                    help="LANL dùng giây tương đối -> cộng vào mốc này để ra ISO 8601")
    ap.add_argument("--out", default=str(ML_DIR / "reports" / "alerts.json"))
    ap.add_argument("--es", default=None, help="URL Elasticsearch, vd http://localhost:9200")
    ap.add_argument("--index", default="alerts-ueba")
    a = ap.parse_args()

    df = load_df("scores")
    if a.split != "all":
        df = df[df.split == a.split]
    df = df[df.anomaly_score >= a.min_score].sort_values("anomaly_score", ascending=False)
    if a.top:
        df = df.head(a.top)
    base = datetime.fromisoformat(a.base_date.replace("Z", "+00:00")).astimezone(timezone.utc)
    alerts = build_alerts(df, base)
    validate(alerts)
    save_json(alerts, Path(a.out))
    n_tp = int(df.label.sum())
    print(f"Xuất {len(alerts)} alert -> {a.out} (trong đó {n_tp} trùng red team)")
    print("  severity:", pd.Series([x['severity'] for x in alerts]).value_counts().to_dict())
    if a.es:
        push_es(alerts, a.es, a.index)


if __name__ == "__main__":
    main()
