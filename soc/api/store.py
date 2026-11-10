"""Truy cập Elasticsearch cho web app (user `soc_app` quyền tối thiểu) và nhật ký kiểm toán.
Mọi dữ liệu trả cho analyst đi qua `public()` để BỎ nhãn đánh giá (ground truth) – analyst phải
tự điều tra như thật, nhãn chỉ dùng để chấm điểm hệ thống.
"""
import json
import os
from datetime import datetime, timezone
from functools import lru_cache

from elasticsearch import Elasticsearch, NotFoundError

from soc.config import ES_CA, ES_URL, INDEX, STATE_DIR

HIDDEN = {"ground_truth", "label.redteam", "label.malicious"}


@lru_cache(maxsize=1)
def es() -> Elasticsearch:
    pw = os.environ.get("SOC_APP_ES_PASSWORD", "")
    if not pw:
        raise RuntimeError("Thiếu SOC_APP_ES_PASSWORD – chạy python -m soc.elastic.indices")
    return Elasticsearch(ES_URL, basic_auth=("soc_app", pw), ca_certs=str(ES_CA),
                         request_timeout=30)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def public(doc: dict, show_truth: bool = False) -> dict:
    if show_truth:
        return doc
    return {k: v for k, v in doc.items() if k not in HIDDEN}


def audit(actor: str, actor_type: str, action: str, target: str = "", detail=None,
          outcome: str = "success"):
    es().index(index=INDEX["audit"], document={
        "@timestamp": now(), "actor": actor, "actor_type": actor_type, "action": action,
        "target": target, "detail": detail or {}, "outcome": outcome})


# ---------------------------------------------------------------- incident / alert
def list_incidents(dataset=None, status=None, severity=None, q=None, size=200,
                   show_truth=False) -> list[dict]:
    must = []
    for f, v in (("dataset", dataset), ("status", status), ("severity", severity)):
        if v:
            must.append({"term": {f: v}})
    if q:
        must.append({"bool": {"should": [{"term": {"entity": q}}, {"term": {"users": q}},
                                         {"term": {"hosts": q}}, {"term": {"mitre_ids": q}},
                                         {"term": {"incident_id": q}}]}})
    r = es().search(index=INDEX["incidents"], query={"bool": {"must": must}}, size=size,
                    sort=[{"max_risk": "desc"}])
    return [public(h["_source"], show_truth) for h in r["hits"]["hits"]]


def get_incident(inc_id: str, show_truth=False) -> dict | None:
    try:
        return public(es().get(index=INDEX["incidents"], id=inc_id)["_source"], show_truth)
    except NotFoundError:
        return None


def update_incident(inc_id: str, fields: dict):
    es().update(index=INDEX["incidents"], id=inc_id, doc=fields, refresh=True)


def incident_alerts(inc_id: str, show_truth=False) -> list[dict]:
    r = es().search(index=INDEX["alerts"], query={"term": {"incident_id": inc_id}}, size=500,
                    sort=[{"timestamp": "asc"}])
    return [public(h["_source"], show_truth) for h in r["hits"]["hits"]]


def entity_alerts(entity: str, size=500, show_truth=False) -> list[dict]:
    r = es().search(index=INDEX["alerts"], query={"term": {"entity": entity}}, size=size,
                    sort=[{"timestamp": "asc"}])
    return [public(h["_source"], show_truth) for h in r["hits"]["hits"]]


def dashboard() -> dict:
    inc = es().search(index=INDEX["incidents"], size=0, aggs={
        "by_status": {"terms": {"field": "status"}},
        "by_severity": {"terms": {"field": "severity"}},
        "by_dataset": {"terms": {"field": "dataset"}},
        "by_tactic": {"terms": {"field": "tactics", "size": 30}},
        "by_technique": {"terms": {"field": "mitre_ids", "size": 50}},
        "by_verdict": {"terms": {"field": "verdict", "missing": "none"}},
    })
    al = es().search(index=INDEX["alerts"], size=0, track_total_hits=True, aggs={
        "by_source": {"terms": {"field": "source"}},
        "by_dataset": {"terms": {"field": "dataset"},
                       "aggs": {"per_day": {"date_histogram": {"field": "timestamp",
                                                               "calendar_interval": "day"},
                                            "aggs": {"src": {"terms": {"field": "source"}}}}}},
        "by_rule": {"terms": {"field": "rule_id", "size": 30, "missing": "ml"}},
    })
    b = lambda r, k: {x["key"]: x["doc_count"] for x in r["aggregations"][k]["buckets"]}  # noqa
    per_day = {}
    for ds in al["aggregations"]["by_dataset"]["buckets"]:
        per_day[ds["key"]] = [{"day": x["key_as_string"][:10],
                               **{s["key"]: s["doc_count"] for s in x["src"]["buckets"]}}
                              for x in ds["per_day"]["buckets"]]
    return {"incidents_total": inc["hits"]["total"]["value"],
            "alerts_total": al["hits"]["total"]["value"],
            "by_status": b(inc, "by_status"), "by_severity": b(inc, "by_severity"),
            "by_dataset": b(inc, "by_dataset"), "by_tactic": b(inc, "by_tactic"),
            "by_technique": b(inc, "by_technique"), "by_verdict": b(inc, "by_verdict"),
            "alerts_by_source": b(al, "by_source"), "alerts_by_rule": b(al, "by_rule"),
            "alerts_per_day": per_day}


def soc_ops() -> dict:
    """Chỉ số vận hành theo giờ thật: MTTA = incident xuất hiện → analyst kết luận;
    MTTR = incident xuất hiện → lead duyệt hành động ứng phó đầu tiên."""
    r = es().search(index=INDEX["incidents"], size=2000, source=[
        "created_at", "verdict_at", "actions", "status", "severity"], query={"match_all": {}})
    ts = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))  # noqa: E731
    tta, ttr, backlog = [], [], {}
    docs = [h["_source"] for h in r["hits"]["hits"]]
    for i in docs:
        if i.get("status") != "closed":
            backlog[i.get("severity", "medium")] = backlog.get(i.get("severity", "medium"), 0) + 1
        if not i.get("created_at"):
            continue
        c = ts(i["created_at"])
        if i.get("verdict_at"):
            tta.append((ts(i["verdict_at"]) - c).total_seconds() / 60)
        ok = [ts(a["at"]) for a in i.get("actions") or [] if a.get("decision") == "approve"]
        if ok:
            ttr.append((min(ok) - c).total_seconds() / 60)
    med = lambda x: round(sorted(x)[len(x) // 2], 1) if x else None  # noqa: E731
    return {"incidents": len(docs), "triaged": len(tta), "responded": len(ttr),
            "mtta_min": round(sum(tta) / len(tta), 1) if tta else None, "mtta_median_min": med(tta),
            "mttr_min": round(sum(ttr) / len(ttr), 1) if ttr else None, "mttr_median_min": med(ttr),
            "backlog": backlog}


# ---------------------------------------------------------------- sự kiện (bằng chứng)
def _events_index(dataset):
    return INDEX["events_lanl"] if dataset == "lanl" else INDEX["events_cert"]


def _entity_query(dataset, entity, start=None, end=None):
    if entity.startswith("host:"):
        q = [{"term": {"source.host": entity.removeprefix("host:")}}]
    else:
        q = [{"term": {"user.name": entity}}]
    if start or end:
        q.append({"range": {"@timestamp": {k: v for k, v in (("gte", start), ("lte", end)) if v}}})
    return {"bool": {"filter": q}}


def event_summary(dataset: str, entity: str, start=None, end=None) -> dict:
    """Thống kê sự kiện của thực thể – bằng chứng cô đọng cho analyst."""
    if dataset == "lanl":
        aggs = {f: {"terms": {"field": f, "size": 15}} for f in
                ("destination.host", "source.host", "user.name", "auth.type", "logon.type",
                 "event.outcome", "event.action")}
    else:
        aggs = {f: {"terms": {"field": f, "size": 15}} for f in
                ("event.dataset", "host.name", "url.domain", "url.category", "file.extension",
                 "event.action")}
        aggs["offhours"] = {"filter": {"term": {"event.offhours": True}}}
        aggs["rare_domains"] = {"filter": {"range": {"url.org_popularity": {"lt": 0.01}}},
                                "aggs": {"d": {"terms": {"field": "url.domain", "size": 15}}}}
        aggs["external_email_attach"] = {"filter": {"bool": {"filter": [
            {"range": {"email.external_recipients": {"gte": 1}}},
            {"range": {"email.attachments": {"gte": 1}}}]}}}
    aggs["per_hour"] = {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h",
                                           "min_doc_count": 1}}
    r = es().search(index=_events_index(dataset), query=_entity_query(dataset, entity, start, end),
                    size=0, aggs=aggs, track_total_hits=True)
    out = {"total_events": r["hits"]["total"]["value"]}
    for k, v in r["aggregations"].items():
        if "buckets" in v:
            out[k] = {(x.get("key_as_string") or x["key"]): x["doc_count"] for x in v["buckets"]}
        elif "d" in v:
            out[k] = {x["key"]: x["doc_count"] for x in v["d"]["buckets"]}
        else:
            out[k] = v["doc_count"]
    return out


def events(dataset: str, entity: str, start=None, end=None, size=50, filters: dict | None = None):
    q = _entity_query(dataset, entity, start, end)
    for f, v in (filters or {}).items():
        q["bool"]["filter"].append({"term": {f: v}})
    r = es().search(index=_events_index(dataset), query=q, size=min(size, 200),
                    sort=[{"@timestamp": "asc"}])
    return [public(h["_source"]) for h in r["hits"]["hits"]]


# ---------------------------------------------------------------- IOC
IOC_FILE = STATE_DIR / "ioc.json"


def list_ioc(active_only=False) -> list[dict]:
    q = {"term": {"active": True}} if active_only else {"match_all": {}}
    r = es().search(index=INDEX["ioc"], query=q, size=500, sort=[{"created_at": "desc"}])
    return [h["_source"] | {"_id": h["_id"]} for h in r["hits"]["hits"]]


def add_ioc(value: str, typ: str, incident_id: str, actor: str, reason: str):
    es().index(index=INDEX["ioc"], id=f"{typ}:{value}", refresh=True, document={
        "value": value, "type": typ, "incident_id": incident_id, "created_at": now(),
        "created_by": actor, "reason": reason, "active": True})
    sync_ioc_file()


def deactivate_ioc(ioc_id: str):
    es().update(index=INDEX["ioc"], id=ioc_id, doc={"active": False}, refresh=True)
    sync_ioc_file()


def sync_ioc_file():
    """Ghi IOC đang hoạt động ra file cho engine luật (placeholder %ioc_hosts% của Sigma)."""
    items = [{"value": i["value"], "type": i["type"]} for i in list_ioc(active_only=True)
             if i["type"] == "host"]
    IOC_FILE.write_text(json.dumps(items, indent=2), encoding="utf-8")


def audit_log(size=200) -> list[dict]:
    r = es().search(index=INDEX["audit"], size=size, sort=[{"@timestamp": "desc"}])
    return [h["_source"] for h in r["hits"]["hits"]]
