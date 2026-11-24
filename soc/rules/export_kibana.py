"""Chuyển luật Sigma của dự án sang Detection Engine của Kibana Security (SIEM công nghiệp) bằng
pySigma – bộ công cụ chính thức của SigmaHQ – với backend ES|QL (hỗ trợ luật tương quan).

Engine Python tự viết (sigma_engine.py) vẫn dùng để ĐÁNH GIÁ offline; file này chứng minh cùng các
luật đó chạy được trên SIEM thật. Processing pipeline:
  * điền placeholder %ioc_hosts% bằng danh sách IOC hiện tại (ValueListPlaceholderTransformation);
  * thêm điều kiện event.dataset theo logsource service (pySigma không tự giữ "loại log");
  * dùng ngưỡng đã dò trên TRAIN (thresholds.json) thay ngưỡng mặc định trong YAML;
  * trỏ truy vấn vào đúng index sự kiện (soc-events-lanl / soc-events-cert).

Chạy:  python -m soc.rules.export_kibana            # → soc/rules/kibana/*.ndjson (lưu trong repo)
       python -m soc.rules.export_kibana --push     # + tạo / cập nhật luật trong Kibana
"""
import argparse
import json
import os
import urllib.error
import urllib.request
from base64 import b64encode
from pathlib import Path

import yaml
from sigma.backends.elasticsearch import ESQLBackend
from sigma.collection import SigmaCollection
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (AddConditionTransformation,
                                              ValueListPlaceholderTransformation)

from soc.config import INDEX, KIBANA_URL
from soc.rules.run_rules import RULE_DIR, THRESH_PATH, ioc_hosts

OUT_DIR = Path(__file__).parent / "kibana"
INDEX_OF = {"lanl": INDEX["events_lanl"], "cert": INDEX["events_cert"]}
DATASET_OF = {("lanl", "auth"): "lanl.auth", **{("cert", s): f"cert.{s}" for s in
                                               ("logon", "device", "file", "email", "http")}}
SEVERITY = {"informational": ("low", 21), "low": ("low", 21), "medium": ("medium", 47),
            "high": ("high", 73), "critical": ("critical", 99)}
# Dữ liệu demo LANL nằm ở 09/2026 → nhìn lại 70 ngày để luật chạy được trên dữ liệu đã nạp;
# CERT là năm 2010–2011 nên luật CERT được tạo nhưng để TẮT (sẽ chạy với log mới).
LOOKBACK = {"lanl": "now-70d", "cert": "now-1d"}


def pipeline() -> ProcessingPipeline:
    items = [ProcessingItem(identifier="ioc-list", transformation=ValueListPlaceholderTransformation())]
    for (product, service), ds in DATASET_OF.items():
        items.append(ProcessingItem(
            identifier=f"dataset-{product}-{service}",
            transformation=AddConditionTransformation({"event.dataset": ds}),
            rule_conditions=[LogsourceCondition(product=product, service=service)]))
    # placeholder IOC rỗng → giá trị không thể khớp (luật vẫn hợp lệ, không bắn)
    return ProcessingPipeline(name="soc-ueba", items=items,
                              vars={"ioc_hosts": ioc_hosts() or ["__no_ioc__"]})


def load(product: str) -> tuple[SigmaCollection, dict]:
    """Nạp file luật, thay ngưỡng tương quan bằng ngưỡng đã dò; trả về collection + meta theo tiêu đề."""
    th = json.loads(THRESH_PATH.read_text(encoding="utf-8")) if THRESH_PATH.exists() else {}
    fname = "lanl_auth.yml" if product == "lanl" else "cert_insider.yml"
    docs = [d for d in yaml.safe_load_all((RULE_DIR / fname).read_text(encoding="utf-8")) if d]
    meta = {}
    for d in docs:
        if "correlation" in d:
            if d["id"] in th:
                d["correlation"]["condition"]["gte"] = th[d["id"]]["threshold"]
            meta[d["title"]] = d
    return SigmaCollection.from_yaml(yaml.safe_dump_all(docs, allow_unicode=True, sort_keys=False)), meta


def kibana_rules() -> list[dict]:
    out = []
    for product in ("lanl", "cert"):
        col, meta = load(product)
        backend = ESQLBackend(processing_pipeline=pipeline())
        corr = [r for r in col.rules if type(r).__name__ == "SigmaCorrelationRule"]
        queries = backend.convert(col)        # luật nền được gộp vào luật tương quan tham chiếu nó
        assert len(queries) == len(corr), (product, len(queries), len(corr))
        for rule, q in zip(corr, queries):
            q = q.replace("from *", f"from {INDEX_OF[product]}", 1)
            d = meta[rule.title]
            sev, score = SEVERITY.get(d.get("level", "medium"), ("medium", 47))
            out.append({
                "rule_id": d["id"], "name": f"[SOC/UEBA] {d['title']}", "type": "esql",
                "language": "esql", "query": q,
                "description": (d.get("description") or d["title"]) + " – converted from Sigma by pySigma.",
                "severity": sev, "risk_score": score, "interval": "1h", "from": LOOKBACK[product],
                "enabled": product == "lanl", "author": ["SOC/UEBA"], "license": "MIT",
                "tags": ["SOC/UEBA", "Sigma", product.upper()] + [t for t in d.get("tags", [])
                                                                if t.startswith("attack.")],
                "false_positives": d.get("falsepositives", []),
            })
    return out


def kibana_request(method: str, path: str, body: dict | None = None):
    pw = os.environ.get("ELASTIC_PASSWORD", "")
    auth = b64encode(f"elastic:{pw}".encode()).decode()
    req = urllib.request.Request(KIBANA_URL + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Basic {auth}", "kbn-xsrf": "soc-ueba",
                                          "Content-Type": "application/json",
                                          "elastic-api-version": "2023-10-31"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"{}")


def push(rules: list[dict]):
    for r in rules:
        try:
            kibana_request("GET", f"/api/detection_engine/rules?rule_id={r['rule_id']}")
            kibana_request("PUT", "/api/detection_engine/rules", r)
            how = "cập nhật"
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            kibana_request("POST", "/api/detection_engine/rules", r)
            how = "tạo mới"
        print(f"  {how}: {r['name']} ({'bật' if r['enabled'] else 'tắt'})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--push", action="store_true", help="tạo / cập nhật luật trong Kibana")
    a = ap.parse_args()
    rules = kibana_rules()
    OUT_DIR.mkdir(exist_ok=True)
    for product in ("lanl", "cert"):
        part = [r for r in rules if product.upper() in r["tags"]]
        (OUT_DIR / f"{product}_rules.ndjson").write_text(
            "\n".join(json.dumps(r, ensure_ascii=False) for r in part) + "\n", encoding="utf-8")
        print(f"{product}: {len(part)} luật ES|QL → {OUT_DIR / f'{product}_rules.ndjson'}")
    if a.push:
        push(rules)


if __name__ == "__main__":
    main()
