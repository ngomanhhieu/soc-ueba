"""Tạo index + mapping trên Elasticsearch cho hệ thống SOC (chạy lại an toàn).

  soc-alerts      cảnh báo từ luật Sigma + ML (theo schema/alert.schema.json, thêm vài field)
  soc-incidents   incident = gom cảnh báo theo thực thể (Lớp 4 – risk), trạng thái xử lý
  soc-events-*    sự kiện gốc của thực thể bị điều tra (để analyst xem bằng chứng)
  soc-ioc         IOC do analyst xác nhận (vòng phản hồi về luật)
  soc-audit       nhật ký kiểm toán: ai làm gì, duyệt gì (bất biến – chỉ thêm)
Ngoài ra tạo role `soc_analyst` (chỉ đọc + ghi incident/ioc/audit) và user cho web app theo
nguyên tắc quyền tối thiểu – web app KHÔNG dùng tài khoản superuser `elastic`.

Chạy:  python -m soc.elastic.indices [--recreate]
"""
import argparse
import secrets

from soc.config import INDEX, es_client
from soc.elastic.elastic_ctl import get_env, set_env

KW = {"type": "keyword"}
DATE = {"type": "date"}
TEXT = {"type": "text"}
FLOAT = {"type": "float"}
INT = {"type": "integer"}
MITRE = {"properties": {"tactic": KW, "technique_id": KW, "technique_name": KW}}

MAPPINGS = {
    INDEX["alerts"]: {
        "alert_id": KW, "timestamp": DATE, "user": KW, "entity": KW, "entity_type": KW,
        "src_host": KW, "dst_host": KW, "source": KW, "rule_id": KW, "rule_title": TEXT,
        "anomaly_score": FLOAT, "is_human_prob": FLOAT, "severity": KW, "dataset": KW,
        "mitre": MITRE, "mitre_ids": KW, "incident_id": KW,
        "features": {"type": "object", "enabled": False},     # chi tiết – chỉ lưu, không index
        "ground_truth": {"type": "boolean"},                   # chỉ để đánh giá, ẩn với analyst
    },
    INDEX["incidents"]: {
        "incident_id": KW, "entity": KW, "entity_type": KW, "dataset": KW, "users": KW,
        "hosts": KW, "opened_at": DATE, "last_seen": DATE, "risk": FLOAT, "max_risk": FLOAT,
        "severity": KW, "status": KW, "alert_ids": KW, "n_alerts": INT, "mitre_ids": KW,
        "tactics": KW, "title": TEXT, "detectors": KW,
        "playbook": {"type": "object", "enabled": False},       # SOAR: bước điều tra + đề xuất
        "attack_chain": {"type": "object", "enabled": False},   # chuỗi tấn công / dòng thời gian
        "verdict": KW, "verdict_by": KW, "verdict_at": DATE, "notes": TEXT, "created_at": DATE,
        "actions": {"type": "object", "enabled": False}, "ground_truth": {"type": "boolean"},
    },
    INDEX["events_lanl"]: {
        "@timestamp": DATE, "event.dataset": KW, "user.name": KW, "user.target.name": KW,
        "user.kind": KW, "source.host": KW, "destination.host": KW, "auth.type": KW,
        "logon.type": KW, "event.action": KW, "event.outcome": KW, "network.remote": {"type": "boolean"},
        "event.id": KW, "label.redteam": {"type": "boolean"},
    },
    INDEX["events_cert"]: {
        "@timestamp": DATE, "event.dataset": KW, "user.name": KW, "host.name": KW,
        "event.action": KW, "event.offhours": {"type": "boolean"}, "event.weekend": {"type": "boolean"},
        "file.name": KW, "file.extension": KW, "email.external_recipients": INT,
        "email.attachments": INT, "email.size": FLOAT, "url.domain": KW,
        "url.org_popularity": FLOAT, "url.category": KW, "http.visits": INT, "event.id": KW,
        "label.malicious": {"type": "boolean"},
    },
    INDEX["ioc"]: {"value": KW, "type": KW, "incident_id": KW, "created_at": DATE,
                   "created_by": KW, "reason": TEXT, "active": {"type": "boolean"}},
    INDEX["audit"]: {"@timestamp": DATE, "actor": KW, "actor_type": KW, "action": KW,
                     "target": KW, "detail": {"type": "object", "enabled": False},
                     "outcome": KW},
}


def create_indices(es, recreate=False):
    for name, props in MAPPINGS.items():
        if es.indices.exists(index=name):
            if not recreate:
                print(f"  {name}: đã có")
                continue
            es.indices.delete(index=name)
        es.indices.create(index=name, mappings={"dynamic": False, "properties": props},
                          settings={"number_of_shards": 1, "number_of_replicas": 0})
        print(f"  {name}: tạo mới")


def create_app_user(es):
    """Role tối thiểu cho web app: đọc alerts/events, ghi incidents/ioc/audit."""
    es.security.put_role(name="soc_app", cluster=["monitor"], indices=[
        {"names": [INDEX["alerts"], INDEX["events_lanl"], INDEX["events_cert"]],
         "privileges": ["read", "view_index_metadata"]},
        {"names": [INDEX["incidents"], INDEX["ioc"], INDEX["alerts"]],
         "privileges": ["read", "write", "view_index_metadata"]},
        {"names": [INDEX["audit"]], "privileges": ["create_doc", "read"]},   # chỉ thêm, không sửa
    ])
    pw = get_env("SOC_APP_ES_PASSWORD") or secrets.token_urlsafe(24)
    es.security.put_user(username="soc_app", password=pw, roles=["soc_app"],
                         full_name="SOC web app (least privilege)")
    set_env("SOC_APP_ES_PASSWORD", pw)
    print("  user soc_app (role soc_app) → .env SOC_APP_ES_PASSWORD")
    # Pipeline nạp dữ liệu / replay: ghi các index soc-*, KHÔNG có quyền quản trị cluster
    es.security.put_role(name="soc_pipeline", cluster=["monitor"], indices=[
        {"names": [v for k, v in INDEX.items() if k != "audit"],
         "privileges": ["read", "write", "delete", "view_index_metadata", "maintenance"]},
        {"names": [INDEX["audit"]], "privileges": ["create_doc"]},   # kiểm toán: chỉ thêm
    ])
    pw = get_env("SOC_PIPELINE_ES_PASSWORD") or secrets.token_urlsafe(24)
    es.security.put_user(username="soc_pipeline", password=pw, roles=["soc_pipeline"],
                         full_name="SOC ingest pipeline (no cluster admin)")
    set_env("SOC_PIPELINE_ES_PASSWORD", pw)
    print("  user soc_pipeline (role soc_pipeline) → .env SOC_PIPELINE_ES_PASSWORD")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recreate", action="store_true")
    a = ap.parse_args()
    es = es_client(admin=True)
    create_indices(es, a.recreate)
    create_app_user(es)


if __name__ == "__main__":
    main()
