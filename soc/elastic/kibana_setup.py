"""Tạo data view trên Kibana cho các index SOC (điều tra trong Discover / Lens). Chạy lại an toàn.

Chạy:  python -m soc.elastic.kibana_setup
"""
import base64
import json
import urllib.error
import urllib.request

from soc.config import ES_PASSWORD, ES_USER, INDEX, KIBANA_URL

VIEWS = [
    ("soc-alerts", INDEX["alerts"], "timestamp", "SOC – Cảnh báo (luật + ML)"),
    ("soc-incidents", INDEX["incidents"], "opened_at", "SOC – Incident"),
    ("soc-events-lanl", INDEX["events_lanl"], "@timestamp", "SOC – Sự kiện xác thực (LANL)"),
    ("soc-events-cert", INDEX["events_cert"], "@timestamp", "SOC – Sự kiện insider (CERT)"),
    ("soc-audit", INDEX["audit"], "@timestamp", "SOC – Nhật ký kiểm toán"),
]


def kibana(path, method="GET", body=None):
    auth = base64.b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()
    req = urllib.request.Request(KIBANA_URL + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Basic {auth}", "kbn-xsrf": "true",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"{}")


def main():
    for vid, pattern, ts, name in VIEWS:
        try:
            kibana(f"/api/data_views/data_view/{vid}")
            print(f"  {name}: đã có")
            continue
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
        kibana("/api/data_views/data_view", "POST", {"data_view": {
            "id": vid, "title": pattern, "timeFieldName": ts, "name": name}})
        print(f"  {name}: tạo mới")
    print(f"Mở {KIBANA_URL}/app/discover (đăng nhập user elastic, mật khẩu trong .env)")


if __name__ == "__main__":
    main()
