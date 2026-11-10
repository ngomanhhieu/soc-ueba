"""Bật toàn bộ hệ thống: Elasticsearch + Kibana (nền) rồi web app SOC.

Chạy:  python -m soc.start      → web http://127.0.0.1:8000 · Kibana http://127.0.0.1:5601
Tắt web: Ctrl+C.  Tắt nền: python -m soc.elastic.elastic_ctl stop
"""
from soc.api.main import main as web
from soc.elastic.elastic_ctl import start

if __name__ == "__main__":
    start()
    web()
