"""Tải ánh xạ ATT&CK → D3FEND (MITRE D3FEND, API chính thức) cho các technique hệ thống phát hiện
được, rút gọn thành bảng tra: technique → các biện pháp phòng thủ (id, tên, tactic D3FEND).
Playbook SOAR dùng bảng này để gắn biện pháp đối phó chuẩn cho từng hành động đề xuất.

Chạy:  python -m soc.mitre.build_d3fend
Kết quả: soc/mitre/d3fend_map.json (nhỏ, commit được; dữ liệu thô → DATA_DIR/mitre/d3fend/)
"""
import json
import time
import urllib.request
from pathlib import Path

from soc.config import DATA_DIR

API = "https://d3fend.mitre.org/api/offensive-technique/attack/{}.json"
RAW = DATA_DIR / "mitre" / "d3fend"
OUT = Path(__file__).parent / "d3fend_map.json"
# Technique mà luật Sigma, ML (ml/src/mitre_mapping.json, cert_pipeline) và đồ thị tấn công gắn
TECHNIQUES = ["T1018", "T1021", "T1048", "T1048.003", "T1052.001", "T1056.001", "T1078",
              "T1110", "T1110.001", "T1110.003", "T1213", "T1550.002", "T1567", "T1570"]


def fetch(tid: str) -> dict:
    p = RAW / f"{tid}.json"
    if not p.exists():
        with urllib.request.urlopen(API.format(tid), timeout=60) as r:
            p.write_bytes(r.read())
        time.sleep(0.5)
    return json.loads(p.read_text(encoding="utf-8"))


def main():
    RAW.mkdir(parents=True, exist_ok=True)
    out = {}
    for tid in TECHNIQUES:
        rows = fetch(tid)["off_to_def"]["results"]["bindings"]
        seen = {}
        for b in rows:
            if "def_tech_id" not in b:
                continue
            d = b["def_tech_id"]["value"]
            seen.setdefault(d, {"id": d, "name": b["def_tech_label"]["value"],
                                "tactic": b.get("def_tactic_label", {}).get("value", ""),
                                "artifact": b.get("def_artifact_label", {}).get("value", "")})
        out[tid] = sorted(seen.values(), key=lambda x: (x["tactic"], x["id"]))
        print(f"  {tid}: {len(out[tid])} biện pháp D3FEND")
    OUT.write_text(json.dumps({"source": "https://d3fend.mitre.org", "map": out},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    print("→", OUT)


if __name__ == "__main__":
    main()
