"""Tải MITRE ATT&CK Enterprise (STIX 2.1, repo chính thức mitre/cti) và rút gọn thành bảng tra
technique → tên, tactic, mô tả ngắn, URL. Dùng cho: gắn MITRE vào cảnh báo, heatmap trên web,
và tool `mitre_lookup` của AI Agent (tra cứu cục bộ, không cần Internet lúc chạy).

Chạy:  python -m soc.mitre.build_attack
Kết quả: soc/mitre/attack_techniques.json (nhỏ, commit được)
"""
import json
import re
import urllib.request
from pathlib import Path

from soc.config import DATA_DIR

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
RAW = DATA_DIR / "mitre" / "enterprise-attack.json"
OUT = Path(__file__).parent / "attack_techniques.json"


def main():
    RAW.parent.mkdir(parents=True, exist_ok=True)
    if not RAW.exists():
        print("Tải", URL)
        urllib.request.urlretrieve(URL, RAW)
    bundle = json.loads(RAW.read_text(encoding="utf-8"))
    version = next((o.get("x_mitre_version") for o in bundle["objects"]
                    if o["type"] == "x-mitre-collection"), None)
    tactics = {o["x_mitre_shortname"]: o["name"] for o in bundle["objects"]
               if o["type"] == "x-mitre-tactic"}
    out = {}
    for o in bundle["objects"]:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not ref:
            continue
        desc = re.sub(r"\(Citation:[^)]*\)", "", o.get("description", ""))
        desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", desc).strip()
        out[ref["external_id"]] = {
            "name": o["name"],
            "tactics": [tactics.get(p["phase_name"], p["phase_name"])
                        for p in o.get("kill_chain_phases", [])
                        if p.get("kill_chain_name") == "mitre-attack"],
            "description": desc.split("\n")[0][:600],
            "url": ref.get("url"),
        }
    # tên kỹ thuật con kèm tên kỹ thuật cha: "Use Alternate Authentication Material: Pass the Hash"
    for tid, t in out.items():
        if "." in tid and tid.split(".")[0] in out:
            t["full_name"] = f"{out[tid.split('.')[0]]['name']}: {t['name']}"
        else:
            t["full_name"] = t["name"]
    OUT.write_text(json.dumps({"attack_version": version, "techniques": out}, ensure_ascii=False,
                              indent=0), encoding="utf-8")
    print(f"ATT&CK {version}: {len(out)} technique → {OUT}")


if __name__ == "__main__":
    main()
