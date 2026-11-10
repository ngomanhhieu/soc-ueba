"""Lớp 5 – SOAR bằng PLAYBOOK viết sẵn (thay AI Agent): tất định, kiểm chứng được, không bịa.

Mỗi incident chạy tự động 1 playbook theo loại:
  PB-LANL-HOST  máy bàn đạp / di chuyển ngang  → tái dựng chuỗi tấn công từ máy (soc.graph)
  PB-LANL-USER  tài khoản bị dùng bất thường   → tái dựng chuỗi từ máy nguồn lạ của tài khoản
  PB-CERT       nội gián đánh cắp dữ liệu       → dòng thời gian theo pha (soc.graph.insider_timeline)
Các bước điều tra chạy tự động (gom bằng chứng); hành động ứng phó chỉ là ĐỀ XUẤT – lead duyệt
trên web. Mỗi hành động gắn kỹ thuật ATT&CK nó chặn và biện pháp MITRE D3FEND tương ứng; mã
D3FEND được kiểm tra là có trong ánh xạ chính thức ATT&CK → D3FEND của technique đó.

Chạy (đã gọi trong soc.risk.incidents):  python -m soc.playbooks.soar  → in thống kê
"""
import json
from pathlib import Path

from soc.config import STATE_DIR
from soc.graph.attack_graph import MIN_SHARED
from soc.graph.insider_timeline import STEPS

D3FEND = json.loads((Path(__file__).parents[1] / "mitre" / "d3fend_map.json")
                    .read_text(encoding="utf-8"))["map"]
MAX_ACCOUNTS_LISTED = 60


def d3(technique: str, d3_id: str) -> dict:
    for x in D3FEND.get(technique, []):
        if x["id"] == d3_id:
            return {"technique": technique, **x}
    raise ValueError(f"{d3_id} không thuộc ánh xạ D3FEND của {technique}")


# hành động → (kỹ thuật ATT&CK bị chặn, biện pháp D3FEND)
ACTIONS = {
    "block_source_host": ("T1021", "D3-NTF"),      # Network Traffic Filtering → thêm IOC
    "reset_credentials": ("T1078", "D3-AL"),       # Account Locking (khoá, cấp lại mật khẩu)
    "monitor_closely": ("T1021", "D3-RTSD"),       # Remote Terminal Session Detection
    "monitor_account": ("T1078", "D3-DAM"),        # Domain Account Monitoring
    "block_usb": ("T1052.001", "D3-IOPR"),         # IO Port Restriction
    "block_outbound": ("T1048.003", "D3-OTF"),     # Outbound Traffic Filtering
    "restrict_access": ("T1078", "D3-UAP"),        # User Account Permissions
}
for _a, (_t, _d) in ACTIONS.items():   # kiểm tra lúc nạp: sai ánh xạ → lỗi ngay
    d3(_t, _d)


def action(name: str, target: str, reason: str, targets: list | None = None) -> dict:
    t, d = ACTIONS[name]
    return {"action": name, "target": target, "targets": targets or [], "reason": reason,
            "d3fend": d3(t, d)}


def active_iocs() -> set:
    p = STATE_DIR / "ioc.json"
    return {i["value"] for i in json.loads(p.read_text(encoding="utf-8"))} if p.exists() else set()


def pb_lanl(inc: dict, g: dict, iocs: set) -> dict:
    host = inc["entity_type"] == "host"
    acc, hosts, tgt = g["compromised_accounts"], g["attacker_hosts"], g["touched_hosts"]
    steps = [
        {"name": "Identify the attacking source host",
         "result": (f"Seed: {', '.join(g['seed']) or 'no unfamiliar source host'}; "
                    f"{sum(len(r) for r in g['expansion_rounds'])} more host(s) share the stolen "
                    "credentials")},
        {"name": "Reconstruct the attack chain (sign-in graph)",
         "result": (f"{len(hosts)} attacker host(s), {len(acc)} account(s) used from them, "
                    f"{len(tgt)} host(s) reached, {g['n_edges']} sign-in edges; main jump host: "
                    f"{g['main_host'] or '—'}")},
        {"name": "Chain confidence",
         "result": (f"{g['confidence_level']} – reaches more hosts than "
                    f"{g['confidence'] * 100:.0f}% of chains seen during training "
                    "(blocking is proposed from 80%)")},
        {"name": "Blast radius",
         "result": (f"{g['blast_radius_hosts']} other hosts the compromised accounts use every day "
                    "– the attacker could move there next")},
        {"name": "Check approved IOCs",
         "result": ", ".join(sorted(set(hosts) & iocs)) or "none of these hosts is on the IOC list"},
    ]
    acts = []
    # đủ bằng chứng máy bàn đạp: ≥ 3 tài khoản lạ VÀ chuỗi lớn bất thường (độ tin cậy ≥ medium)
    if hosts and len(acc) >= MIN_SHARED and g["confidence_level"] != "low":
        for h in hosts:
            if h not in iocs:
                acts.append(action("block_source_host", f"host:{h}",
                                   f"Source of {len(acc)} unfamiliar sign-ins in this chain"))
        acts.append(action("reset_credentials", f"{len(acc)} accounts",
                           "Credentials were used from an attacker host – treat them as stolen",
                           acc[:MAX_ACCOUNTS_LISTED]))
        if tgt:
            acts.append(action("monitor_closely", f"{len(tgt)} hosts reached",
                               "The attacker signed in here – check remote sessions and new processes",
                               tgt[:MAX_ACCOUNTS_LISTED]))
    else:
        acts.append(action("monitor_account", inc["entity"],
                           f"Small chain ({len(acc)} accounts, {len(tgt)} hosts reached, "
                           f"{g['confidence_level']} confidence) – not enough evidence of a jump "
                           "host yet, keep watching"))
    return {"playbook_id": "PB-LANL-HOST" if host else "PB-LANL-USER",
            "name": "Jump host / lateral movement" if host else "Account used abnormally",
            "steps": steps, "recommended_actions": acts, "requires_approval": True}


def pb_cert(inc: dict, tl: dict) -> dict:
    new = [s for s in tl["steps"] if s["new"]]
    by_step = {}
    for s in new:
        by_step.setdefault(s["step"], []).append(s)
    steps = [
        {"name": "Build the behaviour timeline",
         "result": f"{len(tl['steps'])} steps between {tl['window'][0]} and {tl['window'][1]}, "
                   f"{len(new)} of them NEW compared with the previous 30 days"},
        {"name": "Map steps to insider-threat phases",
         "result": " → ".join(tl["phases"]) or "no new phase"},
        {"name": "Look for data theft",
         "result": ", ".join(STEPS[k][1] for k in tl["new_exfil_steps"]) or "no new data-theft step"},
    ]
    acts = []
    usb = {e for s in by_step.get("usb_connect", []) for e in s["examples"]}   # tên máy
    if any(k in by_step for k in ("usb_copy", "usb_exe", "usb_connect")):
        acts.append(action("block_usb", ", ".join(sorted(usb)) or inc["entity"],
                           "New USB activity during this incident", sorted(usb)))
    if "email_ext_attach" in by_step:
        acts.append(action("block_outbound", inc["entity"],
                           "Emailed files outside the company – first time in 30 days"))
    if len(tl["phases"]) >= 2 and tl["new_exfil_steps"]:
        acts.append(action("restrict_access", inc["entity"],
                           f"{len(tl['phases'])} new phases ending in data theft"))
    if not acts:
        acts.append(action("monitor_account", inc["entity"], "No new data-theft step yet"))
    return {"playbook_id": "PB-CERT", "name": "Insider data theft", "steps": steps,
            "recommended_actions": acts, "requires_approval": True}


def enrich(ds: str, incidents: list[dict], ev=None):
    """Gắn attack_chain + playbook vào từng incident (sửa tại chỗ)."""
    iocs = active_iocs()
    if ds == "lanl":
        from soc.graph.attack_graph import reconstruct, set_horizon
        set_horizon(max([int(i["day_last"]) for i in incidents], default=29))
        for i in incidents:
            g = reconstruct(i["entity"], int(i["day_last"]), int(i["day_first"]))
            g.pop("_rt", None)
            i["attack_chain"] = g
            i["playbook"] = pb_lanl(i, g, iocs)
    else:
        from soc.graph.insider_timeline import timelines
        tls = timelines(incidents, ev)
        for i in incidents:
            i["attack_chain"] = tls[i["incident_id"]]
            i["playbook"] = pb_cert(i, tls[i["incident_id"]])


def main():
    from collections import Counter
    for ds in ("lanl", "cert"):
        inc = json.loads((STATE_DIR / f"incidents_{ds}.json").read_text(encoding="utf-8"))
        c = Counter(a["action"] for i in inc for a in i.get("playbook", {}).get("recommended_actions", []))
        print(ds, len(inc), "incident;", dict(c))


if __name__ == "__main__":
    main()
