"""Demo "SOC chạy từng ngày" trên giai đoạn test – workflow B7 → B15 lặp lại mỗi ngày.

Mỗi lần `next` xử lý 1 ngày mới như hệ thống thật:
  LANL (ngày 20–29): chạy luật Sigma của ngày đó với danh sách IOC HIỆN TẠI (lead duyệt trên web
        → ioc.json) – thấy được vòng phản hồi IOC.
  CERT (09/2010 – 05/2011): luật CERT không phụ thuộc IOC và đã tính nhân quả (chỉ dùng các ngày
        trước) → lấy cảnh báo luật + ML của ngày đó.
  Rồi: tính lại rủi ro tới ngày đó, dựng/cập nhật incident, chạy playbook (chuỗi tấn công / dòng
  thời gian), nạp cảnh báo, incident, sự kiện của ngày vào Elasticsearch.
Incident đã có giữ nguyên phần analyst/lead đã làm (verdict, actions, status); playbook chạy lại.

  python -m soc.replay reset [--dataset lanl|cert]       # xoá dữ liệu bộ đó trên ES, đặt đồng hồ
  python -m soc.replay next  [--dataset ...] [--days N]  # chạy tiếp N ngày
  python -m soc.replay status
"""
import argparse
import json
from datetime import datetime, timezone
from functools import lru_cache

import pandas as pd
from elasticsearch import helpers

from soc.config import INDEX, STATE_DIR, es_client
from soc.elastic.ingest import _docs, cert_event_docs, lanl_events
from soc.playbooks.soar import enrich
from soc.risk.incidents import GAP, _json_default, build_incidents, ml_alerts, rule_alerts
from soc.risk.risk import combine, daily_risk, ml_detections, rule_detections, truth_and_splits
from soc.rules.datasets import cert_events
from soc.rules.run_rules import is_ioc_rule, lanl_ioc_rules, ruleset

CLOCK = {"lanl": STATE_DIR / "replay_clock.json", "live": STATE_DIR / "replay_clock_live.json",
         "cert": STATE_DIR / "replay_clock_cert.json"}
# LANL có 2 chế độ (cùng dữ liệu "lanl" trên ES, chạy 1 chế độ mỗi lúc):
#   lanl – giai đoạn test 20–29 (có red team → thấy bắt tấn công + vòng phản hồi IOC)
#   live – ngày MỚI 30–57 tải thêm, chưa từng dùng khi train/thiết kế, không có nhãn red team
LANL_MODES = {"lanl": 20, "live": 30}
ES_DS = {"lanl": "lanl", "live": "lanl", "cert": "cert"}
OFFLINE_RULES = STATE_DIR / "rule_alerts_lanl.parquet"   # kết quả đánh giá offline – KHÔNG ghi đè
LIVE_RULES = STATE_DIR / "replay_rule_alerts_lanl.parquet"
LIVE_RISK = STATE_DIR / "replay_risk_lanl.parquet"
REPLAY_EVENTS = 5000      # sự kiện gốc / thực thể / ngày nạp khi demo (ưu tiên từ xa, thất bại, NTLM)
KEEP = ("verdict", "verdict_by", "verdict_at", "notes", "actions", "status", "created_at")


@lru_cache(maxsize=2)
def test_days(ds: str) -> list:
    return sorted(truth_and_splits(ds)[1]["test"])


def clock(ds: str = "lanl"):
    """Ngày cuối đã xử lý (LANL: số ngày; CERT: Timestamp); None = ES đang chứa dữ liệu đầy đủ
    (chưa reset, hoặc vừa khôi phục bằng soc.elastic.ingest)."""
    p = CLOCK[ds]
    if not p.exists():
        return None
    d = json.loads(p.read_text())["day"]
    return d if ds in LANL_MODES else pd.Timestamp(d)


def set_clock(ds: str, d):
    CLOCK[ds].write_text(json.dumps({"day": d if ds in LANL_MODES else pd.Timestamp(d).strftime("%Y-%m-%d")}))


def last_day(mode: str) -> int:
    from features import available_days
    return 29 if mode == "lanl" else max(available_days())


def reset(ds: str):
    es = es_client()
    e = ES_DS[ds]
    for idx in (INDEX["alerts"], INDEX["incidents"], INDEX[f"events_{e}"]):
        es.delete_by_query(index=idx, query={"term": {"dataset": e}}
                           if idx != INDEX[f"events_{e}"] else {"match_all": {}}, refresh=True)
    if ds in LANL_MODES:
        start = LANL_MODES[ds]
        for m in LANL_MODES:                                  # 2 chế độ dùng chung dữ liệu ES
            CLOCK[m].unlink(missing_ok=True)
        full = pd.read_parquet(OFFLINE_RULES)
        full[full["day"] < start].to_parquet(LIVE_RULES, index=False)   # lịch sử trước demo
        set_clock(ds, start - 1)
    else:
        set_clock(ds, test_days("cert")[0] - pd.Timedelta(days=1))
    print(f"Reset {ds.upper()}: clock = {fmt(ds, clock(ds))}; {ds.upper()} data removed from Elasticsearch.")


def fmt(ds, d):
    if d is None:
        return "full data"
    return f"day {d}" if ds in LANL_MODES else pd.Timestamp(d).strftime("%Y-%m-%d")


def old_docs(es, incidents: list) -> dict:
    ids = [i["incident_id"] for i in incidents]
    return {h["_id"]: h["_source"] for h in es.search(
        index=INDEX["incidents"], query={"ids": {"values": ids}}, size=len(ids) or 1)["hits"]["hits"]}


def split_active(incidents: list, old: dict, is_today) -> list:
    """Incident không hoạt động hôm nay và đã có playbook → giữ chuỗi tấn công / playbook cũ (không
    đổi vì dữ liệu của nó không đổi); trả về các incident cần chạy playbook lại."""
    todo = []
    for i in incidents:
        o = old.get(i["incident_id"], {})
        if not is_today(i) and o.get("playbook") and o.get("attack_chain"):
            i["playbook"], i["attack_chain"] = o["playbook"], o["attack_chain"]
        else:
            todo.append(i)
    return todo


def publish(es, ds: str, alerts: list, incidents: list, old: dict, changed_since):
    """Giữ phần analyst / lead đã làm trên incident cũ, rồi CHỈ nạp phần có thể đã đổi: cảnh báo từ
    ngày `changed_since` (incident mới / kéo dài có thể nhận cảnh báo của vài ngày trước – GAP) và
    incident mới hoặc vừa thay đổi."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    upd = []
    for i in incidents:
        o = old.get(i["incident_id"])
        i["created_at"] = now                       # incident mới xuất hiện hôm nay
        for k in KEEP:
            if k in (o or {}):
                i[k] = o[k]
        if o is None or o.get("last_seen") != i["last_seen"] or o.get("n_alerts") != i["n_alerts"]:
            upd.append(i)
    al = [a for a in alerts if changed_since(a["day"])]
    helpers.bulk(es, _docs(INDEX["alerts"], json.loads(json.dumps(al, default=_json_default)),
                           "alert_id"), chunk_size=2000)
    helpers.bulk(es, _docs(INDEX["incidents"], json.loads(json.dumps(upd, default=_json_default)),
                           "incident_id"), chunk_size=500)
    return len(upd)


def step_lanl(mode: str = "lanl"):
    if clock(mode) is None:
        print("Elasticsearch holds the full data – press Reset first")
        return False
    d, start = clock(mode) + 1, LANL_MODES[mode]
    if d > last_day(mode):
        print(f"End of LANL {'test' if mode == 'lanl' else 'new'} data (day {last_day(mode)})")
        return False
    es = es_client()
    # luật Sigma của ngày d: luật thường không phụ thuộc analyst → lấy kết quả đã chạy sẵn;
    # chỉ chạy lại luật IOC với danh sách IOC HIỆN TẠI (vòng phản hồi) – nhanh hơn ~40 giây/ngày
    ioc_ids = {r.id for r in ruleset().rules if is_ioc_rule(r)}
    off = pd.read_parquet(OFFLINE_RULES)
    new = pd.concat([off[(off["day"] == d) & ~off["rule_id"].isin(ioc_ids)], lanl_ioc_rules(d)],
                    ignore_index=True)
    live = pd.concat([pd.read_parquet(LIVE_RULES), new], ignore_index=True)
    live.to_parquet(LIVE_RULES, index=False)

    truth, _, all_days = truth_and_splits("lanl")
    params = json.loads((STATE_DIR / "risk_params_lanl.json").read_text())
    days = [x for x in all_days if x <= d]
    rules = rule_detections("lanl", LIVE_RULES)
    fid = json.loads((STATE_DIR / "rule_fidelity_lanl.json").read_text(encoding="utf-8"))
    rules["points"] *= rules["detector"].map(lambda r: fid.get(r, 4.0)).values  # luật chưa bắn ở train → hiếm
    ml = ml_detections("lanl")
    ml = ml[ml["day"] <= d]
    det = combine(rules, ml, "both", params["ml_weight"], params["ml_floor"])
    daily_risk(det, days, params["decay"]).to_parquet(LIVE_RISK, index=False)

    demo_days = list(range(start, d + 1))
    alerts = rule_alerts("lanl", set(demo_days), LIVE_RULES) + ml_alerts("lanl", set(demo_days))
    incidents = build_incidents("lanl", alerts, demo_days, truth, LIVE_RISK)
    old = old_docs(es, incidents)
    # chuỗi tấn công + playbook với IOC hiện tại – chỉ cho incident hoạt động hôm nay / mới
    enrich("lanl", split_active(incidents, old, lambda i: i["day_last"] == d))
    publish(es, "lanl", alerts, incidents, old, lambda day: day >= d - GAP - 1)
    inc_today = [dict(i, day_first=max(i["day_first"], d)) for i in incidents if i["day_last"] == d]
    k, _ = helpers.bulk(es.options(request_timeout=120),
                        lanl_events(inc_today, max_per=REPLAY_EVENTS, before=0), chunk_size=5000)
    es.indices.refresh(index="soc-*")
    set_clock(mode, d)
    ioc_hits = new[new["rule_title"].str.contains("IOC")] if len(new) else new
    today = [a for a in alerts if a["day"] == d]
    print(f"Day {d}: {len(new)} new rule detections ({len(ioc_hits)} from the IOC rule), "
          f"{len(today)} detections today, {len(inc_today)} active incidents, {k:,} events loaded")
    return True


def step_cert(ev: dict) -> bool:
    days = test_days("cert")
    cur = clock("cert")
    if cur is None:
        print("Elasticsearch holds the full data – press Reset first")
        return False
    later = [x for x in days if x > cur]
    if not later:
        print("End of CERT test data")
        return False
    d = later[0]
    es = es_client()
    truth = truth_and_splits("cert")[0]
    demo_days = [x for x in days if x <= d]
    # luật CERT + điểm rủi ro đã tính nhân quả (ngày d chỉ dùng dữ liệu ≤ d) → cắt tới ngày d
    alerts = rule_alerts("cert", set(demo_days)) + ml_alerts("cert", set(demo_days))
    incidents = build_incidents("cert", alerts, demo_days, truth)
    old = old_docs(es, incidents)
    todo = split_active(incidents, old, lambda i: pd.Timestamp(i["day_last"]) == d)
    if todo:
        enrich("cert", todo, ev=ev)
    since = d - pd.Timedelta(days=GAP + 1)
    publish(es, "cert", alerts, incidents, old, lambda day: pd.Timestamp(day) >= since)
    inc_today = [dict(i, day_first=d) for i in incidents if pd.Timestamp(i["day_last"]) == d]
    k, _ = helpers.bulk(es.options(request_timeout=120), cert_event_docs(inc_today, ev=ev, after=0),
                        chunk_size=5000)
    es.indices.refresh(index="soc-*")
    set_clock("cert", d)
    today = [a for a in alerts if pd.Timestamp(a["day"]) == d]
    print(f"{d:%Y-%m-%d}: {len(today)} detections today, {len(inc_today)} active incidents, "
          f"{k:,} events loaded")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["reset", "next", "status"])
    ap.add_argument("--dataset", choices=["lanl", "live", "cert"], default="lanl",
                    help="lanl = test 20–29, live = ngày mới 30–57, cert = test CERT")
    ap.add_argument("--days", type=int, default=1)
    a = ap.parse_args()
    if a.cmd == "reset":
        reset(a.dataset)
    elif a.cmd == "next":
        ev = cert_events() if a.dataset == "cert" else None   # đọc 1 lần cho cả N ngày
        for _ in range(a.days):
            if not (step_cert(ev) if a.dataset == "cert" else step_lanl(a.dataset)):
                break
    else:
        print(f"Demo clock: LANL test {fmt('lanl', clock('lanl'))} (20–29) · "
              f"LANL new days {fmt('live', clock('live'))} (30–{last_day('live')}) · "
              f"CERT {fmt('cert', clock('cert'))} (test {fmt('cert', test_days('cert')[0])} → "
              f"{fmt('cert', test_days('cert')[-1])})")


if __name__ == "__main__":
    main()
