"""Nạp cảnh báo, incident và sự kiện gốc (cho điều tra) vào Elasticsearch.

Sự kiện: chỉ nạp sự kiện của các thực thể nằm trong incident (đúng các ngày của incident ± 1),
giống cách SIEM giữ "hot data" phục vụ điều tra. LANL có tài khoản sinh > 100k sự kiện/ngày nên
giới hạn MAX_PER_ENTITY_DAY, ưu tiên sự kiện có giá trị điều tra (đăng nhập từ xa, thất bại, NTLM).

Chạy:  python -m soc.elastic.ingest [--skip-events]
"""
import argparse
import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from elasticsearch import helpers

from soc.config import INDEX, STATE_DIR, es_client
from soc.risk.incidents import LANL_BASE
from soc.rules.datasets import cert_events, lanl_day

MAX_PER_ENTITY_DAY = 20_000


def _docs(index, items, id_field):
    for x in items:
        x = {k: v for k, v in x.items() if k not in ("day", "day_first", "day_last")}
        yield {"_index": index, "_id": x[id_field], "_source": x}


def load_state(ds):
    al = json.loads((STATE_DIR / f"alerts_{ds}.json").read_text(encoding="utf-8"))
    inc = json.loads((STATE_DIR / f"incidents_{ds}.json").read_text(encoding="utf-8"))
    return al, inc


def _event_docs(df: pd.DataFrame, index: str, ds: str):
    df = df.copy()
    if ds == "lanl":
        df["@timestamp"] = (pd.Timestamp(LANL_BASE) + pd.to_timedelta(df["@timestamp"], unit="s")) \
            .dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        df = df.rename(columns={"is_redteam": "label.redteam"})
    else:
        df["@timestamp"] = pd.to_datetime(df["@timestamp"], unit="s").dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        df = df.rename(columns={"is_malicious": "label.malicious"})
    for c in df.columns:
        if isinstance(df[c].dtype, pd.CategoricalDtype):
            df[c] = df[c].astype(str)
    for rec in df.to_dict("records"):
        rec = {k: (v.item() if isinstance(v, np.generic) else v) for k, v in rec.items()
               if not (isinstance(v, float) and np.isnan(v))}
        yield {"_index": index, "_id": rec["event.id"], "_source": rec}


def lanl_events(incidents, max_per=MAX_PER_ENTITY_DAY, before=1):
    """before = số ngày lấy thêm trước incident (ngữ cảnh); demo replay dùng 0 và max_per nhỏ hơn."""
    want = {}   # day → (users, hosts)
    for i in incidents:
        for d in range(i["day_first"] - before, i["day_last"] + 1):
            u, h = want.setdefault(d, (set(), set()))
            if i["entity_type"] == "user":
                u.add(i["entity"])
            else:
                h.add(i["entity"].removeprefix("host:"))
    for d, (users, hosts) in sorted(want.items()):
        df = lanl_day(d)
        m = df["user.name"].isin(users) | df["source.host"].isin(hosts)
        sub = df[m].copy()
        sub["event.id"] = [f"lanl-{d}-{i}" for i in sub.index]
        sub["_prio"] = (sub["network.remote"].astype(int) + (sub["event.outcome"] == "Fail")
                        + (sub["auth.type"] == "NTLM"))
        sub["_ent"] = np.where(sub["user.name"].isin(users), sub["user.name"].astype(str),
                               sub["source.host"].astype(str))
        sub = sub.sort_values(["_prio", "@timestamp"], ascending=[False, True]) \
            .groupby("_ent", observed=True).head(max_per).drop(columns=["_prio", "_ent"])
        print(f"  LANL day {d}: {len(sub):,} events ({len(users)} users, {len(hosts)} hosts)",
              flush=True)
        yield from _event_docs(sub.sort_values("@timestamp"), INDEX["events_lanl"], "lanl")


def cert_event_docs(incidents, ev=None, after=1):
    """Sự kiện của nhân viên trong incident, [ngày đầu − 1, ngày cuối + after]."""
    ev = ev or cert_events()
    spans = [(i["entity"], pd.Timestamp(i["day_first"]) - pd.Timedelta(days=1),
              pd.Timestamp(i["day_last"]) + pd.Timedelta(days=after)) for i in incidents]
    users = {u for u, _, _ in spans}
    for svc, df in ev.items():
        df = df[df["user.name"].isin(users)].copy()
        t = pd.to_datetime(df["@timestamp"], unit="s")
        keep = np.zeros(len(df), dtype=bool)
        for u, a, b in spans:
            keep |= ((df["user.name"] == u) & (t >= a) & (t <= b)).values
        df = df[keep]
        df["event.dataset"] = f"cert.{svc}"
        df["event.id"] = [f"cert-{svc}-{i}" for i in df.index]
        print(f"  CERT {svc}: {len(df):,} events", flush=True)
        yield from _event_docs(df, INDEX["events_cert"], "cert")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-events", action="store_true")
    ap.add_argument("--dataset", choices=["lanl", "cert", "all"], default="all")
    ap.add_argument("--events-only", action="store_true", help="chỉ nạp lại sự kiện")
    a = ap.parse_args()
    es = es_client()
    for ds in (["lanl", "cert"] if a.dataset == "all" else [a.dataset]):
        # xoá bản cũ (kể cả trạng thái replay) để không sót incident/cảnh báo đã đổi ID
        targets = [] if a.skip_events else [(INDEX[f"events_{ds}"], {"match_all": {}})]
        if not a.events_only:
            targets += [(INDEX["alerts"], {"term": {"dataset": ds}}),
                        (INDEX["incidents"], {"term": {"dataset": ds}})]
        for idx, q in targets:
            es.delete_by_query(index=idx, query=q, refresh=True, conflicts="proceed")
        al, inc = load_state(ds)
        if not a.events_only:
            n, _ = helpers.bulk(es, _docs(INDEX["alerts"], al, "alert_id"), chunk_size=2000)
            now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            for i in inc:
                i["created_at"] = now
            m, _ = helpers.bulk(es, _docs(INDEX["incidents"], inc, "incident_id"), chunk_size=500)
            print(f"[{ds}] loaded {n} detections, {m} incidents")
            # dữ liệu đầy đủ → đồng hồ demo replay của bộ này không còn ý nghĩa
            for clock in (("replay_clock.json", "replay_clock_live.json") if ds == "lanl"
                          else ("replay_clock_cert.json",)):
                (STATE_DIR / clock).unlink(missing_ok=True)
        if not a.skip_events:
            gen = lanl_events(inc) if ds == "lanl" else cert_event_docs(inc)
            k, _ = helpers.bulk(es.options(request_timeout=120), gen, chunk_size=5000)
            print(f"[{ds}] loaded {k:,} events")
    es.indices.refresh(index="soc-*")


if __name__ == "__main__":
    main()
