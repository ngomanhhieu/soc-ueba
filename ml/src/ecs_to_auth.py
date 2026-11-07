"""Log thật (Winlogbeat + Filebeat, ECS) -> bảng auth cùng định dạng LANL.

Đầu ra giống `lanl_load_auth.py` (cột time, user, dst_user, src_comp, dst_comp,
auth_type, logon_type, auth_orient, success, is_machine, day) nên dùng lại được
nguyên `features.py`, rule, model.

Nguồn dữ liệu (chọn một):
  # đọc thẳng từ Elasticsearch trên Ubuntu server
  python src/ecs_to_auth.py --es https://<ip>:9200 --since 2026-11-01 --until 2026-11-08
  # hoặc từ file NDJSON đã export (mỗi dòng 1 document hoặc 1 hit có _source)
  python src/ecs_to_auth.py --file data/raw/ecs_sample.ndjson

Biến môi trường / ../.env: ELASTIC_USER (mặc định elastic), ELASTIC_PASSWORD, ES_CA_CERT (tuỳ chọn).

Windows (Winlogbeat, kênh Security):
  4624 logon OK, 4625 logon fail, 4648 logon bằng credential tường minh,
  4634/4647 logoff, 4768 Kerberos TGT, 4769 Kerberos TGS, 4776 xác thực NTLM.
Linux (Filebeat module system, fileset auth): sshd Accepted/Failed, login console.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from datetime import datetime, timezone

import pandas as pd

from common import env, save_df

WIN_CODES = {"4624", "4625", "4648", "4634", "4647", "4768", "4769", "4776"}
ORIENT = {"4624": "LogOn", "4625": "LogOn", "4648": "LogOn", "4776": "LogOn",
          "4634": "LogOff", "4647": "LogOff", "4768": "TGT", "4769": "TGS"}
LOGON_TYPE = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
              "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
              "10": "RemoteInteractive", "11": "CachedInteractive"}
# tài khoản hệ thống sinh nhiễu, không phải người hay dịch vụ cần theo dõi
NOISE_USERS = {"-", "", "ANONYMOUS LOGON", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
NOISE_PREFIX = ("DWM-", "UMFD-", "FONT DRIVER HOST")
EMPTY = {None, "", "-", "::1", "127.0.0.1", "localhost"}


def get(doc: dict, *paths, default=None):
    """Lấy trường theo nhiều đường dẫn ứng viên (dạng lồng nhau hoặc key có dấu chấm)."""
    for p in paths:
        if p in doc:
            v = doc[p]
        else:
            v = doc
            for k in p.split("."):
                if not isinstance(v, dict) or k not in v:
                    v = None
                    break
                v = v[k]
        if isinstance(v, list):
            v = v[0] if v else None
        if v not in (None, ""):
            return v
    return default


def _ts(doc) -> int | None:
    t = get(doc, "@timestamp", "timestamp")
    if t is None:
        return None
    ts = pd.Timestamp(t)
    return int((ts if ts.tzinfo else ts.tz_localize("UTC")).timestamp())


def _host(v) -> str | None:
    if v in EMPTY:
        return None
    v = str(v).strip().lstrip("\\")
    try:
        ipaddress.ip_address(v.removeprefix("::ffff:"))
        return v.removeprefix("::ffff:")  # IP giữ nguyên
    except ValueError:
        return v.split(".")[0].upper()  # bỏ hậu tố FQDN để cùng 1 máy chỉ có 1 tên


def map_windows(doc) -> dict | None:
    code = str(get(doc, "event.code", "winlog.event_id", default=""))
    if code not in WIN_CODES:
        return None
    ed = lambda k: get(doc, f"winlog.event_data.{k}")  # noqa: E731
    name = ed("TargetUserName") or get(doc, "user.name")
    if name is None or name.upper() in NOISE_USERS or name.upper().startswith(NOISE_PREFIX):
        return None
    if code == "4648":  # 4648: Subject dùng credential của Target -> người hành động là Subject
        name = ed("SubjectUserName") or name
    if "@" in name:  # dạng UPN user@domain
        name, dom = name.split("@", 1)
    else:
        dom = ed("TargetDomainName") or get(doc, "user.domain") or "LOCAL"
    dom = dom.split(".")[0].upper()
    user = f"{name}@{dom}"
    dst = _host(get(doc, "host.name", "agent.hostname", "winlog.computer_name"))
    src = _host(ed("WorkstationName")) or _host(ed("Workstation")) or \
        _host(get(doc, "source.ip", "winlog.event_data.IpAddress")) or dst

    if code in ("4768", "4769"):
        auth = "Kerberos"
    elif code == "4776":
        auth = "NTLM"
    else:
        pkg = str(ed("AuthenticationPackageName") or ed("LogonProcessName") or "?")
        auth = ("Kerberos" if "kerberos" in pkg.lower() else "NTLM" if "ntlm" in pkg.lower()
                else "Negotiate" if "negotiate" in pkg.lower() else pkg)
    lt = LOGON_TYPE.get(str(ed("LogonType")), "?") if code not in ("4768", "4769", "4776") else "Network"
    if code == "4648":
        lt = "NewCredentials" if lt == "?" else lt

    if code == "4625":
        ok = False
    elif code in ("4768", "4769", "4776"):
        st = str(ed("Status") or "0x0").lower()
        ok = st in ("0x0", "0", "0x00000000")
    else:
        ok = get(doc, "event.outcome", default="success") != "failure"
    return {"time": _ts(doc), "user": user, "dst_user": user, "src_comp": src, "dst_comp": dst,
            "auth_type": auth, "logon_type": lt, "auth_orient": ORIENT[code], "success": ok,
            "os": "windows"}


def map_linux(doc) -> dict | None:
    ds = str(get(doc, "event.dataset", "fileset.name", default=""))
    proc = str(get(doc, "process.name", "system.auth.program", default="")).lower()
    cats = get(doc, "event.category", default="")
    if not ("auth" in ds or "authentication" in str(cats) or proc in ("sshd", "login")):
        return None
    if proc not in ("sshd", "login", "gdm-password", "lightdm"):
        return None  # sudo/su/cron: không phải sự kiện đăng nhập, bỏ qua (có thể bổ sung sau)
    outcome = get(doc, "event.outcome")
    msg = str(get(doc, "message", default=""))
    if outcome is None:  # pipeline tự viết (grok) có thể chưa có event.outcome
        if "Accepted" in msg:
            outcome = "success"
        elif "Failed" in msg or "Invalid user" in msg or "authentication failure" in msg:
            outcome = "failure"
        else:
            return None  # "Disconnected", "session closed"... không tính
    name = get(doc, "user.name", "system.auth.user")
    if not name:
        return None
    dst = _host(get(doc, "host.name", "host.hostname", "agent.hostname"))
    src = _host(get(doc, "source.ip", "source.address", "system.auth.ssh.ip")) or dst
    method = str(get(doc, "system.auth.ssh.method", default="")).lower()
    auth = "SSH-key" if "publickey" in method else "SSH-password" if proc == "sshd" else "Local"
    return {"time": _ts(doc), "user": f"{name}@{dst}", "dst_user": f"{name}@{dst}",
            "src_comp": src, "dst_comp": dst, "auth_type": auth,
            "logon_type": "RemoteInteractive" if proc == "sshd" else "Interactive",
            "auth_orient": "LogOn", "success": outcome == "success", "os": "linux"}


def to_auth_rows(docs) -> pd.DataFrame:
    rows, n, skipped = [], 0, 0
    for d in docs:
        n += 1
        d = d.get("_source", d)
        r = map_windows(d) or map_linux(d)
        if r is None or r["time"] is None:
            skipped += 1
            continue
        rows.append(r)
    print(f"  {n:,} document -> {len(rows):,} sự kiện xác thực (bỏ {skipped:,})")
    return pd.DataFrame(rows)


def finalize(df: pd.DataFrame, tz_offset: float) -> pd.DataFrame:
    df = df.sort_values("time", kind="stable").reset_index(drop=True)
    df["is_machine"] = df["user"].str.contains(r"\$@", regex=True)
    # "day" theo giờ địa phương để active_hours_day / hour_entropy_day có nghĩa
    df["day"] = ((df["time"] + int(tz_offset * 3600)) // 86400).astype("int32")
    for c in ["dst_user", "src_comp", "dst_comp", "auth_type", "logon_type", "auth_orient"]:
        df[c] = df[c].fillna("?").astype("category")
    df["time"] = df["time"].astype("int64")
    return df


def read_ndjson(path):
    with open(path, encoding="utf-8") as f:
        txt = f.read().strip()
    if txt.startswith("["):  # mảng JSON
        yield from json.loads(txt)
        return
    if txt.startswith("{") and '"hits"' in txt[:200]:  # nguyên response _search
        try:
            yield from json.loads(txt)["hits"]["hits"]
            return
        except (json.JSONDecodeError, KeyError):
            pass
    for line in txt.splitlines():
        if line.strip():
            yield json.loads(line)


def read_es(url, index, since, until, size=2000):
    from elasticsearch import Elasticsearch, helpers
    kw = {"basic_auth": (env("ELASTIC_USER", "elastic"), env("ELASTIC_PASSWORD", "changeme"))}
    ca = env("ES_CA_CERT")
    kw.update({"ca_certs": ca} if ca else {"verify_certs": False, "ssl_show_warn": False})
    es = Elasticsearch(url, **kw)
    query = {"bool": {
        "filter": [{"range": {"@timestamp": {"gte": since, "lt": until}}}],
        "should": [{"terms": {"event.code": sorted(WIN_CODES)}},
                   {"terms": {"event.dataset": ["system.auth"]}},
                   {"terms": {"process.name": ["sshd", "login"]}}],
        "minimum_should_match": 1}}
    print(f"  truy vấn {url}/{index} từ {since} đến {until} ...")
    yield from helpers.scan(es, index=index, query={"query": query}, size=size,
                            preserve_order=False, request_timeout=120)


def main():
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--es", help="URL Elasticsearch, vd https://192.168.1.10:9200")
    src.add_argument("--file", help="file NDJSON/JSON đã export")
    ap.add_argument("--index", default="winlogbeat-*,filebeat-*")
    ap.add_argument("--since", default="now-7d/d")
    ap.add_argument("--until", default="now")
    ap.add_argument("--tz-offset", type=float, default=7, help="giờ địa phương so với UTC (VN = 7)")
    ap.add_argument("--out", default="real_auth")
    a = ap.parse_args()

    docs = read_es(a.es, a.index, a.since, a.until) if a.es else read_ndjson(a.file)
    df = to_auth_rows(docs)
    if df.empty:
        raise SystemExit("Không có sự kiện xác thực nào – kiểm tra index/khoảng thời gian/tên trường.")
    df = finalize(df, a.tz_offset)
    p = save_df(df, a.out)
    t0 = datetime.fromtimestamp(df.time.min(), timezone.utc)
    t1 = datetime.fromtimestamp(df.time.max(), timezone.utc)
    print(f"Lưu {len(df):,} sự kiện -> {p}  ({t0:%Y-%m-%d %H:%M} → {t1:%Y-%m-%d %H:%M} UTC)")
    print("  theo OS:", df.os.value_counts().to_dict())
    print(f"  user người: {df.loc[~df.is_machine, 'user'].nunique()} | "
          f"tài khoản máy: {df.loc[df.is_machine, 'user'].nunique()} | host: {df.dst_comp.nunique()}")
    print("  auth_type:", df.auth_type.value_counts().head(6).to_dict())
    print("  logon_type:", df.logon_type.value_counts().head(6).to_dict())
    print(f"  tỉ lệ thất bại: {(~df.success).mean():.1%}")


if __name__ == "__main__":
    main()
