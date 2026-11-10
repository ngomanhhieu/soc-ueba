"""Dòng thời gian tấn công nội gián (CERT) theo các pha của chuỗi tấn công – bản tương ứng với
đồ thị lateral movement của LANL (CERT không có di chuyển ngang: insider dùng chính tài khoản).

Với mỗi incident CERT, lấy sự kiện của nhân viên trong [ngày đầu − 1, ngày cuối + 1] và xếp vào:
  1. Truy cập      – đăng nhập ngoài giờ / cuối tuần, lần đầu đăng nhập một máy (T1078)
  2. Chuẩn bị      – vào trang tìm việc, trang đối thủ, domain cực hiếm (< 1% nhân viên từng vào)
  3. Cài đặt       – chép file .exe ra USB (mẫu cài keylogger lên máy khác: T1056.001, T1570)
  4. Đánh cắp      – cắm USB, chép file ra USB (T1052.001), email ra ngoài kèm file (T1048.003)
Mỗi bước được đánh dấu MỚI nếu nhân viên không làm việc đó trong 30 ngày trước cửa sổ (so với
chính họ, không dùng nhãn) – analyst nhìn bước MỚI trước.

Gọi trong soc.risk.incidents (qua soc.playbooks.soar) → field attack_chain của incident CERT.
Chạy:  python -m soc.graph.insider_timeline   # đánh giá → soc/reports/insider_timeline_eval.json
"""
import json

import pandas as pd

from soc.config import SOC_REPORTS, STATE_DIR
from soc.rules.datasets import cert_events

BASELINE_DAYS = 30
RARE_POP = 0.01
PHASES = ["Access", "Preparation", "Installation", "Exfiltration"]
# bước: (pha, tên, MITRE)
STEPS = {
    "logon_offhours": ("Access", "Logon outside working hours / at the weekend", "T1078"),
    "logon_new_pc": ("Access", "First logon to this PC", "T1078"),
    "web_job": ("Preparation", "Visited job-search sites (may be leaving)", None),
    "web_competitor": ("Preparation", "Visited competitor websites", None),
    "web_rare": ("Preparation", "Visited very rare domains", None),
    "usb_exe": ("Installation", "Copied an .exe to USB (possible keylogger)", "T1056.001"),
    "usb_connect": ("Exfiltration", "Connected a USB device", "T1052.001"),
    "usb_copy": ("Exfiltration", "Copied files to USB", "T1052.001"),
    "email_ext_attach": ("Exfiltration", "Emailed attachments outside the company", "T1048.003"),
}


def step_events(ev: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Mọi sự kiện thuộc một bước → bảng chung (user, ts, step, detail)."""
    parts = []

    def add(df, step, detail):
        parts.append(pd.DataFrame({"user": df["user.name"].astype(str).values,
                                   "ts": df["@timestamp"].values, "step": step,
                                   "detail": detail.astype(str).values if detail is not None
                                   else ""}))

    lg = ev["logon"][ev["logon"]["event.action"] == "Logon"]
    add(lg[lg["event.offhours"] | lg["event.weekend"]], "logon_offhours", lg["host.name"]
        [lg["event.offhours"] | lg["event.weekend"]])
    # máy lạ = lần đầu tiên nhân viên đăng nhập máy này (chỉ nhìn quá khứ – chạy từng ngày được)
    first = lg.groupby(["user.name", "host.name"], observed=True)["@timestamp"].transform("min")
    other = (lg["@timestamp"] == first).values
    add(lg[other], "logon_new_pc", lg["host.name"][other])
    h = ev["http"]
    for cat, step in (("job", "web_job"), ("competitor", "web_competitor")):
        m = h["url.category"] == cat
        add(h[m], step, h["url.domain"][m])
    m = h["url.org_popularity"] < RARE_POP
    add(h[m], "web_rare", h["url.domain"][m])
    d = ev["device"][ev["device"]["event.action"] == "Connect"]
    add(d, "usb_connect", d["host.name"])
    f = ev["file"]
    add(f, "usb_copy", f["file.name"])
    m = f["file.extension"] == "exe"
    add(f[m], "usb_exe", f["file.name"][m])
    e = ev["email"]
    m = (e["email.external_recipients"] > 0) & (e["email.attachments"] > 0)
    add(e[m], "email_ext_attach", e["host.name"][m])
    s = pd.concat(parts, ignore_index=True)
    s["date"] = pd.to_datetime(s["ts"], unit="s").dt.floor("D")
    return s


def timeline(s_user: pd.DataFrame, start: pd.Timestamp, end: pd.Timestamp) -> list[dict]:
    base = s_user[(s_user["date"] < start) & (s_user["date"] >= start - pd.Timedelta(days=BASELINE_DAYS))]
    seen = set(base["step"])
    w = s_user[(s_user["date"] >= start) & (s_user["date"] <= end)]
    out = []
    for (date, step), g in w.groupby(["date", "step"]):
        phase, name, mitre = STEPS[step]
        out.append({"date": date.strftime("%Y-%m-%d"), "phase": phase, "step": step,
                    "name": name, "mitre": mitre, "count": int(len(g)),
                    "first": pd.to_datetime(g["ts"].min(), unit="s").strftime("%H:%M"),
                    "examples": sorted(set(g["detail"]))[:3], "new": step not in seen})
    order = {p: i for i, p in enumerate(PHASES)}
    return sorted(out, key=lambda x: (x["date"], order[x["phase"]], x["first"]))


def timelines(incidents: list[dict], ev=None) -> dict:
    """incident_id → dòng thời gian (gọi từ soc.playbooks.soar); ev = sự kiện CERT đã đọc sẵn."""
    if ev is None:
        print("  đọc sự kiện CERT cho dòng thời gian…", flush=True)
    s = step_events(ev or cert_events())
    s = s[s["user"].isin({i["entity"] for i in incidents})]
    by_user = dict(tuple(s.groupby("user")))
    out = {}
    for i in incidents:
        a = pd.Timestamp(i["day_first"]) - pd.Timedelta(days=1)
        b = pd.Timestamp(i["day_last"]) + pd.Timedelta(days=1)
        tl = timeline(by_user.get(i["entity"], s.iloc[:0]), a, b)
        out[i["incident_id"]] = {
            "window": [a.strftime("%Y-%m-%d"), b.strftime("%Y-%m-%d")], "steps": tl,
            "new_exfil_steps": sorted({x["step"] for x in tl
                                       if x["new"] and x["phase"] in ("Installation", "Exfiltration")}),
            "phases": sorted({x["phase"] for x in tl if x["new"]}, key=PHASES.index),
            "mitre_ids": sorted({x["mitre"] for x in tl if x["mitre"] and x["new"]})}
    return out


def evaluate(incidents: list[dict]) -> dict:
    """Incident insider thật có bước đánh cắp MỚI thường xuyên hơn incident lành tính không?"""
    df = pd.DataFrame([{"insider": bool(i["ground_truth"]),
                        "new_exfil": bool(i["attack_chain"]["new_exfil_steps"]),
                        "n_new_steps": sum(x["new"] for x in i["attack_chain"]["steps"])}
                       for i in incidents])
    res = {"incidents": len(df), "insider_incidents": int(df["insider"].sum())}
    for name, g in (("insider", df[df["insider"]]), ("benign", df[~df["insider"]])):
        res[f"{name}_with_new_exfil_step"] = float(g["new_exfil"].mean()) if len(g) else None
        res[f"{name}_median_new_steps"] = float(g["n_new_steps"].median()) if len(g) else None
    (SOC_REPORTS / "insider_timeline_eval.json").write_text(json.dumps(res, indent=1),
                                                           encoding="utf-8")
    return res


def main():
    inc = json.loads((STATE_DIR / "incidents_cert.json").read_text(encoding="utf-8"))
    print(json.dumps(evaluate(inc), ensure_ascii=False))


if __name__ == "__main__":
    main()
