"""Web app SOC (FastAPI + HTML/JS thuần, không framework frontend, không CDN).

Chạy:  python -m soc.api.main          → http://127.0.0.1:8000
Chỉ nghe localhost. Triển khai thật: đặt sau reverse proxy HTTPS và bật SESSION_HTTPS_ONLY=1.
"""
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.middleware.sessions import SessionMiddleware

from soc.api import narrative, store
from soc.api.security import (ROLES, SECURITY_HEADERS, LoginThrottle, authenticate,
                              new_csrf)
from soc.config import STATE_DIR
from soc.elastic.elastic_ctl import get_env, set_env

HERE = Path(__file__).parent
SECRET = get_env("SOC_SESSION_SECRET") or secrets.token_urlsafe(48)
set_env("SOC_SESSION_SECRET", SECRET)

app = FastAPI(title="SOC/UEBA", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET, session_cookie="soc_session",
                   max_age=8 * 3600, same_site="strict",
                   https_only=os.environ.get("SESSION_HTTPS_ONLY") == "1")
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
templates = Jinja2Templates(directory=HERE / "templates")
templates.env.globals.update(fmt_min=narrative.fmt_minutes,
                             headline=narrative.headline, reason_text=narrative.reason_text,
                             feature_label=narrative.label, phase_color=narrative.phase_color)
throttle = LoginThrottle()

VERDICTS = {"true_positive": "Real attack", "benign_positive": "Unusual but legitimate",
            "false_positive": "False alarm", "needs_more_info": "Needs more information"}
ACTION_LABEL = {"block_source_host": "Block source host (add IOC)",
                "reset_credentials": "Lock & reset passwords", "monitor_closely": "Watch reached hosts",
                "monitor_account": "Keep watching", "block_usb": "Block USB ports",
                "block_outbound": "Block outbound data", "restrict_access": "Restrict access rights"}
TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access", "Execution",
                "Persistence", "Privilege Escalation", "Defense Evasion", "Stealth", "Credential Access",
                "Discovery", "Lateral Movement", "Collection", "Command and Control",
                "Exfiltration", "Impact"]
STATUS_LABEL = {"new": "New", "investigating": "Investigating", "closed": "Closed"}
DATASET_LABEL = {"lanl": "LANL · sign-ins", "cert": "CERT · insider"}
IOC_ACTIONS = {"block_source_host"}


@app.middleware("http")
async def headers(request: Request, call_next):
    resp = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp


# ---------------------------------------------------------------- phiên / quyền
def user(request: Request) -> dict | None:
    return request.session.get("user")


def need(request: Request, role: str = "analyst") -> dict:
    u = user(request)
    if not u:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    if ROLES[u["role"]] < ROLES[role]:
        store.audit(u["username"], "user", "forbidden", str(request.url.path), outcome="denied")
        raise HTTPException(status_code=403, detail="You do not have permission to do this")
    return u


def check_csrf(request: Request, token: str):
    if not token or not secrets.compare_digest(token, request.session.get("csrf", "")):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")


def render(request: Request, name: str, status_code: int = 200, **ctx):
    u = user(request)
    show_truth = bool(u and u["role"] == "lead" and request.session.get("truth"))
    return templates.TemplateResponse(request, name, {
        "user": u, "csrf": request.session.get("csrf", ""), "show_truth": show_truth,
        "VERDICTS": VERDICTS, "ACTION_LABEL": ACTION_LABEL, "STATUS_LABEL": STATUS_LABEL,
        "DATASET_LABEL": DATASET_LABEL, "path": request.url.path, **ctx}, status_code=status_code)


def truth_on(request: Request) -> bool:
    u = user(request)
    return bool(u and u["role"] == "lead" and request.session.get("truth"))


@app.exception_handler(HTTPException)
async def http_exc(request: Request, exc: HTTPException):
    if exc.status_code == 303:
        return RedirectResponse(exc.headers["Location"], status_code=303)
    return render(request, "error.html", status_code=exc.status_code, code=exc.status_code,
                  detail=exc.detail)


# ---------------------------------------------------------------- đăng nhập
@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    request.session.setdefault("csrf", new_csrf())
    return render(request, "login.html", error=None)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...),
          csrf: str = Form("")):
    check_csrf(request, csrf)
    ip = request.client.host if request.client else "?"
    if throttle.locked(ip, username):
        store.audit(username, "user", "login", outcome="locked")
        return render(request, "login.html", error="Too many failed attempts – locked for 15 minutes")
    u = authenticate(username, password)
    if not u:
        throttle.fail(ip, username)
        store.audit(username, "user", "login", detail={"ip": ip}, outcome="failure")
        return render(request, "login.html", error="Wrong username or password")
    throttle.reset(ip, username)
    request.session.clear()                      # chống session fixation
    request.session.update({"user": u, "csrf": new_csrf()})
    store.audit(username, "user", "login", detail={"ip": ip})
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf: str = Form("")):
    check_csrf(request, csrf)
    u = user(request)
    if u:
        store.audit(u["username"], "user", "logout")
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.post("/truth-mode")
def truth_mode(request: Request, csrf: str = Form("")):
    u = need(request, "lead")
    check_csrf(request, csrf)
    request.session["truth"] = not request.session.get("truth")
    store.audit(u["username"], "user", "toggle_evaluation_mode",
                detail={"on": request.session["truth"]})
    return RedirectResponse(request.headers.get("referer") or "/", status_code=303)


# ---------------------------------------------------------------- trang
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    need(request)
    d = store.dashboard()
    rows = store.list_incidents(size=500, show_truth=truth_on(request))
    open_rows = [i for i in rows if i["status"] != "closed"]
    attention = [i for i in open_rows if i["severity"] == "critical"][:6]
    # thang rủi ro khác nhau giữa bộ dữ liệu / loại thực thể → chuẩn hoá theo max trong nhóm
    peak = {}
    for i in rows:
        k = (i["dataset"], i["entity_type"])
        peak[k] = max(peak.get(k, 0), i["max_risk"])
    risky = sorted(({"entity": i["entity"], "dataset": i["dataset"], "severity": i["severity"],
                     "incident_id": i["incident_id"],
                     "level": i["max_risk"] / (peak[(i["dataset"], i["entity_type"])] or 1)}
                    for i in open_rows), key=lambda x: -x["level"])[:8]
    from soc.replay import clock, fmt
    mode = {ds: clock(ds) for ds in ("lanl", "live", "cert")}
    demo = [f"{name} {fmt(ds, mode[ds])}" for ds, name in
            (("lanl", "LANL test"), ("live", "LANL new days"), ("cert", "CERT"))
            if mode[ds] is not None]
    mp = HERE.parents[1] / "soc" / "reports" / "soc_metrics.json"
    mttd = json.loads(mp.read_text(encoding="utf-8")) if mp.exists() else {}
    return render(request, "dashboard.html", d=d, demo=demo, attention=attention, risky=risky,
                  ops=store.soc_ops(), mttd=mttd,
                  n_open=len(open_rows), n_rows=len(rows), tactics=TACTIC_ORDER)


@app.get("/incidents", response_class=HTMLResponse)
def incidents(request: Request, dataset: str = "", status: str = "", severity: str = "",
              q: str = ""):
    need(request)
    rows = store.list_incidents(dataset or None, status or None, severity or None, q or None, size=1000,
                                show_truth=truth_on(request))
    peak = {}
    for i in store.list_incidents(size=1000):
        k = (i["dataset"], i["entity_type"])
        peak[k] = max(peak.get(k, 0), i["max_risk"])
    return render(request, "incidents.html", rows=rows, peak=peak,
                  f={"dataset": dataset, "status": status, "severity": severity, "q": q})


@app.get("/incidents/{inc_id}", response_class=HTMLResponse)
def incident(request: Request, inc_id: str):
    need(request)
    inc = store.get_incident(inc_id, show_truth=truth_on(request))
    if not inc:
        raise HTTPException(404, "Incident not found")
    alerts = store.incident_alerts(inc_id, show_truth=truth_on(request))
    try:
        ev = store.event_summary(inc["dataset"], inc["entity"])
    except Exception:
        ev = {}
    chain = inc.get("attack_chain") or {}
    svg = chain_svg(chain) if inc["dataset"] == "lanl" and chain.get("attacker_hosts") else ""
    # "vì sao bị phát hiện": gom cảnh báo theo loại phát hiện
    why = {}
    for a in alerts:
        w = why.setdefault(a["rule_title"], {"title": a["rule_title"], "source": a["source"], "n": 0,
                                             "mitre": set(), "reasons": [], "first": a["timestamp"],
                                             "last": a["timestamp"], "truth": False})
        w["n"] += (a.get("features") or {}).get("count", 1)    # cảnh báo đã gộp → cộng bộ đếm
        w["mitre"] |= set(a.get("mitre_ids") or [])
        w["last"] = a["timestamp"]
        w["truth"] |= bool(a.get("ground_truth"))
        for r in (a.get("features") or {}).get("top_reasons", []):
            if r not in w["reasons"]:
                w["reasons"].append(r)
    why = sorted(why.values(), key=lambda w: (w["source"] != "ml", -w["n"]))
    phases = {}
    for s in chain.get("steps", []):
        phases.setdefault(s["phase"], []).append(s)
    return render(request, "incident.html", inc=inc, alerts=alerts, ev=ev, chain=chain,
                  chain_svg=svg, why=why, phases=phases, PHASES=PHASE_INFO, EV_LABEL=EV_LABEL)


PHASE_INFO = [("Access", "unusual logons"), ("Preparation", "job hunting, rare websites"),
              ("Installation", "tools copied to USB"), ("Exfiltration", "data leaves via USB / email")]
EV_LABEL = {"destination.host": "Hosts signed in to", "source.host": "Signed in from",
            "user.name": "Accounts", "auth.type": "Authentication", "logon.type": "Logon type",
            "event.outcome": "Result", "event.action": "Action", "event.dataset": "Activity type",
            "host.name": "PCs used", "url.domain": "Websites", "url.category": "Website category",
            "file.extension": "File types copied", "rare_domains": "Very rare websites"}


def chain_svg(g: dict, top: int = 9) -> Markup:
    """Đồ thị chuỗi tấn công 3 cột: máy tấn công → tài khoản bị chiếm → máy bị chạm tới. SVG dựng
    ở server (đường cong Bézier, class CSS – hợp CSP, không script)."""
    tl = g.get("timeline") or []
    cnt_u, cnt_d = {}, {}
    for e in tl:
        cnt_u[e["user"]] = cnt_u.get(e["user"], 0) + e["n"]
        cnt_d[e["dst"]] = cnt_d.get(e["dst"], 0) + e["n"]
    srcs = g["attacker_hosts"][:4]
    users = sorted(cnt_u, key=lambda u: -cnt_u[u])[:top]
    dsts = [d for d in sorted(cnt_d, key=lambda d: -cnt_d[d]) if d not in g["attacker_hosts"]][:top]
    rows = max(len(srcs), len(users), len(dsts), 1)
    gap, bh = 34, 24
    W, H = 900, rows * gap + 44
    cols = {"s": (20, 170), "u": (365, 190), "d": (715, 165)}      # x, độ rộng hộp

    def ys(n):
        return [38 + i * gap + (rows - n) * gap / 2 for i in range(n)]
    pos = {("s", h): y for h, y in zip(srcs, ys(len(srcs)))}
    pos |= {("u", u): y for u, y in zip(users, ys(len(users)))}
    pos |= {("d", d): y for d, y in zip(dsts, ys(len(dsts)))}
    out = [f'<svg class="chain" viewBox="0 0 {W} {H}" role="img" aria-label="Attack chain graph">',
           f'<text class="hd" x="{cols["s"][0]}" y="18">Attacker host{"s" if len(srcs) > 1 else ""}</text>',
           f'<text class="hd" x="{cols["u"][0]}" y="18">Accounts used · top {len(users)} of '
           f'{len(g["compromised_accounts"])}</text>',
           f'<text class="hd" x="{cols["d"][0]}" y="18">Hosts reached · top {len(dsts)} of '
           f'{len(g["touched_hosts"])}</text>']
    seen = set()
    for e in tl:
        ntlm = " ntlm" if e["auth"] == "NTLM" else ""
        for a, b in ((("s", e["src"]), ("u", e["user"])), (("u", e["user"]), ("d", e["dst"]))):
            if a in pos and b in pos and (a, b) not in seen:
                seen.add((a, b))
                x1 = cols[a[0]][0] + cols[a[0]][1]
                x2 = cols[b[0]][0]
                y1, y2 = pos[a] + bh / 2, pos[b] + bh / 2
                mx = (x1 + x2) / 2
                out.append(f'<path class="{ntlm.strip()}" d="M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}"/>')
    for (k, name), y in pos.items():
        x, w = cols[k]
        cls = {"s": "node src", "u": "node acc", "d": "node"}[k]
        if k == "s" and name == g.get("main_host"):
            cls += " jump"
        out.append(f'<rect class="{cls}" x="{x}" y="{y}" width="{w}" height="{bh}" rx="12"/>'
                   f'<text class="lbl" x="{x + w / 2}" y="{y + 16}" text-anchor="middle">'
                   f'{escape(name)}</text>')
    out.append("</svg>")
    return Markup("".join(out))


@app.post("/incidents/{inc_id}/verdict")
def verdict(request: Request, inc_id: str, verdict: str = Form(...), notes: str = Form(""),
            csrf: str = Form("")):
    u = need(request)
    check_csrf(request, csrf)
    if verdict not in VERDICTS:
        raise HTTPException(400, "Invalid verdict")
    status = "investigating" if verdict == "needs_more_info" else "closed"
    store.update_incident(inc_id, {"verdict": verdict, "verdict_by": u["username"],
                                   "verdict_at": store.now(), "notes": notes[:2000],
                                   "status": status})
    store.audit(u["username"], "user", "set_verdict", inc_id, detail={"verdict": verdict})
    return RedirectResponse(f"/incidents/{inc_id}", status_code=303)


@app.post("/incidents/{inc_id}/approve")
def approve(request: Request, inc_id: str, idx: int = Form(...), decision: str = Form(...),
            csrf: str = Form("")):
    """Lead duyệt/từ chối 1 hành động playbook đề xuất. Thực thi = mô phỏng (ghi nhận), riêng
    "chặn máy nguồn" → thêm IOC thật vào danh sách (luật Sigma IOC dùng ngay)."""
    u = need(request, "lead")
    check_csrf(request, csrf)
    inc = store.get_incident(inc_id, show_truth=True)
    ana = (inc or {}).get("playbook") or {}
    acts = ana.get("recommended_actions") or []
    if not (0 <= idx < len(acts)) or decision not in ("approve", "reject"):
        raise HTTPException(400, "Invalid action")
    act = acts[idx]
    done = inc.get("actions") or []
    done.append({**act, "decision": decision, "by": u["username"], "at": store.now(),
                 "executed": "simulated" if decision == "approve" else None})
    store.update_incident(inc_id, {"actions": done})
    if decision == "approve" and act["action"] in IOC_ACTIONS:
        value = act["target"].removeprefix("host:")
        store.add_ioc(value, "host", inc_id, u["username"], act["reason"][:500])
    store.audit(u["username"], "user", f"action_{decision}", inc_id, detail=act)
    return RedirectResponse(f"/incidents/{inc_id}", status_code=303)


@app.get("/entity/{entity:path}", response_class=HTMLResponse)
def entity(request: Request, entity: str):
    need(request)
    al = store.entity_alerts(entity, show_truth=truth_on(request))
    incs = store.list_incidents(q=entity, show_truth=truth_on(request))
    days = {}
    for a in al:
        d = days.setdefault(a["timestamp"][:10], {"day": a["timestamp"][:10], "rule": 0, "ml": 0})
        d[a["source"] if a["source"] in ("rule", "ml") else "rule"] +=             (a.get("features") or {}).get("count", 1)
    # "bình thường vs hôm nay": cảnh báo ML có điểm cao nhất (gần nhất nếu bằng nhau)
    ml = [a for a in al if a["source"] == "ml" and a["features"].get("baseline")]
    focus = max(ml, key=lambda a: (a["anomaly_score"], a["timestamp"])) if ml else None
    compare = []
    if focus:
        f, base = focus["features"], focus["features"]["baseline"]
        hot = {r.removeprefix("trend_").removeprefix("w30_") for r in f.get("top_reasons", [])}
        for k, b in base.items():
            if k.startswith("_") or k not in f:
                continue
            v, top = float(f[k]), max(float(f[k]), float(b), 1e-9)
            compare.append({"key": k, "label": narrative.label(k), "today": v, "base": float(b),
                            "wt": round(100 * v / top), "wb": round(100 * b / top),
                            "hot": k in hot, "ratio": (v + 1) / (b + 1)})
        compare.sort(key=lambda c: (not c["hot"], -c["ratio"]))
        compare = [c for c in compare if c["hot"] or c["today"] != c["base"]][:10]
    kind = "host" if entity.startswith("host:") else (
        "employee" if (incs and incs[0]["dataset"] == "cert") else "account")
    return render(request, "entity.html", entity=entity, alerts=al, incidents=incs,
                  per_day=sorted(days.values(), key=lambda x: x["day"]), focus=focus,
                  compare=compare, kind=kind)


@app.get("/ioc", response_class=HTMLResponse)
def ioc(request: Request):
    need(request)
    return render(request, "ioc.html", items=store.list_ioc())


@app.post("/ioc/{ioc_id:path}/deactivate")
def ioc_off(request: Request, ioc_id: str, csrf: str = Form("")):
    u = need(request, "lead")
    check_csrf(request, csrf)
    store.deactivate_ioc(ioc_id)
    store.audit(u["username"], "user", "ioc_deactivate", ioc_id)
    return RedirectResponse("/ioc", status_code=303)


@app.get("/audit", response_class=HTMLResponse)
def audit(request: Request):
    need(request, "lead")
    return render(request, "audit.html", items=store.audit_log())


# ---------------------------------------------------------------- demo replay (lead)
# Chạy pipeline thành TIẾN TRÌNH RIÊNG (dùng user ES soc_pipeline) – web app không giữ quyền ghi
# dữ liệu phát hiện. Mỗi lúc chỉ 1 tác vụ.
REPLAY_CMDS = {f"{ds}_{a}": cmd for ds in ("lanl", "live", "cert") for a, cmd in (
    ("reset", ["-m", "soc.replay", "reset", "--dataset", ds]),
    ("next", ["-m", "soc.replay", "next", "--dataset", ds] + (["--days", "7"] if ds == "cert" else [])),
    ("restore", ["-m", "soc.elastic.ingest", "--dataset", "cert" if ds == "cert" else "lanl"]))}
JOB = {"proc": None, "action": None, "by": None, "at": None}
JOB_LOG = STATE_DIR / "replay_job.log"
REPO = HERE.parents[1]


def replay_state() -> dict:
    from soc.replay import clock, fmt
    p = JOB["proc"]
    lines = JOB_LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-25:] \
        if JOB_LOG.exists() else []
    return {"day": {ds: fmt(ds, clock(ds)) for ds in ("lanl", "live", "cert")},
            "running": bool(p and p.poll() is None), "action": JOB["action"], "by": JOB["by"],
            "at": JOB["at"], "exit_code": None if not p or p.poll() is None else p.returncode,
            "log": [ln for ln in lines if "Warning" not in ln and "warn(" not in ln]}


@app.get("/replay", response_class=HTMLResponse)
def replay_page(request: Request):
    need(request, "lead")
    return render(request, "replay.html", st=replay_state())


@app.get("/replay/status")
def replay_status(request: Request):
    need(request, "lead")
    return JSONResponse(replay_state())


@app.post("/replay/{action}")
def replay_run(request: Request, action: str, csrf: str = Form("")):
    u = need(request, "lead")
    check_csrf(request, csrf)
    if action not in REPLAY_CMDS:
        raise HTTPException(400, "Invalid task")
    if replay_state()["running"]:
        raise HTTPException(409, "A task is already running – wait for it to finish")
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
    with open(JOB_LOG, "wb") as f:
        JOB["proc"] = subprocess.Popen([sys.executable, *REPLAY_CMDS[action]], cwd=REPO,
                                       stdin=subprocess.DEVNULL, stdout=f,
                                       stderr=subprocess.STDOUT, env=env)
    JOB.update(action=action, by=u["username"], at=store.now())
    store.audit(u["username"], "user", f"replay_{action}")
    return RedirectResponse("/replay", status_code=303)


@app.get("/healthz")
def health():
    return JSONResponse({"ok": True})


def main():
    import uvicorn
    uvicorn.run("soc.api.main:app", host="127.0.0.1", port=int(os.environ.get("SOC_PORT", 8000)),
                proxy_headers=False, server_header=False)


if __name__ == "__main__":
    main()
