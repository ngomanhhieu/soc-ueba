"""Cấu hình + bật/tắt Elasticsearch và Kibana (bản zip Windows, chạy nền, không cần admin).

Bảo mật mặc định:
  * Elasticsearch: bật xpack.security, HTTPS (chứng chỉ ES tự sinh lần đầu), chỉ nghe 127.0.0.1
  * mật khẩu user `elastic` sinh ngẫu nhiên, lưu vào .env (không commit)
  * Kibana nối tới ES bằng service account token (không dùng mật khẩu superuser), có khoá mã
    hoá saved objects (bắt buộc cho Security/Detection Engine)
Dữ liệu + log ở <ELASTIC_HOME>/esdata, kbdata, logs (ngoài repo).

Chạy (từ gốc repo):
  python -m soc.elastic.elastic_ctl setup     # lần đầu: cấu hình, bật ES, đặt mật khẩu, token Kibana
  python -m soc.elastic.elastic_ctl start     # bật ES + Kibana
  python -m soc.elastic.elastic_ctl status | stop
"""
import argparse
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.request

from soc.config import ELASTIC_HOME, ELASTIC_VERSION, ES_CA, ES_URL, KIBANA_URL, REPO_DIR

ES_DIR = ELASTIC_HOME / f"elasticsearch-{ELASTIC_VERSION}"
KB_DIR = ELASTIC_HOME / f"kibana-{ELASTIC_VERSION}"
LOG_DIR = ELASTIC_HOME / "logs"
PID_FILE = {"es": ELASTIC_HOME / "es.pid", "kibana": ELASTIC_HOME / "kibana.pid"}
ENV_PATH = REPO_DIR / ".env"
HEAP = os.environ.get("ES_HEAP", "2g")
DETACH = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS \
    if sys.platform == "win32" else 0


def _p(path) -> str:
    return str(path).replace("\\", "/")


def set_env(key: str, value: str):
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines() if ENV_PATH.exists() else []
    lines = [ln for ln in lines if not ln.startswith(f"{key}=")] + [f"{key}={value}"]
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.environ[key] = value


def get_env(key: str) -> str:
    if ENV_PATH.exists():
        for ln in ENV_PATH.read_text(encoding="utf-8").splitlines():
            if ln.startswith(f"{key}="):
                return ln.split("=", 1)[1]
    return os.environ.get(key, "")


def write_es_config():
    cfg = ES_DIR / "config" / "elasticsearch.yml"
    text = cfg.read_text(encoding="utf-8")
    marker = "# ---- soc-ueba ----"
    if marker not in text:
        text += f"""
{marker}
cluster.name: soc-ueba
node.name: soc-node-1
path.data: {_p(ELASTIC_HOME / 'esdata')}
path.logs: {_p(LOG_DIR / 'es')}
network.host: 127.0.0.1
http.port: 9200
"""
        cfg.write_text(text, encoding="utf-8")
    heap = ES_DIR / "config" / "jvm.options.d" / "heap.options"
    heap.write_text(f"-Xms{HEAP}\n-Xmx{HEAP}\n", encoding="utf-8")


def write_kibana_config(token: str):
    cfg = KB_DIR / "config" / "kibana.yml"
    keys = {k: get_env(k) or secrets.token_hex(16)
            for k in ("KIBANA_ENC_KEY_SO", "KIBANA_ENC_KEY_SEC", "KIBANA_ENC_KEY_REP")}
    for k, v in keys.items():
        set_env(k, v)
    cfg.write_text(f"""# sinh bởi soc/elastic/elastic_ctl.py
server.host: "127.0.0.1"
server.port: 5601
path.data: {_p(ELASTIC_HOME / 'kbdata')}
logging.appenders.file:
  type: file
  fileName: {_p(LOG_DIR / 'kibana.log')}
  layout: {{type: json}}
logging.root.appenders: [default, file]
elasticsearch.hosts: ["{ES_URL}"]
elasticsearch.serviceAccountToken: "{token}"
elasticsearch.ssl.certificateAuthorities: ["{_p(ES_CA)}"]
xpack.encryptedSavedObjects.encryptionKey: "{keys['KIBANA_ENC_KEY_SO']}"
xpack.security.encryptionKey: "{keys['KIBANA_ENC_KEY_SEC']}"
xpack.reporting.encryptionKey: "{keys['KIBANA_ENC_KEY_REP']}"
telemetry.optIn: false
""", encoding="utf-8")


def _running(name: str) -> bool:
    f = PID_FILE[name]
    if not f.exists():
        return False
    pid = f.read_text().strip()
    out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True)
    return pid in out.stdout


def _launch(name: str, exe, log):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    # Tách hẳn khỏi phiên gọi: không stdin, nhóm tiến trình riêng, thoát job của tiến trình cha
    # (nếu được phép) – Ctrl+C hay đóng terminal không làm tắt ES/Kibana.
    breakaway = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0)
    with open(log, "ab") as f:
        try:
            p = subprocess.Popen([str(exe)], stdin=subprocess.DEVNULL, stdout=f,
                                 stderr=subprocess.STDOUT, cwd=exe.parent.parent,
                                 creationflags=DETACH | breakaway)
        except OSError:
            p = subprocess.Popen([str(exe)], stdin=subprocess.DEVNULL, stdout=f,
                                 stderr=subprocess.STDOUT, cwd=exe.parent.parent,
                                 creationflags=DETACH)
    PID_FILE[name].write_text(str(p.pid))
    print(f"  {name} pid={p.pid}, log={log}")


def es_request(path: str, method="GET", body: bytes | None = None, password: str | None = None,
               timeout=10):
    import base64
    import ssl
    ctx = ssl.create_default_context(cafile=str(ES_CA))
    req = urllib.request.Request(ES_URL + path, data=body, method=method,
                                 headers={"Content-Type": "application/json"})
    pw = password if password is not None else get_env("ELASTIC_PASSWORD")
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(f"elastic:{pw}".encode()).decode())
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        return r.read().decode()


def wait_es(timeout=240) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        if ES_CA.exists():
            try:
                es_request("/", password=get_env("ELASTIC_PASSWORD") or "x")
                return True
            except urllib.error.HTTPError as e:   # 401 = ES đã lên, chỉ là chưa có mật khẩu đúng
                if e.code == 401:
                    return True
            except Exception:
                pass
        time.sleep(3)
    return False


def wait_kibana(timeout=600) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(KIBANA_URL + "/api/status", timeout=5) as r:
                if r.status in (200, 401):
                    return True
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return True
        except Exception:
            pass
        time.sleep(5)
    return False


def start(which=("es", "kibana")):
    if "es" in which:
        if _running("es"):
            print("Elasticsearch đang chạy")
        else:
            print("Bật Elasticsearch...")
            _launch("es", ES_DIR / "bin" / "elasticsearch.bat", LOG_DIR / "es_stdout.log")
        print("  chờ ES sẵn sàng:", "OK" if wait_es() else "QUÁ THỜI GIAN – xem log")
    if "kibana" in which:
        if _running("kibana"):
            print("Kibana đang chạy")
        else:
            print("Bật Kibana...")
            _launch("kibana", KB_DIR / "bin" / "kibana.bat", LOG_DIR / "kibana_stdout.log")
        print("  chờ Kibana sẵn sàng:", "OK" if wait_kibana() else "QUÁ THỜI GIAN – xem log")


def stop():
    for name in ("kibana", "es"):
        if _running(name):
            pid = PID_FILE[name].read_text().strip()
            subprocess.run(["taskkill", "/PID", pid, "/T", "/F"], capture_output=True)
            print(f"Đã tắt {name} (pid {pid})")
        PID_FILE[name].unlink(missing_ok=True)


def setup():
    if not ES_DIR.exists() or not KB_DIR.exists():
        raise SystemExit("Chưa cài Elastic – chạy soc/elastic/install_elastic.py trước")
    write_es_config()
    start(("es",))
    # đặt mật khẩu elastic ngẫu nhiên (in ra stdout ở chế độ -b -s)
    pw = subprocess.run([str(ES_DIR / "bin" / "elasticsearch-reset-password.bat"), "-u", "elastic",
                         "-b", "-s", "--url", ES_URL], capture_output=True, text=True,
                        cwd=ES_DIR).stdout.strip().splitlines()[-1]
    set_env("ELASTIC_PASSWORD", pw)
    print("  đã đặt mật khẩu user elastic → .env (ELASTIC_PASSWORD)")
    # token service account cho Kibana (thay token cũ nếu có)
    try:
        es_request("/_security/service/elastic/kibana/credential/token/soc-kibana", "DELETE")
    except Exception:
        pass
    resp = es_request("/_security/service/elastic/kibana/credential/token/soc-kibana", "POST")
    token = re.search(r'"value"\s*:\s*"([^"]+)"', resp).group(1)
    write_kibana_config(token)
    print("  đã tạo token Kibana + khoá mã hoá → kibana.yml")
    start(("kibana",))


def status():
    for name in ("es", "kibana"):
        print(f"{name}: {'đang chạy' if _running(name) else 'tắt'}")
    try:
        print(es_request("/_cluster/health"))
    except Exception as e:
        print("ES không trả lời:", e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["setup", "start", "stop", "status"])
    a = ap.parse_args()
    {"setup": setup, "start": start, "stop": stop, "status": status}[a.cmd]()


if __name__ == "__main__":
    main()
