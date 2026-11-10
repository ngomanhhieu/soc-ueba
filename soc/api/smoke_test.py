"""Kiểm thử nhanh web app đang chạy (http://127.0.0.1:8000): đăng nhập, phân quyền, CSRF,
khoá do sai mật khẩu, header bảo mật, các trang chính. Dùng tài khoản demo trong .env.

Chạy:  python -m soc.api.smoke_test
"""
import http.cookiejar
import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request

import soc.config  # noqa: F401  (nạp .env)
from soc.api.security import USERS_PATH, load_users, save_user

BASE = os.environ.get("SOC_URL", "http://127.0.0.1:8000")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def session():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), NoRedirect())


def req(op, path, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    try:
        r = op.open(BASE + path, data=body, timeout=60)
        return r.status, r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)


def csrf_of(html):
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(op, user, pw):
    _, html, _ = req(op, "/login")
    return req(op, "/login", {"username": user, "password": pw, "csrf": csrf_of(html)})


def check(name, cond):
    print(("OK  " if cond else "FAIL"), name)
    return cond


def main():
    ok = True
    a = session()
    s, _, h = req(a, "/")
    ok &= check("chưa đăng nhập → chuyển tới /login", s == 303 and h.get("location") == "/login")
    s, html, h = req(a, "/login")
    ok &= check("header CSP + X-Frame-Options", "default-src 'self'" in h.get(
        "content-security-policy", "") and h.get("x-frame-options") == "DENY")
    s, _, _ = req(a, "/login", {"username": "analyst1", "password": "x", "csrf": "sai"})
    ok &= check("POST thiếu CSRF đúng → 403", s == 403)
    s, html, _ = login(a, "analyst1", "sai-mat-khau")
    ok &= check("sai mật khẩu → báo lỗi", "Wrong username or password" in html)
    s, _, h = login(a, "analyst1", os.environ["SOC_DEMO_ANALYST1_PASSWORD"])
    ok &= check("analyst đăng nhập được", s == 303)
    for p in ("/", "/incidents", "/ioc"):
        s, html, _ = req(a, p)
        ok &= check(f"analyst xem {p}", s == 200)
    s, _, _ = req(a, "/audit")
    ok &= check("analyst KHÔNG xem được nhật ký kiểm toán (403)", s == 403)
    _, html, _ = req(a, "/")
    s, _, _ = req(a, "/truth-mode", {"csrf": csrf_of(html)})
    ok &= check("analyst KHÔNG bật được chế độ đánh giá (403)", s == 403)
    _, html, _ = req(a, "/incidents?dataset=lanl&q=host:C17693")
    ids = re.findall(r'href="/incidents/(INC-LANL-[0-9a-f]+)"', html)
    s, html, _ = req(a, f"/incidents/{ids[0]}") if ids else (0, "", {})
    ok &= check("incident LANL: playbook + đồ thị chuỗi tấn công (SVG, D3FEND)",
                s == 200 and "Response plan" in html and '<svg class="chain"' in html
                and "D3FEND" in html)
    if ids:
        s, _, _ = req(a, f"/incidents/{ids[0]}/approve",
                      {"idx": 0, "decision": "approve", "csrf": csrf_of(html)})
        ok &= check("analyst KHÔNG duyệt được hành động playbook (403)", s == 403)
    _, html, _ = req(a, "/incidents?dataset=cert")
    ids = re.findall(r'href="/incidents/(INC-CERT-[0-9a-f]+)"', html)
    s, html, _ = req(a, f"/incidents/{ids[0]}") if ids else (0, "", {})
    ok &= check("incident CERT: playbook + dòng thời gian nội gián",
                s == 200 and "PB-CERT" in html and "Exfiltration" in html and "Attack story" in html)
    s, _, _ = req(a, "/replay")
    ok &= check("analyst KHÔNG vào được demo replay (403)", s == 403)
    lead = session()
    login(lead, "lead1", os.environ["SOC_DEMO_LEAD1_PASSWORD"])
    s, html, _ = req(lead, "/replay")
    ok &= check("lead: trang replay có cả LANL và CERT",
                s == 200 and "LANL – stolen accounts" in html and "CERT – insider threat" in html)

    # Thử khoá trên tài khoản TẠM (không khoá nhầm tài khoản demo thật), xoá khi xong
    tmp_user, tmp_pw = f"smoke_{secrets.token_hex(3)}", secrets.token_urlsafe(16)
    save_user(tmp_user, tmp_pw, "analyst")
    try:
        b = session()
        for _ in range(5):
            login(b, tmp_user, "sai")
        s, html, _ = login(b, tmp_user, tmp_pw)
        ok &= check("5 lần sai → khoá tạm cả khi đúng mật khẩu", "locked for 15 minutes" in html)
        c = session()   # cùng IP nhưng throttle theo (IP, user) – user khác không bị ảnh hưởng
        s, _, _ = login(c, "analyst1", os.environ["SOC_DEMO_ANALYST1_PASSWORD"])
        ok &= check("khoá chỉ áp cho tài khoản bị dò", s == 303)
    finally:
        users = load_users()
        users.pop(tmp_user, None)
        USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")
    print("\nTẤT CẢ ĐẠT" if ok else "\nCÓ LỖI")


if __name__ == "__main__":
    main()
