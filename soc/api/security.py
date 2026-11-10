"""Bảo mật cho chính web app SOC (một hệ thống giám sát cũng là mục tiêu tấn công).

  * Mật khẩu: PBKDF2-HMAC-SHA256, salt ngẫu nhiên, 310 000 vòng (khuyến nghị OWASP); so sánh
    hằng thời gian. Lưu ở <STATE_DIR>/users.json (ngoài repo).
  * Phân quyền (RBAC): analyst – xem, gắn nhãn TP/FP, yêu cầu AI phân tích;
                      lead    – thêm: duyệt hành động ứng phó, quản lý IOC, xem nhật ký kiểm toán.
  * CSRF: token ngẫu nhiên gắn với phiên, bắt buộc cho mọi request thay đổi dữ liệu.
  * Chống dò mật khẩu: khoá tạm sau 5 lần sai / 15 phút theo (IP, tên đăng nhập).
  * Header bảo mật: CSP chỉ cho phép tài nguyên cùng nguồn, chặn nhúng iframe, nosniff...
"""
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict

from soc.config import STATE_DIR

USERS_PATH = STATE_DIR / "users.json"
ROLES = {"analyst": 1, "lead": 2}
ITERATIONS = 310_000
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, it, salt, dk = stored.split("$")
        cand = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
        return hmac.compare_digest(cand.hex(), dk)
    except ValueError:
        return False


def load_users() -> dict:
    return json.loads(USERS_PATH.read_text(encoding="utf-8")) if USERS_PATH.exists() else {}


def save_user(username: str, password: str, role: str, allow_weak: bool = False):
    """allow_weak: chỉ cho tài khoản demo trên máy cá nhân (người dùng yêu cầu rõ ràng)."""
    if role not in ROLES:
        raise ValueError(f"role phải là {list(ROLES)}")
    if len(password) < 12 and not allow_weak:
        raise ValueError("mật khẩu tối thiểu 12 ký tự")
    users = load_users()
    users[username] = {"password": hash_password(password), "role": role}
    USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")


_DUMMY = hash_password("dummy-password-for-timing")


def authenticate(username: str, password: str) -> dict | None:
    u = load_users().get(username)
    if not u:
        verify_password(password, _DUMMY)          # cùng thời gian dù user không tồn tại
        return None
    return {"username": username, "role": u["role"]} if verify_password(password, u["password"]) \
        else None


class LoginThrottle:
    def __init__(self):
        self.fails = defaultdict(list)

    def _key(self, ip, user):
        return f"{ip}|{user.lower()}"

    def locked(self, ip, user) -> bool:
        now = time.time()
        k = self._key(ip, user)
        self.fails[k] = [t for t in self.fails[k] if now - t < LOCK_SECONDS]
        return len(self.fails[k]) >= MAX_FAILS

    def fail(self, ip, user):
        self.fails[self._key(ip, user)].append(time.time())

    def reset(self, ip, user):
        self.fails.pop(self._key(ip, user), None)


def new_csrf() -> str:
    return secrets.token_urlsafe(32)


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                               "script-src 'self'; frame-ancestors 'none'; form-action 'self'; "
                               "base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}
