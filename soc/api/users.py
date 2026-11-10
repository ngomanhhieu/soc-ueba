"""Quản lý tài khoản web app SOC.

  python -m soc.api.users add <tên> --role analyst|lead     # nhập mật khẩu (ẩn)
  python -m soc.api.users add <tên> --role lead --password X --allow-weak   # demo cục bộ, bỏ
                                                           # yêu cầu ≥ 12 ký tự (KHÔNG dùng thật)
  python -m soc.api.users demo                             # tạo 2 tài khoản demo, mật khẩu ngẫu
                                                           # nhiên ghi vào .env (không commit)
  python -m soc.api.users list
"""
import argparse
import getpass
import secrets

from soc.api.security import load_users, save_user
from soc.elastic.elastic_ctl import set_env


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["add", "demo", "list"])
    ap.add_argument("username", nargs="?")
    ap.add_argument("--role", default="analyst")
    ap.add_argument("--password", help="không nhập ẩn (chỉ cho demo cục bộ)")
    ap.add_argument("--allow-weak", action="store_true", help="bỏ yêu cầu ≥ 12 ký tự (demo cục bộ)")
    a = ap.parse_args()
    if a.cmd == "add":
        pw = a.password or getpass.getpass("Mật khẩu (≥12 ký tự): ")
        save_user(a.username, pw, a.role, allow_weak=a.allow_weak)
        print(f"Đã tạo {a.username} ({a.role})")
    elif a.cmd == "demo":
        for user, role in (("analyst1", "analyst"), ("lead1", "lead")):
            pw = secrets.token_urlsafe(12)
            save_user(user, pw, role)
            set_env(f"SOC_DEMO_{user.upper()}_PASSWORD", pw)
            print(f"{user} ({role}) – mật khẩu trong .env: SOC_DEMO_{user.upper()}_PASSWORD")
    else:
        for u, v in load_users().items():
            print(u, v["role"])


if __name__ == "__main__":
    main()
