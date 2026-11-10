"""Cài Elastic Stack (Elasticsearch + Kibana) chạy trực tiếp trên Windows – không cần Docker/admin.

Tải bản zip chính thức từ artifacts.elastic.co, kiểm tra SHA-512, giải nén vào ELASTIC_HOME
(mặc định <SOC_DATA_DIR>/elastic = F:/soc-ueba-data/elastic, ngoài repo vì nặng ~1.5GB).

Chạy:  python platform/elastic/install_elastic.py [--version 9.5.5]
"""
import argparse
import hashlib
import os
import shutil
import urllib.request
import zipfile
from pathlib import Path

DEFAULT_HOME = Path(os.environ.get("SOC_DATA_DIR", "F:/soc-ueba-data")) / "elastic"
ELASTIC_VERSION = "9.5.5"   # khớp major với client Python elasticsearch 9.x


def download(url: str, dest: Path):
    tmp = dest.with_suffix(".part")
    with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
        total = int(r.headers.get("Content-Length", 0))
        done = 0
        while chunk := r.read(1 << 20):
            f.write(chunk)
            done += len(chunk)
            if total and done % (100 << 20) < (1 << 20):
                print(f"  {done / 1e6:,.0f}/{total / 1e6:,.0f} MB", flush=True)
    tmp.replace(dest)


def sha512(path: Path) -> str:
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 22), b""):
            h.update(blk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default=ELASTIC_VERSION)
    ap.add_argument("--home", type=Path, default=DEFAULT_HOME)
    args = ap.parse_args()
    args.home.mkdir(parents=True, exist_ok=True)

    for product in ("elasticsearch", "kibana"):
        target = args.home / f"{product}-{args.version}"
        if target.exists():
            print(f"{product} đã có: {target}")
            continue
        name = f"{product}-{args.version}-windows-x86_64.zip"
        url = f"https://artifacts.elastic.co/downloads/{product}/{name}"
        zpath = args.home / name
        if not zpath.exists():
            print(f"Tải {url}", flush=True)
            download(url, zpath)
        expected = urllib.request.urlopen(url + ".sha512", timeout=60).read().decode().split()[0]
        if sha512(zpath) != expected:
            zpath.unlink()
            raise SystemExit(f"SHA-512 sai cho {name} – đã xoá, chạy lại để tải lại")
        print(f"{name}: SHA-512 OK, giải nén...", flush=True)
        with zipfile.ZipFile(zpath) as z:
            z.extractall(args.home)
        zpath.unlink()
    print(f"Xong → {args.home}. Tiếp theo: python platform/elastic/elastic_ctl.py start")


if __name__ == "__main__":
    main()
