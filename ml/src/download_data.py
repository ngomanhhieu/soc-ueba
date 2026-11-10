"""Tải dataset về <SOC_DATA_DIR> (mặc định F:/soc-ueba-data). Có resume: chạy lại sẽ tải tiếp.

LANL: server bắt điền email + mục đích để cấp link (token lưu ở lanl/.token, KHÔNG commit),
và giới hạn ~8KB/s mỗi kết nối → tải song song theo đoạn (HTTP Range). File auth sắp theo thời
gian nên chỉ cần phần đầu (--lanl-gb) là đủ các ngày có red team (ngày 1–15 ≈ 92% red team).
CERT r4.2: tải thẳng từ KiltHub (CMU), có kiểm tra SHA-256.

Ví dụ:
  python src/download_data.py lanl --email ban@gmail.com --lanl-gb 2.6 --connections 16
  python src/download_data.py cert
"""
import argparse
import hashlib
import shutil
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import CERT_RAW, LANL_RAW

UA = {"User-Agent": "Mozilla/5.0 (soc-ueba research download)"}
LANL_BASE = "https://csr.lanl.gov"
CERT_FILES = {  # tên file: id trên figshare (KiltHub article 12841247)
    "SEI_Insider_README.txt": 24860765, "answers.tar.bz2": 24857828,
    "CHECKSUMS-sha256.txt": 24857831, "r4.2.tar.bz2": 24856766,
}
PART_SIZE = 16 << 20


def _get(url, headers=None, timeout=60, method="GET"):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})}, method=method)
    return urllib.request.urlopen(req, timeout=timeout)


def lanl_token(email: str | None, usage: str) -> str:
    tok_file = LANL_RAW / ".token"
    if tok_file.exists():
        return tok_file.read_text().strip()
    if not email:
        sys.exit("Cần --email để LANL cấp link tải lần đầu.")
    q = urllib.parse.urlencode({"email": email, "usage": usage})
    tok = _get(f"{LANL_BASE}/data-fence/token?{q}").read().decode().strip()
    tok_file.write_text(tok)
    return tok


def ranged_download(url: str, dest, total: int, connections: int, start: int = 0):
    """Tải [start, total) theo các đoạn PART_SIZE song song, ghép theo thứ tự vào dest.
    start > 0: dest đã có start byte đầu → chỉ tải phần sau rồi nối tiếp (tăng --lanl-gb)."""
    parts_dir = dest.with_suffix(dest.suffix + f".parts{start}")
    parts_dir.mkdir(parents=True, exist_ok=True)
    ranges = [(i, s, min(s + PART_SIZE, total) - 1)
              for i, s in enumerate(range(start, total, PART_SIZE))]

    def fetch(i, start, end):
        p = parts_dir / f"{i:05d}"
        want = end - start + 1
        if p.exists() and p.stat().st_size == want:
            return 0
        for attempt in range(8):
            try:
                have = p.stat().st_size if p.exists() else 0
                with _get(url, {"Range": f"bytes={start + have}-{end}"}, timeout=120) as r, \
                        open(p, "ab") as f:
                    shutil.copyfileobj(r, f, 1 << 16)
                if p.stat().st_size == want:
                    return want
            except Exception as e:  # mạng chập chờn → thử lại, tải tiếp từ chỗ dở
                time.sleep(5 * (attempt + 1))
                last = e
        raise RuntimeError(f"part {i} lỗi: {last}")

    t0, done = time.time(), 0
    with ThreadPoolExecutor(connections) as ex:
        futs = [ex.submit(fetch, *r) for r in ranges]
        for k, fut in enumerate(as_completed(futs), 1):
            done += fut.result()
            if k % 8 == 0 or k == len(futs):
                speed = done / max(time.time() - t0, 1) / 1024
                print(f"  {k}/{len(futs)} đoạn, {speed:,.0f} KB/s", flush=True)

    with open(dest, "ab" if start else "wb") as out:
        for i, _, _ in ranges:
            with open(parts_dir / f"{i:05d}", "rb") as f:
                shutil.copyfileobj(f, out, 1 << 20)
    shutil.rmtree(parts_dir)
    print(f"  → {dest} ({dest.stat().st_size / 1e9:.2f} GB)")


def download_lanl(args):
    LANL_RAW.mkdir(parents=True, exist_ok=True)
    tok = lanl_token(args.email, args.usage)
    for name in ("redteam.txt.gz",):
        dest = LANL_RAW / name
        if not dest.exists():
            dest.write_bytes(_get(f"{LANL_BASE}/data-fence/{tok}/cyber1/{name}").read())
    url = f"{LANL_BASE}/data-fence/{tok}/cyber1/auth.txt.gz"
    with _get(url, method="HEAD") as r:
        size = int(r.headers["Content-Length"])
    total = size if args.lanl_gb <= 0 else min(size, int(args.lanl_gb * 1e9))
    dest = LANL_RAW / "auth.txt.gz"
    have = dest.stat().st_size if dest.exists() else 0
    if have >= total:
        print(f"LANL auth.txt.gz: đã có {have / 1e9:.2f} GB ≥ {total / 1e9:.2f} GB, bỏ qua")
        return
    print(f"LANL auth.txt.gz: tải {have / 1e9:.2f} → {total / 1e9:.2f}/{size / 1e9:.2f} GB, "
          f"{args.connections} kết nối")
    ranged_download(url, dest, total, args.connections, start=have)
    if total < size:
        print("  (chỉ là phần đầu file – gzip sẽ báo hết đột ngột ở cuối, lanl_load_auth.py "
              "dừng trước đó nếu --end-day nằm trong phần đã tải)")


def download_cert(_args):
    CERT_RAW.mkdir(parents=True, exist_ok=True)
    for name, fid in CERT_FILES.items():
        dest = CERT_RAW / name
        if dest.exists():
            continue
        print("CERT:", name)
        with _get(f"https://ndownloader.figshare.com/files/{fid}", timeout=300) as r, \
                open(dest, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
    sums = dict(line.split()[::-1] for line in
                (CERT_RAW / "CHECKSUMS-sha256.txt").read_text().splitlines() if line.strip())
    for name in ("r4.2.tar.bz2", "answers.tar.bz2"):
        h = hashlib.sha256()
        with open(CERT_RAW / name, "rb") as f:
            for blk in iter(lambda: f.read(1 << 22), b""):
                h.update(blk)
        ok = sums.get(name, sums.get(f"./{name}")) == h.hexdigest()
        print(f"  {name}: SHA-256 {'OK' if ok else 'SAI – tải lại!'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=["lanl", "cert"])
    ap.add_argument("--email")
    ap.add_argument("--usage", default="University graduation project: SOC/UEBA anomaly detection research")
    ap.add_argument("--lanl-gb", type=float, default=2.6, help="0 = tải cả file 7.6GB")
    ap.add_argument("--connections", type=int, default=16)
    args = ap.parse_args()
    {"lanl": download_lanl, "cert": download_cert}[args.dataset](args)


if __name__ == "__main__":
    main()
