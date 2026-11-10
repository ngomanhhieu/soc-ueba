"""A1 cho CERT: rút gọn http.csv (14GB) thành bảng (user, date, domain, số lượt truy cập).

Bảng này dùng để tạo feature "domain hiếm" KHÔNG cần nhãn (cert_features.py): trang web mà
gần như không ai trong công ty vào (vd. wikileaks, trang bán keylogger) tự nổi lên mà không
phải liệt kê sẵn tên miền từ answers/ (liệt kê sẵn = rò nhãn vào feature).

Chạy:  python src/cert_http_domains.py
Kết quả: <SOC_DATA_DIR>/cert/http_user_day_domain.parquet
"""
import time as _time

import pandas as pd
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pv

from config import CERT_RAW

R42 = CERT_RAW / "r4.2"
OUT_PATH = CERT_RAW / "http_user_day_domain.parquet"


def main():
    reader = pv.open_csv(
        R42 / "http.csv", read_options=pv.ReadOptions(block_size=64 << 20),
        convert_options=pv.ConvertOptions(include_columns=["date", "user", "url"],
                                          column_types={c: pa.string()
                                                        for c in ("date", "user", "url")}))
    parts, n, t0 = [], 0, _time.time()
    for batch in reader:
        ts = pc.strptime(batch.column("date"), format="%m/%d/%Y %H:%M:%S", unit="s")
        host = pc.extract_regex(pc.utf8_lower(batch.column("url")),
                                r"^[a-z]+://(?:www\.)?(?P<d>[^/:]+)").field("d")
        df = pd.DataFrame({"user": batch.column("user").to_numpy(zero_copy_only=False),
                           "date": pc.floor_temporal(ts, unit="day")
                           .to_numpy(zero_copy_only=False),
                           "domain": host.to_numpy(zero_copy_only=False)})
        parts.append(df.groupby(["user", "date", "domain"]).size().rename("visits"))
        n += batch.num_rows
        if len(parts) % 20 == 0:
            print(f"  {n:>12,} dòng ({_time.time() - t0:,.0f}s)", flush=True)
    out = pd.concat(parts).groupby(level=[0, 1, 2]).sum().reset_index()
    for c in ("user", "domain"):
        out[c] = out[c].astype("category")
    out["visits"] = out["visits"].astype("int32")
    out.to_parquet(OUT_PATH, index=False)
    print(f"Xong: {n:,} dòng → {len(out):,} (user, ngày, domain), "
          f"{out['domain'].nunique():,} domain → {OUT_PATH} ({_time.time() - t0:,.0f}s)")


if __name__ == "__main__":
    main()
