"""A1 – Bước 2: đọc auth.txt.gz (7.2GB nén, ~1 tỷ dòng) theo luồng, lọc khoảng ngày,
gắn nhãn red team và ghi ra parquet theo từng ngày.

Không giải nén file gốc: đọc thẳng gzip bằng pyarrow theo block (RAM ~1-2GB).
File sắp xếp theo thời gian nên dừng đọc ngay khi vượt qua ngày cuối.

Chạy:  python src/lanl_load_auth.py --start-day 0 --end-day 29
Kết quả: <SOC_DATA_DIR>/lanl_events/auth_day00.parquet, auth_day01.parquet, ...
"""
import argparse
import time as _time

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.csv as pv
import pyarrow.parquet as pq

from config import AUTH_COLS, LANL_AUTH_GZ, LANL_EVENTS_DIR, SECONDS_PER_DAY
from lanl_explore_redteam import load_redteam

STRING_COLS = AUTH_COLS[1:]


def day_path(day: int):
    return LANL_EVENTS_DIR / f"auth_day{day:02d}.parquet"


def redteam_labels(batch: pa.RecordBatch, red_times: pa.Array, red_keys: set) -> pa.Array:
    """True nếu dòng trùng (time, user, src_comp, dst_comp) với một sự kiện red team."""
    candidates = pc.is_in(batch.column("time"), value_set=red_times)
    labels = [False] * batch.num_rows
    idx = pc.indices_nonzero(candidates).to_pylist()
    if idx:
        t = batch.column("time")
        u, s, d = (batch.column(c) for c in ("src_user", "src_comp", "dst_comp"))
        for i in idx:
            key = (t[i].as_py(), u[i].as_py(), s[i].as_py(), d[i].as_py())
            labels[i] = key in red_keys
    return pa.array(labels, type=pa.bool_())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start-day", type=int, default=0)
    ap.add_argument("--end-day", type=int, default=29, help="ngày cuối (bao gồm)")
    ap.add_argument("--overwrite", action="store_true", help="ghi đè ngày đã có parquet")
    args = ap.parse_args()

    LANL_EVENTS_DIR.mkdir(parents=True, exist_ok=True)
    t_start, t_end = args.start_day * SECONDS_PER_DAY, (args.end_day + 1) * SECONDS_PER_DAY

    red = load_redteam()
    red_keys = set(map(tuple, red[["time", "user", "src_comp", "dst_comp"]].itertuples(index=False)))
    red_times = pa.array(sorted(red["time"].unique()), type=pa.int64())

    schema = pa.schema([("time", pa.int64())] + [(c, pa.string()) for c in STRING_COLS]
                       + [("is_redteam", pa.bool_())])
    reader = pv.open_csv(
        pa.input_stream(str(LANL_AUTH_GZ), compression="gzip"),
        read_options=pv.ReadOptions(column_names=AUTH_COLS, block_size=64 << 20),
        convert_options=pv.ConvertOptions(
            column_types={"time": pa.int64(), **{c: pa.string() for c in STRING_COLS}}),
    )

    writers, counts, red_counts = {}, {}, {}
    t0 = _time.time()

    def close_day(day):
        writers.pop(day).close()
        print(f"  ngày {day:02d}: {counts[day]:>11,} sự kiện, {red_counts[day]:>4} red team "
              f"({_time.time() - t0:,.0f}s)", flush=True)

    max_seen = -1
    while True:
        try:
            batch = reader.read_next_batch()
        except StopIteration:
            break
        except OSError as e:  # chỉ tải phần đầu file → gzip cụt ở cuối là bình thường
            print(f"  Dừng ở cuối phần đã tải ({e}).")
            break
        times = batch.column("time")
        max_seen = max(max_seen, pc.max(times).as_py())
        if pc.min(times).as_py() >= t_end:
            break
        mask = pc.and_(pc.greater_equal(times, t_start), pc.less(times, t_end))
        batch = batch.filter(mask)
        if batch.num_rows == 0:
            continue

        batch = pa.RecordBatch.from_arrays(
            batch.columns + [redteam_labels(batch, red_times, red_keys)], schema=schema)
        days = pc.divide(batch.column("time"), SECONDS_PER_DAY)
        for day in pc.unique(days).to_pylist():
            if day not in writers:
                if day_path(day).exists() and not args.overwrite:
                    continue
                writers[day] = pq.ParquetWriter(day_path(day), schema, compression="zstd")
                counts[day] = red_counts[day] = 0
            part = batch.filter(pc.equal(days, day))
            writers[day].write_batch(part)
            counts[day] += part.num_rows
            red_counts[day] += pc.sum(part.column("is_redteam")).as_py() or 0

        min_day = pc.min(days).as_py()
        for day in [d for d in writers if d < min_day]:
            close_day(day)

    for day in list(writers):
        close_day(day)
        if max_seen < (day + 1) * SECONDS_PER_DAY:   # ngày chưa đọc hết → bỏ, tránh dữ liệu thiếu
            day_path(day).unlink()
            print(f"  ngày {day:02d} chưa đủ dữ liệu (file nguồn bị cắt) → đã xoá")
    print(f"Xong sau {_time.time() - t0:,.0f}s. Parquet ở: {LANL_EVENTS_DIR}")


if __name__ == "__main__":
    main()
