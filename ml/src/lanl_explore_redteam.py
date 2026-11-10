"""A1 – Bước 1: xem red team (nhãn tấn công) nằm ở những ngày nào trong LANL.

Chạy (trong thư mục ml/):  python src/lanl_explore_redteam.py
Kết quả: in ra màn hình + reports/lanl_redteam_by_day.csv
"""
import pandas as pd

from config import LANL_REDTEAM_GZ, REDTEAM_COLS, REPORTS_DIR, SECONDS_PER_DAY


def load_redteam() -> pd.DataFrame:
    red = pd.read_csv(LANL_REDTEAM_GZ, names=REDTEAM_COLS)
    red["day"] = red["time"] // SECONDS_PER_DAY
    return red


def main():
    red = load_redteam()
    print("Tổng sự kiện red team:", len(red))
    print("Số user bị red team dùng:", red["user"].nunique())
    print("Số máy nguồn:", red["src_comp"].nunique(), "| số máy đích:", red["dst_comp"].nunique())
    print("time min/max:", red["time"].min(), red["time"].max(),
          f"(ngày {red['day'].min()} → {red['day'].max()})")

    by_day = red.groupby("day").agg(events=("time", "size"), users=("user", "nunique"),
                                    dst_comps=("dst_comp", "nunique"))
    print(by_day.to_string())
    out = REPORTS_DIR / "lanl_redteam_by_day.csv"
    by_day.to_csv(out)
    print("Đã lưu:", out)


if __name__ == "__main__":
    main()
