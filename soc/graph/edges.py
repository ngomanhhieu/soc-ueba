"""Đồ thị xác thực LANL theo ngày: gom sự kiện của tài khoản NGƯỜI thành cạnh
(tài khoản, máy nguồn → máy đích, kiểu xác thực) – đầu vào cho tái dựng chuỗi tấn công.

~19 triệu sự kiện/ngày → ~280 nghìn cạnh/ngày. Cột is_redteam chỉ giữ để CHẤM ĐIỂM (rt),
thuật toán tái dựng không đọc nó.

Chạy:  python -m soc.graph.edges            # mọi ngày có dữ liệu → STATE_DIR/graph/
"""
import pandas as pd

from soc.config import STATE_DIR
from soc.rules.datasets import lanl_day
from features import available_days

GRAPH_DIR = STATE_DIR / "graph"
GRAPH_DIR.mkdir(parents=True, exist_ok=True)
KEYS = ["user", "src", "dst", "auth"]


def edges_path(day: int):
    return GRAPH_DIR / f"edges_d{day:02d}.parquet"


def build_day(day: int) -> pd.DataFrame:
    df = lanl_day(day)
    df = df[df["user.kind"] == "human"]
    g = df.groupby(["user.name", "source.host", "destination.host", "auth.type"], observed=True)
    e = g.agg(t0=("@timestamp", "min"), t1=("@timestamp", "max"), n=("@timestamp", "size"),
              rt=("is_redteam", "any")).reset_index()
    e.columns = KEYS + ["t0", "t1", "n", "rt"]
    for c in KEYS:
        e[c] = e[c].astype(str)
    e["day"] = day
    return e


def load_edges(day: int) -> pd.DataFrame:
    return pd.read_parquet(edges_path(day))


def main():
    for d in available_days():
        if edges_path(d).exists():
            continue
        e = build_day(d)
        e.to_parquet(edges_path(d), index=False)
        print(f"  ngày {d:02d}: {len(e):,} cạnh", flush=True)


if __name__ == "__main__":
    main()
