import pandas as pd

red = pd.read_csv("data/raw/redteam.txt.gz",
                  names=["time", "user", "src_comp", "dst_comp"])
red["day"] = red["time"] // 86400

print("Tổng sự kiện red team:", len(red))
print("Số user bị red team dùng:", red["user"].nunique())
print("time min/max:", red["time"].min(), red["time"].max())
print(red.groupby("day").size())
print(red.groupby("day")["user"].nunique())
