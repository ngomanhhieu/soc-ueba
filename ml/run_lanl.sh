#!/usr/bin/env bash
# Chạy toàn bộ pipeline Người A trên LANL. Chạy từ thư mục ml/:
#   bash run_lanl.sh                # dữ liệu thật trong data/raw/
#   SYNTH=1 bash run_lanl.sh        # chạy thử bằng dữ liệu giả
set -euo pipefail
cd "$(dirname "$0")"

START_DAY=${START_DAY:-0}
END_DAY=${END_DAY:-30}
USER_SAMPLE=${USER_SAMPLE:-0.05}
MACHINE_SAMPLE=${MACHINE_SAMPLE:-0.002}
TRAIN_END=${TRAIN_END:-}
VAL_END=${VAL_END:-}

if [[ "${SYNTH:-0}" == "1" ]]; then
  python src/make_synthetic_lanl.py
  AUTH=data/raw/synthetic/auth.txt.gz; RED=data/raw/synthetic/redteam.txt.gz
  END_DAY=14; USER_SAMPLE=1; MACHINE_SAMPLE=1; TRAIN_END=${TRAIN_END:-7}; VAL_END=${VAL_END:-10}
else
  AUTH=data/raw/auth.txt.gz; RED=data/raw/redteam.txt.gz
  python src/lanl_explore_redteam.py
fi

python src/lanl_load_auth.py --auth "$AUTH" --redteam "$RED" --start-day "$START_DAY" \
  --end-day "$END_DAY" --user-sample "$USER_SAMPLE" --machine-sample "$MACHINE_SAMPLE"
python src/features.py --window 3600 --warmup-days 2
python src/train.py ${TRAIN_END:+--train-end-day $TRAIN_END} ${VAL_END:+--val-end-day $VAL_END}
python src/evaluate.py --alert-quantile 0.995
python src/export_alerts.py --split test --min-score 0.995
echo "Xong. Kết quả: reports/metrics.md, reports/roc_pr.png, reports/alerts.json"
