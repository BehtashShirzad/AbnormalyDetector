#!/bin/sh
set -e

echo "Trainer loop started (every 60s)..."

while true; do
  echo "[trainer] training at $(date -u)"
  python /app/train_risk_model.py \
    --db-url "$DB_URL" \
    --out "${MODEL_OUT:-/models/ip_risk_model.joblib}"

  echo "[trainer] done. sleeping 60s..."
  sleep 60
done
