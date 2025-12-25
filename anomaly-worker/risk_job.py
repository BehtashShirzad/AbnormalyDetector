import os
import json
import time
from datetime import datetime, timedelta

import pandas as pd
from sqlalchemy import create_engine, text
from joblib import load

import pika


# ======================
# ENV CONFIG
# ======================
DB_URL = os.getenv("DB_URL", "")   
MODEL_PATH = os.getenv("MODEL_PATH", "/models/ip_risk_model.joblib")

# inference window (seconds)
INFER_WINDOW_SEC = int(os.getenv("INFER_WINDOW_SEC", "60"))

# job interval (seconds)
JOB_EVERY_SEC = int(os.getenv("JOB_EVERY_SEC", "10"))

# publish thresholds
HIGH_TH = float(os.getenv("HIGH_TH", "0.90"))
MED_TH = float(os.getenv("MED_TH", "0.80"))

# cooldown: don't re-publish same IP too frequently
COOLDOWN_SEC = int(os.getenv("COOLDOWN_SEC", "60"))

# TTLs for firewall/blocking usage
HIGH_TTL_SEC = int(os.getenv("HIGH_TTL_SEC", "1800"))   # 30 min
MED_TTL_SEC = int(os.getenv("MED_TTL_SEC", "600"))      # 10 min

# RabbitMQ
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", "5672"))
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "guest")

INTEGRATION_EXCHANGE = os.getenv("INTEGRATION_EXCHANGE", "security.integration")
INTEGRATION_EXCHANGE_TYPE = os.getenv("INTEGRATION_EXCHANGE_TYPE", "fanout")
INTEGRATION_ROUTING_KEY = os.getenv("INTEGRATION_ROUTING_KEY", "")

SERVICE_NAME = os.getenv("SERVICE_NAME", "risk-job")

# ======================
# SQL
# ======================
SQL_FETCH_WINDOW = """
SELECT
  ip::text as ip,
  event_type,
  severity,
  occurred_at,
  method,
  path,
  status_code,
  user_agent
FROM anormal_events
WHERE occurred_at >= :t0 AND occurred_at < :t1
"""


# ======================
# Utilities
# ======================
def utcnow():
    return datetime.utcnow()

def iso_z(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat() + "Z"

def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default

def load_model_artifact_if_changed(state: dict):
    """
    state: { "mtime": float|None, "artifact": dict|None }
    """
    if not os.path.exists(MODEL_PATH):
        state["artifact"] = None
        state["mtime"] = None
        return

    mtime = os.path.getmtime(MODEL_PATH)
    if state.get("mtime") == mtime and state.get("artifact") is not None:
        return

    artifact = load(MODEL_PATH)
    state["artifact"] = artifact
    state["mtime"] = mtime
    print(f"[job] loaded model artifact: mode={artifact.get('mode')} window={artifact.get('window_sec')} mtime={mtime}")

def build_features_from_events(df: pd.DataFrame, window_sec: int, attack_types: set, suspicious_types: set) -> pd.DataFrame:
    """
    Build the same features as training, but aggregated per IP over the last window.
    Output: one row per IP.
    """
    df = df.copy()
    df["event_type"] = pd.to_numeric(df["event_type"], errors="coerce").fillna(0).astype(int)
    df["severity"] = pd.to_numeric(df["severity"], errors="coerce").fillna(0).astype(int)
    df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce")

    df["is_attack_type"] = df["event_type"].isin(attack_types).astype(int)
    df["is_suspicious_type"] = df["event_type"].isin(suspicious_types).astype(int)
    df["is_403"] = (df["status_code"] == 403).fillna(False).astype(int)
    df["is_4xx"] = df["status_code"].between(400, 499).fillna(False).astype(int)

    df["path"] = df["path"].fillna("")
    df["method"] = df["method"].fillna("")
    df["user_agent"] = df["user_agent"].fillna("")

    agg = df.groupby(["ip"], as_index=False).agg(
        events_count=("event_type", "size"),
        attack_type_count=("is_attack_type", "sum"),
        suspicious_type_count=("is_suspicious_type", "sum"),
        max_severity=("severity", "max"),
        mean_severity=("severity", "mean"),
        cnt_403=("is_403", "sum"),
        cnt_4xx=("is_4xx", "sum"),
        uniq_path=("path", "nunique"),
        uniq_method=("method", "nunique"),
        uniq_ua=("user_agent", "nunique"),
    )

    agg["events_rate"] = agg["events_count"] / float(window_sec)
    denom = agg["events_count"].clip(lower=1)
    agg["ratio_attack_type"] = agg["attack_type_count"] / denom
    agg["ratio_suspicious_type"] = agg["suspicious_type_count"] / denom
    agg["ratio_403"] = agg["cnt_403"] / denom
    agg["ratio_4xx"] = agg["cnt_4xx"] / denom

    return agg

def score_rows(artifact: dict, feats: pd.DataFrame) -> pd.DataFrame:
    """
    Adds risk_score column.
    Supports supervised (predict_proba) and unsupervised (IsolationForest).
    """
    mode = artifact.get("mode", "supervised")
    model = artifact["model"]
    feature_cols = artifact["feature_cols"]

    # ensure all feature columns exist
    X = feats.copy()
    for c in feature_cols:
        if c not in X.columns:
            X[c] = 0

    X = X[feature_cols].copy()

    if mode == "unsupervised":
        # higher = more anomalous
        normality = model.decision_function(X)
        # convert to 0..1-ish risk score (avoid div by 0)
        mx, mn = float(normality.max()), float(normality.min())
        denom = (mx - mn) if (mx - mn) != 0 else 1.0
        risk = (mx - normality) / denom
        feats["risk_score"] = risk.astype(float)
    else:
        proba = model.predict_proba(X)[:, 1]
        feats["risk_score"] = proba.astype(float)

    return feats

def infer_reasons(row: pd.Series) -> list:
    reasons = []
    if safe_int(row.get("attack_type_count", 0)) > 0:
        reasons.append("attack_event")
    if safe_int(row.get("suspicious_type_count", 0)) > 0:
        reasons.append("suspicious_events")
    if float(row.get("events_rate", 0.0)) >= 2.0:
        reasons.append("high_rate")
    if float(row.get("ratio_403", 0.0)) >= 0.3:
        reasons.append("403_spike")
    if safe_int(row.get("uniq_path", 0)) >= 20:
        reasons.append("scan_like")
    if safe_int(row.get("max_severity", 0)) >= 3:
        reasons.append("high_severity")
    return reasons[:3]

def rabbit_channel():
    creds = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)
    params = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=creds,
        heartbeat=60,
    )
    conn = pika.BlockingConnection(params)
    ch = conn.channel()
    ch.exchange_declare(exchange=INTEGRATION_EXCHANGE, exchange_type=INTEGRATION_EXCHANGE_TYPE, durable=True)
    ch.queue_declare(queue="integrationQueue",durable=True)
    ch.queue_bind(exchange=INTEGRATION_EXCHANGE,queue="integrationQueue",routing_key="")
    return conn, ch

def publish_integration_event(ch, payload: dict):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
  
    ch.basic_publish(
    exchange=INTEGRATION_EXCHANGE,
    routing_key=INTEGRATION_ROUTING_KEY, 
    body=body,
       properties=pika.BasicProperties(
            content_type="application/json",
            delivery_mode=2,  # persistent
        ),

    )

def main_loop():
    if not DB_URL:
        raise SystemExit("ERROR: DB_URL is not set.")

    engine = create_engine(DB_URL, pool_pre_ping=True)

    state = {"mtime": None, "artifact": None}
    last_sent = {}  # ip -> epoch seconds

    conn, ch = rabbit_channel()
    print("[job] risk job started.")

    try:
        while True:
            now = utcnow()
            t1 = now
            t0 = now - timedelta(seconds=INFER_WINDOW_SEC)

            load_model_artifact_if_changed(state)
            artifact = state.get("artifact")
            if artifact is None:
                print("[job] model artifact not found yet. waiting...")
                time.sleep(JOB_EVERY_SEC)
                continue

            # model meta
            model_version = os.getenv("MODEL_VERSION", f"{artifact.get('mode','m')}_v1")

            # fetch events
            df = pd.read_sql(text(SQL_FETCH_WINDOW), engine, params={"t0": t0, "t1": t1})
            if df.empty:
                time.sleep(JOB_EVERY_SEC)
                continue

            # training used these sets; artifact has them too (best)
            attack_types = set(artifact.get("attack_event_types", []))
            suspicious_types = set(artifact.get("suspicious_event_types", []))
            if not attack_types:
                attack_types = {1, 2}  # fallback: SQLi, XSS
            if not suspicious_types:
                suspicious_types = {10, 11, 12, 13, 20, 21}

            feats = build_features_from_events(df, INFER_WINDOW_SEC, attack_types, suspicious_types)
            feats = score_rows(artifact, feats)

            # pick risky IPs
            feats_sorted = feats.sort_values("risk_score", ascending=False)
            high = feats_sorted[feats_sorted["risk_score"] >= HIGH_TH]
            med = feats_sorted[(feats_sorted["risk_score"] >= MED_TH) & (feats_sorted["risk_score"] < HIGH_TH)]

            items = []
            now_epoch = int(time.time())

            def add_group(sub: pd.DataFrame, level: str, ttl: int):
                nonlocal items
                for _, r in sub.iterrows():
                    ip = r["ip"]
                    if ip in last_sent and (now_epoch - last_sent[ip] < COOLDOWN_SEC):
                        continue
                    last_sent[ip] = now_epoch
                    items.append({
                        "ip": ip,
                        "risk_score": float(r["risk_score"]),
                        "risk_level": level,
                        "ttl_sec": ttl,
                        "reasons": infer_reasons(r),
                        "window_sec": INFER_WINDOW_SEC,
                    })

            add_group(high, "high", HIGH_TTL_SEC)
            add_group(med, "medium", MED_TTL_SEC)

            if items:
                payload = {
                    "event_type": "ip_risk_detected",
                    "producer": SERVICE_NAME,
                    "ts": iso_z(now),
                    "model_path": MODEL_PATH,
                    "model_version": model_version,
                    "window_sec": INFER_WINDOW_SEC,
                    "items": items,
                }
                publish_integration_event(ch, payload)
                print(f"[job] published {len(items)} risky IP(s). top={items[0]['ip']} score={items[0]['risk_score']:.3f}")

            time.sleep(JOB_EVERY_SEC)

    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main_loop()
