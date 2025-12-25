import os
import json
import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pandas as pd
from sqlalchemy import create_engine, text
from joblib import dump

from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, IsolationForest


# -----------------------------
# Config (edit these)
# -----------------------------
# این mapping رو مطابق enum خودت تنظیم کن
# مثال:
# 1 = SQL_INJECTION
# 2 = RATE_LIMIT
# 3 = PATH_TRAVERSAL
# 4 = BAD_TOKEN
ATTACK_EVENT_TYPES = {1, 2}              # SQLi, XSS
SUSPICIOUS_EVENT_TYPES = {10, 11, 12, 13, 20, 21}

DEFAULT_LABEL_SEVERITY_THRESHOLD = 3  # severity >= 3 => حمله/ریسک بالا (قابل تغییر)


SQL_FETCH = """
SELECT
    ip::text as ip,
    event_type,
    severity,
    description,
    occurred_at,
    method,
    path,
    status_code,
    user_agent
FROM anormal_events
WHERE occurred_at >= :t0 AND occurred_at < :t1
"""


@dataclass
class TrainConfig:
    db_url: str
    window_sec: int
    days: int
    mode: str          # supervised | unsupervised
    model: str         # lr | rf | iso
    label_sev: int
    out_path: str


def parse_args() -> TrainConfig:
    p = argparse.ArgumentParser(description="Train IP Risk Model from anormal_events")
    p.add_argument("--db-url", default=os.getenv("DB_URL", ""), help="Postgres SQLAlchemy URL")
    p.add_argument("--window-sec", type=int, default=int(os.getenv("WINDOW_SEC", "60")), help="Aggregation window")
    p.add_argument("--days", type=int, default=int(os.getenv("DAYS", "14")), help="How many days back to train")
    p.add_argument("--mode", choices=["supervised", "unsupervised"], default=os.getenv("MODE", "supervised"))
    p.add_argument("--model", choices=["lr", "rf", "iso"], default=os.getenv("MODEL", "rf"))
    p.add_argument("--label-sev", type=int, default=int(os.getenv("LABEL_SEV", str(DEFAULT_LABEL_SEVERITY_THRESHOLD))))
    p.add_argument("--out", default=os.getenv("MODEL_OUT", "./ip_risk_model.joblib"))
    a = p.parse_args()

    if not a.db_url:
        raise SystemExit("ERROR: --db-url is required (or set POSTGRES_HOST env var).")

    return TrainConfig(
        db_url=a.db_url,
        window_sec=a.window_sec,
        days=a.days,
        mode=a.mode,
        model=a.model,
        label_sev=a.label_sev,
        out_path=a.out,
    )


def load_events(engine, t0: datetime, t1: datetime) -> pd.DataFrame:
    df = pd.read_sql(text(SQL_FETCH), engine, params={"t0": t0, "t1": t1})
    if df.empty:
        return df

    df["occurred_at"] = pd.to_datetime(df["occurred_at"])
    # اگر ip رو inet نگه داشتی، اینجا به string تبدیل شده.
    df["event_type"] = df["event_type"].astype(int, errors="ignore")
    df["severity"] = df["severity"].astype(int, errors="ignore")
    return df


def bin_and_aggregate(df: pd.DataFrame, window_sec: int) -> pd.DataFrame:
    """
    Aggregate per (ip, time_bin) to build ML-friendly features.
    """
    df = df.copy()
    # تایم‌بین
    df["time_bin"] = df["occurred_at"].dt.floor(f"{window_sec}s")

    # flags per row
    df["is_attack_type"] = df["event_type"].isin(ATTACK_EVENT_TYPES).astype(int)
    df["is_suspicious_type"] = df["event_type"].isin(SUSPICIOUS_EVENT_TYPES).astype(int)
    df["is_403"] = (df["status_code"] == 403).fillna(False).astype(int)
    df["is_4xx"] = df["status_code"].between(400, 499).fillna(False).astype(int)

    # برای robust بودن در nullها
    df["path"] = df["path"].fillna("")
    df["method"] = df["method"].fillna("")
    df["user_agent"] = df["user_agent"].fillna("")

    agg = df.groupby(["ip", "time_bin"], as_index=False).agg(
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

    # فیچرهای مشتق‌شده
    agg["events_rate"] = agg["events_count"] / float(window_sec)
    agg["ratio_attack_type"] = agg["attack_type_count"] / agg["events_count"].clip(lower=1)
    agg["ratio_suspicious_type"] = agg["suspicious_type_count"] / agg["events_count"].clip(lower=1)
    agg["ratio_403"] = agg["cnt_403"] / agg["events_count"].clip(lower=1)
    agg["ratio_4xx"] = agg["cnt_4xx"] / agg["events_count"].clip(lower=1)

    return agg


def make_labels(agg: pd.DataFrame, label_sev_threshold: int) -> pd.Series:
    """
    Supervised label heuristic:
    - اگر event_type از ATTACK_EVENT_TYPES باشد => 1
    - یا max_severity >= threshold => 1
    این را بعداً می‌توانی دقیق‌تر کنی.
    """
    y = ((agg["attack_type_count"] > 0) | (agg["max_severity"] >= label_sev_threshold)).astype(int)
    return y


def build_model(model_name: str, mode: str):
    if mode == "unsupervised":
        # IsolationForest: anomaly detection (بدون لیبل)
        return Pipeline([
            ("scaler", StandardScaler()),
            ("iso", IsolationForest(
                n_estimators=400,
                contamination=0.01,
                random_state=42
            ))
        ])

    # supervised
    if model_name == "lr":
        return Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                n_jobs=None
            ))
        ])

    # rf (پیشنهاد خوب برای شروع)
    return RandomForestClassifier(
        n_estimators=600,
        random_state=42,
        class_weight="balanced_subsample",
        n_jobs=-1,
        min_samples_leaf=2
    )


def train_supervised(agg: pd.DataFrame, y: pd.Series, model_name: str):
    feature_cols = [
        "events_count", "events_rate",
        "attack_type_count", "suspicious_type_count",
        "max_severity", "mean_severity",
        "cnt_403", "cnt_4xx",
        "uniq_path", "uniq_method", "uniq_ua",
        "ratio_attack_type", "ratio_suspicious_type",
        "ratio_403", "ratio_4xx",
    ]

    X = agg[feature_cols].copy()

    # اگر همه لیبل‌ها یکسان شدند، supervised معنی ندارد
    if y.nunique() < 2:
        raise RuntimeError("Only one label class found. Use unsupervised or adjust label rules.")

    n = len(y)
    n_classes = y.nunique()
    min_class_count = y.value_counts().min()

    model = build_model(model_name=model_name, mode="supervised")

    # ✅ اگر دیتا کم است: بدون split روی کل دیتا train کن (برای ارائه عالیه)
    # شرط‌ها: تعداد نمونه کم یا یک کلاس خیلی کم نمونه دارد
    if n < 20 or min_class_count < 2:
        print(f"[train] small dataset (n={n}, min_class_count={min_class_count}). Training on ALL data (no validation).")
        model.fit(X, y)
        return model, feature_cols, {"val_auc": None, "note": "trained_on_all_no_validation_small_data"}

    # ✅ در غیر اینصورت split استاندارد
    test_size = 0.2
    # مطمئن شو test حداقل به تعداد کلاس‌ها نمونه داشته باشد
    if int(n * test_size) < n_classes:
        test_size = max(test_size, n_classes / n)

    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )

    model.fit(X_train, y_train)

    proba = model.predict_proba(X_val)[:, 1]
    preds = (proba >= 0.5).astype(int)

    auc = roc_auc_score(y_val, proba)
    print(f"[train] val AUC = {auc:.4f}")
    print("[train] classification report (threshold=0.5):")
    print(classification_report(y_val, preds, digits=4))

    return model, feature_cols, {"val_auc": float(auc)}


def train_unsupervised(agg: pd.DataFrame):
    feature_cols = [
        "events_count", "events_rate",
        "attack_type_count", "suspicious_type_count",
        "max_severity", "mean_severity",
        "cnt_403", "cnt_4xx",
        "uniq_path", "uniq_method", "uniq_ua",
        "ratio_attack_type", "ratio_suspicious_type",
        "ratio_403", "ratio_4xx",
    ]
    X = agg[feature_cols].copy()
    model = build_model(model_name="iso", mode="unsupervised")
    model.fit(X)
    return model, feature_cols, {}


def main():
    cfg = parse_args()

    engine = create_engine(cfg.db_url, pool_pre_ping=True)

    # بازه آموزش
    t1 = datetime.now(timezone.utc)  # چون occurred_at TIMESTAMP بدون tz هست
    t0 = t1 - timedelta(days=cfg.days)

    print(f"[load] from {t0} to {t1}")
    df = load_events(engine, t0=t0, t1=t1)
    if df.empty:
        raise SystemExit("No rows found in the given time range.")

    agg = bin_and_aggregate(df, window_sec=cfg.window_sec)
    if agg.empty:
        raise SystemExit("Aggregation produced no rows.")

    if cfg.mode == "supervised":
        y = make_labels(agg, label_sev_threshold=cfg.label_sev)
        print(f"[labels] positive={int(y.sum())} / total={len(y)}")
        model, feature_cols, metrics = train_supervised(agg, y, model_name=cfg.model)
    else:
        model, feature_cols, metrics = train_unsupervised(agg)

    artifact = {
        "mode": cfg.mode,
        "model": model,
        "feature_cols": feature_cols,
        "window_sec": cfg.window_sec,
        "trained_at": datetime.utcnow().isoformat() + "Z",
        "label_severity_threshold": cfg.label_sev,
        "attack_event_types": sorted(list(ATTACK_EVENT_TYPES)),
        "suspicious_event_types": sorted(list(SUSPICIOUS_EVENT_TYPES)),
        "metrics": metrics,
    }

    dump(artifact, cfg.out_path)
    print(f"[save] model artifact saved to: {cfg.out_path}")
    print("[done]")


if __name__ == "__main__":
    main()
