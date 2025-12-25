import json
import os
import pika
import psycopg2
from psycopg2.extras import Json
from datetime import datetime


# ======================
# CONFIG
# ======================
RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", "rabbitmq")
RABBITMQ_USER = os.getenv("RABBITMQ_USER", "guest")
RABBITMQ_PASS = os.getenv("RABBITMQ_PASS", "guest")
RABBITMQ_PORT = int(os.getenv("RABBITMQ_PORT", 5672))

QUEUE_NAME = os.getenv("QUEUE_NAME", "anormal.events.queue")
EXCHANGE = os.getenv("EXCHANGE", "anormal.events")
ROUTING_KEY = os.getenv("ROUTING_KEY", "anormal.event")

DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "postgres"),
    "port": int(os.getenv("POSTGRES_PORT", 5432)),
    "dbname": os.getenv("POSTGRES_DB", "security"),
    "user": os.getenv("POSTGRES_USER", "postgres"),
    "password": os.getenv("POSTGRES_PASSWORD", "postgres"),
}

# ======================
# ENUM MAPPINGS (اگر به شکل string بیاد)
# ======================
SEVERITY_MAP = {
    "Info": 0,
    "Warning": 1,
    "Error": 2,
    "Attack": 3,
}

EVENT_TYPE_MAP = {
    "Unknown": 0,
    "SQLInjection": 1,
    "XSS": 2,
    "RateLimiting": 10,
    "TooManyRequestsBurst": 11,
    "SuspiciousScan": 12,
    "BotDetected": 13,
    "WafRuleTriggered": 20,
    "FirewallBlock": 21,
}


# ======================
# HELPERS
# ======================
def get_any(payload: dict, *keys, default=None):
    """Read key in either PascalCase/camelCase or alternative keys."""
    for k in keys:
        if k in payload:
            return payload[k]
    return default


def parse_enum(value, mapping: dict, field_name: str) -> int:
    """Supports int/str values."""
    if value is None:
        raise ValueError(f"Missing field: {field_name}")

    if isinstance(value, int):
        return value

    if isinstance(value, str):
        v = value.strip()
        # اگر عدد بود
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            return int(v)
        # اگر اسم enum بود
        if v in mapping:
            return mapping[v]
        # گاهی lower میاد
        for k, num in mapping.items():
            if k.lower() == v.lower():
                return num

    raise ValueError(f"Invalid {field_name}: {value!r}")


def parse_datetime(value):
    """
    Supports ISO-8601 string from .NET like:
    2025-12-25T19:10:30.123Z
    2025-12-25T19:10:30
    """
    if value is None:
        raise ValueError("Missing field: OccurredAt")

    if isinstance(value, datetime):
        return value

    if isinstance(value, str):
        s = value.strip()
        # Python fromisoformat doesn't like 'Z'
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            # fallback: try without timezone
            try:
                return datetime.fromisoformat(s.split("+")[0])
            except Exception as e:
                raise ValueError(f"Invalid OccurredAt datetime: {value!r}") from e

    raise ValueError(f"Invalid OccurredAt type: {type(value)}")


def parse_request_jsonb(request_value):
    """
    DB: request JSONB
    C#: Request is string? (usually JSON string), but could be dict if producer changes.
    """
    if request_value is None:
        return None

    # اگر dict/list بود مستقیم
    if isinstance(request_value, (dict, list)):
        return request_value

    # اگر string بود سعی کن json parse کنی
    if isinstance(request_value, str):
        s = request_value.strip()
        if not s:
            return None
        try:
            return json.loads(s)
        except Exception:
            # JSON نیست → داخل jsonb با کلید raw ذخیره کن
            return {"raw": s}

    # هر چیز دیگه
    return {"raw": str(request_value)}


def normalize_payload(payload: dict) -> dict:
    """
    Normalize keys from C# record:
    ServiceName, Ip, EventType, Severity, Description, OccurredAt,
    RequestId, Method, Path, StatusCode, UserAgent, Request
    """
    service_name = get_any(payload, "ServiceName", "serviceName")
    ip = get_any(payload, "Ip", "ip")
    description = get_any(payload, "Description", "description")
    occurred_at_raw = get_any(payload, "OccurredAt", "occurredAt")

    event_type_raw = get_any(payload, "EventType", "eventType")
    severity_raw = get_any(payload, "Severity", "severity")

    # optional
    request_id = get_any(payload, "RequestId", "requestId")
    method = get_any(payload, "Method", "method")
    path = get_any(payload, "Path", "path")
    status_code = get_any(payload, "StatusCode", "statusCode")
    user_agent = get_any(payload, "UserAgent", "userAgent")

    request_raw = get_any(payload, "Request", "request")

    # validation minimum
    if not service_name:
        raise ValueError("Missing field: ServiceName")
    if not ip:
        raise ValueError("Missing field: Ip")
    if not description:
        raise ValueError("Missing field: Description")

    event_type = parse_enum(event_type_raw, EVENT_TYPE_MAP, "EventType")
    severity = parse_enum(severity_raw, SEVERITY_MAP, "Severity")
    occurred_at = parse_datetime(occurred_at_raw)
    request_jsonb = parse_request_jsonb(request_raw)

    # status_code should be int or None
    if status_code is not None and not isinstance(status_code, int):
        # اگر string عددی بود
        if isinstance(status_code, str) and status_code.strip().isdigit():
            status_code = int(status_code.strip())
        else:
            status_code = None

    return {
        "service_name": service_name,
        "ip": ip,
        "event_type": event_type,
        "severity": severity,
        "description": description,
        "occurred_at": occurred_at,
        "request_id": request_id,
        "method": method,
        "path": path,
        "status_code": status_code,
        "user_agent": user_agent,
        "request": request_jsonb,
    }


# ======================
# DATABASE
# ======================
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


def save_event(event_norm: dict):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO anormal_events
                (service_name, ip, event_type, severity, description, occurred_at,
                 request_id, method, path, status_code, user_agent, request)
                VALUES (%s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s)
                """,
                (
                    event_norm["service_name"],
                    event_norm["ip"],
                    event_norm["event_type"],
                    event_norm["severity"],
                    event_norm["description"],
                    event_norm["occurred_at"],
                    event_norm["request_id"],
                    event_norm["method"],
                    event_norm["path"],
                    event_norm["status_code"],
                    event_norm["user_agent"],
                    Json(event_norm["request"]) if event_norm["request"] is not None else None,
                )
            )
            conn.commit()
    finally:
        conn.close()


# ======================
# RABBITMQ CALLBACK
# ======================
def on_message(channel, method, properties, body):
    try:
        payload = json.loads(body.decode("utf-8"))
        event_norm = normalize_payload(payload)

        save_event(event_norm)

        channel.basic_ack(delivery_tag=method.delivery_tag)
        print(f"✔ Event saved | Type={event_norm['event_type']} Severity={event_norm['severity']} IP={event_norm['ip']}")

    except Exception as e:
        print("❌ Failed to process event:", e)
        # requeue=False چون اگر payload خراب بود، گیر نکنه
        channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)


# ======================
# WORKER
# ======================
def start_worker():
    credentials = pika.PlainCredentials(RABBITMQ_USER, RABBITMQ_PASS)

    parameters = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials,
        heartbeat=60
    )

    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()

    channel.exchange_declare(exchange=EXCHANGE, exchange_type="direct", durable=True)
    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.queue_bind(queue=QUEUE_NAME, exchange=EXCHANGE, routing_key=ROUTING_KEY)
    channel.basic_qos(prefetch_count=1)

    channel.basic_consume(queue=QUEUE_NAME, on_message_callback=on_message)

    print("🚀 AnormalEvent worker started...")
    channel.start_consuming()


if __name__ == "__main__":
    start_worker()
