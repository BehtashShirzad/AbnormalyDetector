import json
import pika
import psycopg2
from psycopg2.extras import Json

# ======================
# CONFIG
# ======================
RABBITMQ_HOST = "127.0.0.1"
RABBITMQ_PORT = 5672
RABBITMQ_USER = "guest"
RABBITMQ_PASS = "guest"
QUEUE_NAME = "anormal.events.queue"
ROUTING_KEY  = "anormal.event"
EXCHANGE ="anormal.events"
DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 5432,
    "dbname": "security",
    "user": "postgres",
    "password": "postgres"
}

# ======================
# DATABASE
# ======================
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)

def save_event(event: dict):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO anormal_events
                (service_name, description, severity, occurred_at, request)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    event.get("ServiceName"),
                    event.get("Description"),
                    event.get("Severity"),
                    event.get("OccurredAt"),
                    Json(event.get("request"))
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

        # validation حداقلی
        required_fields = ["ServiceName", "Description", "Severity", "OccurredAt"]
        for field in required_fields:
            if field not in payload:
                raise ValueError(f"Missing field: {field}")

        save_event(payload)

        channel.basic_ack(delivery_tag=method.delivery_tag)
        print(f"✔ Event saved | Severity={payload['severity']}")

    except Exception as e:
        print("❌ Failed to process event:", e)
        channel.basic_nack(delivery_tag=method.delivery_tag, requeue=False)

# ======================
# WORKER
# ======================
def start_worker():
    credentials = pika.PlainCredentials(
        RABBITMQ_USER,
        RABBITMQ_PASS
    )

    parameters = pika.ConnectionParameters(
        host=RABBITMQ_HOST,
        port=RABBITMQ_PORT,
        credentials=credentials,
        heartbeat=60
    )

    connection = pika.BlockingConnection(parameters)
    channel = connection.channel()

    channel.queue_declare(queue=QUEUE_NAME, durable=True)
    channel.queue_bind(queue=QUEUE_NAME,exchange=EXCHANGE,routing_key=ROUTING_KEY)
    channel.basic_qos(prefetch_count=1)

    channel.basic_consume(
        queue=QUEUE_NAME,
        on_message_callback=on_message
    )

    print("🚀 AnormalEvent worker started...")
    channel.start_consuming()

if __name__ == "__main__":
    start_worker()
