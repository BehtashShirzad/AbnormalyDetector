FROM python:3.11.2-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# کل فایل‌ها (Worker.py + train_ip_risk_model.py + train_loop.sh)
COPY . .

# پیش‌فرض worker (compose می‌تونه override کنه)
CMD ["python", "Worker.py"]
