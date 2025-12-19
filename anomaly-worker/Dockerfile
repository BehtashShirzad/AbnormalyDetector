# Base image
FROM python:3.11.2-slim

# جلوگیری از cache بی‌مورد
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# تنظیم working directory
WORKDIR /app

# نصب وابستگی‌های سیستمی لازم برای psycopg2
# RUN apt-get update && apt-get install -y \
#     gcc \
#     libpq-dev \
#     && rm -rf /var/lib/apt/lists/*

# کپی requirements
COPY requirements.txt .

# نصب پکیج‌های پایتون
RUN pip install --no-cache-dir -r requirements.txt

# کپی سورس
COPY Worker.py .

# اجرای worker
CMD ["python", "Worker.py"]
