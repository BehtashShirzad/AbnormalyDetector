# Security Event Pipeline (API Gateway + RabbitMQ + Postgres + ML IP Risk)

A project that:
1) detects suspicious/attack-like HTTP behavior in an **ASP.NET API Gateway** (rate bursts, SQLi/XSS, scans, bots, etc.),
2) publishes security events to **RabbitMQ**,
3) persists them into **PostgreSQL** via a Python worker,
4) continuously trains an **IP risk model** (every 60 seconds) from stored events,
5) runs a **risk job** (every 10 seconds) to score recent IPs and publish an **integration event** (fanout) with risky IPs.

This is designed for a clean, easy-to-demo setup using `docker compose`.

---

## Architecture

**API Gateway (ASP.NET)**  
→ publishes `AnormalEvent` messages to RabbitMQ (`anormal.events` exchange)

**anomaly-worker (Python)**  
→ consumes events from RabbitMQ queue and inserts them into Postgres table `anormal_events`

**ip-risk-trainer (Python)**  
→ trains a model from `anormal_events` every 60 seconds and writes it to a shared volume (`./models/ip_risk_model.joblib`)

**ip-risk-job (Python)**  
→ loads the latest model, aggregates last N seconds of events, scores IPs, and publishes risky IPs to a **fanout** exchange (`security.integration`)

**Firewall / Consumer (future)**  
→ subscribes to the fanout exchange and blocks IPs (or logs them)

---

## Event Types

`SecurityEventType` (int):
- `1`  SQLInjection
- `2`  XSS
- `10` RateLimiting
- `11` TooManyRequestsBurst
- `12` SuspiciousScan
- `13` BotDetected
- `20` WafRuleTriggered
- `21` FirewallBlock

Severity (short):
- `0` Info
- `1` Warning
- `2` Error
- `3` Attack

---

## Database

Table: `anormal_events`

Typical columns:
- `service_name`, `ip`, `event_type`, `severity`, `description`
- `occurred_at`, plus request metadata (method, path, status_code, user_agent, request JSON)

---

## Running the Project

### Requirements
- Docker + Docker Compose (v2 recommended): `docker compose version`

### Start
From the project root:

```bash
docker compose up -d --build

```

### Check Containers

```bash
docker compose ps
docker compose logs -f rabbitmq
docker compose logs -f apigateway
docker compose logs -f anomaly-worker
docker compose logs -f ip-risk-trainer
docker compose logs -f ip-risk-job

```
API Gateway DLL name
If apigateway fails to start, check the 'RabbitMQ' and time container and update:
```bash
command: ["sh", "-c", "sleep 25 && dotnet API.Gateway.dll"]
```
