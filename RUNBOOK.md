# SOC Platform — Runbook

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.12+ | Tested 3.13.14 |
| Node.js | 20+ | Tested v24.14.0 |
| npm | 10+ | Tested 11.9.0 |
| Docker Desktop | Latest | For infrastructure services |
| Git | Latest | Optional |

---

## 1. Infrastructure (Docker)

Start all data-layer services (PostgreSQL, Redis, Elasticsearch, Kafka, Zookeeper, Logstash, Prometheus, Grafana):

```powershell
docker-compose -f infrastructure/docker/docker-compose.yml up -d
```

Wait for health checks to pass (~30s). Verify:

```powershell
# PostgreSQL on host port 5434
docker exec soc-postgres pg_isready -U socuser

# Redis on host port 6379
docker exec soc-redis redis-cli -a redispass ping

# Elasticsearch on host port 9200
curl -s http://localhost:9200/_cluster/health | python -c "import sys,json; print(json.load(sys.stdin)['status'])"

# Kafka on host port 9092
docker exec soc-kafka kafka-topics --list --bootstrap-server localhost:9092
```

Expected output: `ready`, `PONG`, `green` (or `yellow`), and a topic list.

---

## 2. Environment Setup

Copy `.env.example` to `.env` (already done if cloned). Defaults work for local dev.

Key settings in `backend/.env`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `postgresql+asyncpg://socuser:socpass@localhost:5434/socplatform` | Async DB connection |
| `REDIS_URL` | `redis://:redispass@localhost:6379/0` | Cache + rate limiting |
| `ELASTICSEARCH_HOSTS` | `["http://localhost:9200"]` | Search + logging |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Event bus |
| `JWT_SECRET_KEY` | `your-super-secret-key-...` | Change in production |

> **Windows note**: If you have a local PostgreSQL on port 5432, Docker Postgres uses port 5434 to avoid conflict. The `.env` defaults to port **5434** — keep it.

---

## 3. Python Setup

```powershell
# Create virtual environment (one time)
cd backend
python -m venv venv
.\venv\Scripts\Activate

# Install dependencies
pip install -r requirements.txt

# Pin bcrypt (passlib 1.7.4 is incompatible with bcrypt 4.x+)
pip install bcrypt==3.2.2
```

> **Why bcrypt 3.2.2?** passlib 1.7.4 (latest) does not support bcrypt >= 4.0. Pinning to 3.2.2 is required.

---

## 4. Database Setup

```powershell
cd backend

# Run migrations
alembic upgrade head

# Seed default admin user (org + admin + analyst accounts)
python ..\scripts\seed.py
```

Credentials after seeding:

| Email | Password | Role |
|-------|----------|------|
| `admin@socplatform.io` | `Admin123!` | admin |
| `analyst@socplatform.io` | `Analyst123!` | analyst |

---

## 5. Start Backend Services

### Option A: API Gateway (recommended — single entrypoint)

Start the API Gateway which proxies to all 15 microservices:

```powershell
cd backend
python -m uvicorn core.main:app --reload --host 0.0.0.0 --port 8000
```

Then start individual services in separate terminals:

**Terminal 1 — Core Services:**
```powershell
cd backend
python -m uvicorn services.auth_service.main:app --reload --host 0.0.0.0 --port 8010
python -m uvicorn services.asset_discovery.main:app --reload --host 0.0.0.0 --port 8002
python -m uvicorn services.vuln_scanner.main:app --reload --host 0.0.0.0 --port 8003
python -m uvicorn services.threat_intel.main:app --reload --host 0.0.0.0 --port 8004
```

**Terminal 2 — Security Services:**
```powershell
cd backend
python -m uvicorn services.incident_response.main:app --reload --host 0.0.0.0 --port 8005
python -m uvicorn services.ai_copilot.main:app --reload --host 0.0.0.0 --port 8006
python -m uvicorn services.edr_service.main:app --reload --host 0.0.0.0 --port 8007
python -m uvicorn services.ndr_service.main:app --reload --host 0.0.0.0 --port 8008
```

**Terminal 3 — Analytics + Cloud:**
```powershell
cd backend
python -m uvicorn services.mitre_mapper.main:app --reload --host 0.0.0.0 --port 8009
python -m uvicorn services.cloud_security.main:app --reload --host 0.0.0.0 --port 8011
python -m uvicorn services.hunting_service.main:app --reload --host 0.0.0.0 --port 8012
```

**Terminal 4 — Extended Services:**
```powershell
cd backend
python -m uvicorn services.identity_security.main:app --reload --host 0.0.0.0 --port 8013
python -m uvicorn services.email_security.main:app --reload --host 0.0.0.0 --port 8014
python -m uvicorn services.autonomous_soc.main:app --reload --host 0.0.0.0 --port 8015
python -m uvicorn services.predictive_analytics.main:app --reload --host 0.0.0.0 --port 8016
```

### Option B: Each service directly (no API Gateway)

Each service is self-contained. Run any service directly on its port:

```powershell
cd backend
python services/auth_service/main.py
```

### Port Map

| Service | Port | Health Endpoint |
|---------|------|-----------------|
| **API Gateway** | 8000 | `/health` |
| Asset Discovery | 8002 | `/health` |
| Vulnerability Scanner | 8003 | `/health` |
| Threat Intelligence | 8004 | `/health` |
| Incident Response | 8005 | `/health` |
| AI Copilot | 8006 | `/health` |
| EDR | 8007 | `/health` |
| NDR | 8008 | `/health` |
| MITRE Mapper | 8009 | `/health` |
| **Auth Service** | 8010 | `/health` |
| Cloud Security | 8011 | `/health` |
| Hunting Service | 8012 | `/health` |
| Identity Security | 8013 | `/health` |
| Email Security | 8014 | `/health` |
| Autonomous SOC | 8015 | `/health` |
| Predictive Analytics | 8016 | `/health` |

---

## 6. Frontend

```powershell
cd frontend

# Install dependencies (one time)
npm install

# Development server (hot reload)
npm run dev

# Production build (output to dist/)
npm run build

# Preview production build
npm run preview
```

Frontend runs on `http://localhost:5173` by default (Vite). The API Gateway at `http://localhost:8000` is proxied from the frontend via Vite config.

---

## 7. End-to-End Verification

```powershell
# 1. Login
curl -s -X POST http://localhost:8000/api/v1/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"admin@socplatform.io\",\"password\":\"Admin123!\"}"

# Save the access_token, then:
# 2. Get current user
curl -s http://localhost:8000/api/v1/auth/me -H "Authorization: Bearer <token>"

# 3. List assets
curl -s http://localhost:8000/api/v1/assets -H "Authorization: Bearer <token>"

# 4. List incidents
curl -s http://localhost:8000/api/v1/incidents -H "Authorization: Bearer <token>"

# 5. Check API Gateway routes
curl -s http://localhost:8000/routes

# 6. API Gateway health
curl -s http://localhost:8000/health
```

---

## 8. Running Tests

```powershell
cd backend

# All tests
python -m pytest ..\tests

# Auth tests only
python -m pytest ..\tests\test_services\test_auth.py -v --no-header

# With coverage
python -m pytest --cov=. --cov-report=term-missing ..\tests
```

---

## 9. Grafana Monitoring

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | `http://localhost:3000` | admin / admin |
| Prometheus | `http://localhost:9090` | — |

Dashboards are auto-provisioned:
- **SOC Platform Overview** — service health, API rates, error rates, latency, vulnerabilities, incidents, threat intel, Kafka lag, DB connections, Redis/ES stats (19 panels)
- **Service Detail** — per-service drill-down with request rate, latency (p50/p95/p99), CPU/memory, recent errors (7 panels)

---

## 10. Common Issues & Fixes

### bcrypt error on import
```
ModuleNotFoundError: No module named 'bcrypt.__about__'
```
**Fix:** `pip install bcrypt==3.2.2`

### Redis authentication error
```
AUTH <password> called without connecting
```
**Fix:** The `redis-py >= 8.0.0` uses RESP3 protocol by default which sends HELLO before AUTH. Downgrade: `pip install redis==6.4.0`

### Elasticsearch connection error
```
NotMasterError: ... version=9 ...
```
**Fix:** The `elasticsearch >= 9.0.0` sends incompatible headers. Pin: `pip install elasticsearch[async]==8.17.1`

### Port 8001 in use
```
Address already in use: 8001
```
Port 8001 may have a ghost process. Use `netstat -ano | findstr :8001` to find PID, then `taskkill /PID <pid> /F`. Auth service now uses port **8010** to avoid this.

### Database connection refused
```
Cannot connect to localhost:5434
```
Ensure Docker is running and Postgres container is up: `docker start soc-postgres`

---

## 11. Service Structure

```
backend/
  core/                     # Shared framework
    main.py                 # API Gateway (port 8000)
    config.py               # Settings from .env
    database.py             # SQLAlchemy async engine
    security.py             # JWT, bcrypt, MFA
    redis.py                # Redis client
    elastic.py              # Elasticsearch client
    kafka.py                # Kafka producer/consumer
    dependencies.py         # FastAPI deps (auth, permissions)
    midware.py              # Rate limiting, security headers
    logging.py              # Structured logging
  services/
    auth_service/            # Port 8010 — JWT, MFA, RBAC
    asset_discovery/         # Port 8002
    vuln_scanner/            # Port 8003
    threat_intel/            # Port 8004
    incident_response/       # Port 8005
    ai_copilot/              # Port 8006 — LLM integration
    edr_service/             # Port 8007
    ndr_service/             # Port 8008
    mitre_mapper/            # Port 8009
    cloud_security/          # Port 8011
    hunting_service/         # Port 8012
    identity_security/       # Port 8013
    email_security/          # Port 8014
    autonomous_soc/          # Port 8015
    predictive_analytics/    # Port 8016
tests/
  conftest.py
  test_core/
  test_services/
frontend/                    # React + TailwindCSS + ShadCN
infrastructure/
  docker/                    # docker-compose + Grafana configs
  kubernetes/                # K8s manifests + HPA
  prometheus/                # Prometheus scrape config
docs/
  architecture.md
  api.md
```

---

## 12. Kubernetes Deployment

```powershell
# Apply namespace
kubectl apply -f infrastructure/kubernetes/namespaces/soc-namespaces.yaml

# Apply ConfigMap
kubectl apply -f infrastructure/kubernetes/configmaps/soc-config.yaml

# Deploy all services
kubectl apply -f infrastructure/kubernetes/deployments/
kubectl apply -f infrastructure/kubernetes/hpa/

# Deploy ingress
kubectl apply -f infrastructure/kubernetes/ingress/soc-ingress.yaml
```

---

## 13. Docker Build

```powershell
# Build all service images
docker-compose -f infrastructure/docker/docker-compose.yml build

# Or build individual services
docker build -t socplatform/auth-service:latest -f backend/services/auth_service/Dockerfile backend/
docker build -t socplatform/asset-discovery:latest -f backend/services/asset_discovery/Dockerfile backend/
# ... repeat for each service
```

---

## 14. API Reference

Full API docs available at `docs/api.md`. Each service also exposes auto-generated OpenAPI docs:

| Service | Swagger UI | ReDoc |
|---------|-----------|-------|
| Auth | `http://localhost:8010/docs` | `http://localhost:8010/redoc` |
| Any service | `http://localhost:<port>/docs` | `http://localhost:<port>/redoc` |
| API Gateway | `http://localhost:8000/docs` | `http://localhost:8000/redoc` |
