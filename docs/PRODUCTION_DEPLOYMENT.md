# SOC Platform — Production Deployment Guide

## Prerequisites

| Tool | Version |
|------|---------|
| Docker + Docker Compose | Latest |
| kubectl | 1.28+ |
| Python | 3.12+ |
| Node.js | 20+ |
| Git | Latest |

---

## Step 1 — Clone & Configure Environment

```bash
git clone <repo-url>
cd Talent

# Copy and configure environment variables
cp .env.example .env
```

Edit `.env` and set **all production values**:

```env
# Change these — never use defaults in production
JWT_SECRET_KEY=<generate-with: openssl rand -hex 64>
ELASTICSEARCH_PASSWORD=<strong-password>

# Database
DATABASE_URL=postgresql+asyncpg://socuser:<db-pass>@postgres:5432/socplatform
SYNC_DATABASE_URL=postgresql://socuser:<db-pass>@postgres:5432/socplatform

# Redis (with password)
REDIS_URL=redis://:<redis-pass>@redis:6379/0

# LLM (at least one required)
OPENAI_API_KEY=<your-key>
GOOGLE_GEMINI_API_KEY=<your-key>
LLM_PROVIDER=gemini

# Cloud credentials (optional)
AWS_ACCESS_KEY_ID=<key>
AWS_SECRET_ACCESS_KEY=<secret>

# Email alerts
SMTP_HOST=<smtp-host>
SMTP_USER=<smtp-user>
SMTP_PASSWORD=<smtp-pass>

# CORS — set to your actual frontend domain
CORS_ORIGINS=["https://yourdomain.com"]

# Logging
LOG_LEVEL=WARNING
JSON_LOGS=true
```

---

## Step 2 — Build Docker Images

```bash
docker-compose -f infrastructure/docker/docker-compose.yml build
```

Or build individual service images:

```bash
docker build -t socplatform/auth-service:latest \
  -f backend/services/auth_service/Dockerfile backend/

docker build -t socplatform/asset-discovery:latest \
  -f backend/services/asset_discovery/Dockerfile backend/

# Repeat for each service (vuln_scanner, threat_intel, incident_response,
# ai_copilot, edr_service, ndr_service, mitre_mapper, cloud_security,
# hunting_service, identity_security, email_security, autonomous_soc,
# predictive_analytics)
```

Push to your container registry:

```bash
docker tag socplatform/auth-service:latest <registry>/auth-service:latest
docker push <registry>/auth-service:latest
# Repeat for all services
```

---

## Step 3 — Start Infrastructure Services

```bash
docker-compose -f infrastructure/docker/docker-compose.yml up -d
```

Verify all services are healthy (~30–60s):

```bash
docker-compose -f infrastructure/docker/docker-compose.yml ps

# Individual health checks
docker exec soc-postgres pg_isready -U socuser
docker exec soc-redis redis-cli -a <redis-pass> ping
curl -s http://localhost:9200/_cluster/health | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])"
docker exec soc-kafka kafka-topics --list --bootstrap-server localhost:9092
```

Expected: `accepting connections`, `PONG`, `green` or `yellow`, topic list.

---

## Step 4 — Database Migrations & Seed

```bash
cd backend

# Install dependencies
python -m venv venv
source venv/bin/activate          # Linux/macOS
# .\venv\Scripts\Activate         # Windows

pip install -r requirements.txt
pip install bcrypt==3.2.2         # Required — passlib incompatibility fix

# Run migrations
alembic upgrade head

# Seed default admin accounts
python ../scripts/seed.py
```

Default credentials after seeding (change immediately in production):

| Email | Password | Role |
|-------|----------|------|
| `admin@socplatform.io` | `Admin123!` | admin |
| `analyst@socplatform.io` | `Analyst123!` | analyst |

> **Change default passwords immediately after first login.**

---

## Step 5 — Build Frontend

```bash
cd frontend
npm install
npm run build
# Output: frontend/dist/
```

Serve `dist/` via Nginx, Traefik, or a CDN (e.g. AWS CloudFront + S3).

Example Nginx config:

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    root /var/www/soc-frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Step 6 — Start Backend Services

### API Gateway (required — single entrypoint on port 8000)

```bash
cd backend
python -m uvicorn core.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### All Microservices (run each in a separate process/container)

```bash
# Core
python -m uvicorn services.auth_service.main:app       --host 0.0.0.0 --port 8010 --workers 2
python -m uvicorn services.asset_discovery.main:app    --host 0.0.0.0 --port 8002 --workers 2
python -m uvicorn services.vuln_scanner.main:app       --host 0.0.0.0 --port 8003 --workers 2
python -m uvicorn services.threat_intel.main:app       --host 0.0.0.0 --port 8004 --workers 2

# Security
python -m uvicorn services.incident_response.main:app  --host 0.0.0.0 --port 8005 --workers 2
python -m uvicorn services.ai_copilot.main:app         --host 0.0.0.0 --port 8006 --workers 2
python -m uvicorn services.edr_service.main:app        --host 0.0.0.0 --port 8007 --workers 2
python -m uvicorn services.ndr_service.main:app        --host 0.0.0.0 --port 8008 --workers 2

# Analytics + Cloud
python -m uvicorn services.mitre_mapper.main:app       --host 0.0.0.0 --port 8009 --workers 2
python -m uvicorn services.cloud_security.main:app     --host 0.0.0.0 --port 8011 --workers 2
python -m uvicorn services.hunting_service.main:app    --host 0.0.0.0 --port 8012 --workers 2

# Extended
python -m uvicorn services.identity_security.main:app  --host 0.0.0.0 --port 8013 --workers 2
python -m uvicorn services.email_security.main:app     --host 0.0.0.0 --port 8014 --workers 2
python -m uvicorn services.autonomous_soc.main:app     --host 0.0.0.0 --port 8015 --workers 2
python -m uvicorn services.predictive_analytics.main:app --host 0.0.0.0 --port 8016 --workers 2
```

> In production, use a process manager (systemd, supervisor) or run each service as a Docker container / Kubernetes pod.

---

## Step 7 — Kubernetes Deployment (recommended for production)

### 7.1 — Configure Secrets

```bash
# Encode your .env values as base64 and add to:
# infrastructure/kubernetes/secrets/soc-secrets.yaml

kubectl apply -f infrastructure/kubernetes/secrets/
```

### 7.2 — Deploy

```bash
kubectl apply -f infrastructure/kubernetes/namespaces/
kubectl apply -f infrastructure/kubernetes/configmaps/
kubectl apply -f infrastructure/kubernetes/secrets/
kubectl apply -f infrastructure/kubernetes/deployments/
kubectl apply -f infrastructure/kubernetes/services/
kubectl apply -f infrastructure/kubernetes/hpa/
kubectl apply -f infrastructure/kubernetes/ingress/
```

### 7.3 — Verify

```bash
kubectl get pods -n soc-platform
kubectl rollout status deployment/auth-service -n soc-platform
kubectl rollout status deployment/asset-discovery -n soc-platform
kubectl rollout status deployment/ai-copilot -n soc-platform
```

---

## Step 8 — CI/CD (GitHub Actions)

The pipeline in `.github/workflows/` runs automatically:

- `ci.yml` — runs on every push: lint → test → build
- `deploy.yml` — runs on merge to `main` after CI passes: deploys to Kubernetes

Required GitHub Secrets:

| Secret | Value |
|--------|-------|
| `KUBE_CONFIG` | Base64-encoded kubeconfig: `cat ~/.kube/config \| base64` |

---

## Step 9 — Verify Production

```bash
# API Gateway health
curl -s https://yourdomain.com/api/health

# Login
curl -s -X POST https://yourdomain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@socplatform.io","password":"<new-password>"}'

# Use returned access_token
curl -s https://yourdomain.com/api/v1/auth/me \
  -H "Authorization: Bearer <token>"
```

---

## Step 10 — Monitoring

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Grafana | `http://<host>:3000` | admin / admin *(change immediately)* |
| Prometheus | `http://<host>:9090` | — |
| API Docs | `http://<host>:8000/docs` | — |

Grafana dashboards are auto-provisioned:
- **SOC Platform Overview** — service health, API rates, error rates, latency, Kafka lag
- **Service Detail** — per-service drill-down (p50/p95/p99 latency, CPU/memory)

---

## Port Reference

| Service | Port |
|---------|------|
| API Gateway | 8000 |
| Asset Discovery | 8002 |
| Vulnerability Scanner | 8003 |
| Threat Intelligence | 8004 |
| Incident Response | 8005 |
| AI Copilot | 8006 |
| EDR | 8007 |
| NDR | 8008 |
| MITRE Mapper | 8009 |
| Auth Service | 8010 |
| Cloud Security | 8011 |
| Hunting Service | 8012 |
| Identity Security | 8013 |
| Email Security | 8014 |
| Autonomous SOC | 8015 |
| Predictive Analytics | 8016 |
| PostgreSQL | 5434 (host) / 5432 (container) |
| Redis | 6379 |
| Elasticsearch | 9200 |
| Kafka | 9092 |
| Grafana | 3000 |
| Prometheus | 9090 |
| Traefik Dashboard | 8080 |

---

## Common Issues

| Error | Fix |
|-------|-----|
| `No module named 'bcrypt.__about__'` | `pip install bcrypt==3.2.2` |
| Redis AUTH error | `pip install redis==6.4.0` |
| Elasticsearch version mismatch | `pip install elasticsearch[async]==8.17.1` |
| Port already in use | `netstat -ano \| findstr :<port>` → `taskkill /PID <pid> /F` |
| DB connection refused on 5434 | `docker start soc-postgres` |
