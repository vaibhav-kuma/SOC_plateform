#!/usr/bin/env bash
#=============================================================================
#  Deploy script for the SOC Platform
#  - Builds Docker images
#  - Spins up services via docker-compose
#  - Runs migrations / seeds
#  - Verifies health & readiness
#  - Starts OpenTelemetry collectors (optional)
#  - Handles cleanup on failure
#
#  Usage:  ./deploy.sh  [environment]   (environment = prod|staging|dev)
#=============================================================================

set -euo pipefail   # abort on any error, treat unset vars as errors

#-------------------------- Config ------------------------------------------------
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/backend"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"

# Optional: pick a specific env file (you can also rely on the default .env)
ENVIRONMENT="${1:-dev}"          # default = dev
ENV_FILE="${PROJECT_ROOT}/.env.${ENVIRONMENT}"

# Image tags (adjust registry if you push to a private repo)
BACKEND_IMAGE="soc-platform-api:${ENVIRONMENT}"
FRONTEND_IMAGE="soc-platform-frontend:${ENVIRONMENT}"

# OpenTelemetry collector (Jaeger / Tempo) optional service name in compose
OTEL_COLLECTOR="otel-collector"

#--------------------------- Helper Functions -----------------------------------
log()      { echo -e "\e[32m[INFO]\e[0m $*"; }
warn()     { echo -e "\e[33m[WARN]\e[0m $*"; }
error()    { echo -e "\e[31m[ERROR]\e[0m $*"; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "Command '$1' not found. Install it first." >&2; exit 1; }
}

#--------------------------- Prerequisite Checks -------------------------------
log "Checking required tools..."
require_cmd docker
require_cmd docker-compose
require_cmd git
require_cmd python3
require_cmd pip

log "Ensuring we are on a clean git state..."
git status --porcelain | grep -q . && { warn "Uncommitted changes detected."; exit 1; }

#--------------------------- Load environment -----------------------------------
if [[ -f "${ENV_FILE}" ]]; then
  log "Loading environment from ${ENV_FILE}"
else
  warn "Environment file ${ENV_FILE} not found – using default .env"
  ENV_FILE="${PROJECT_ROOT}/.env"
else
  warn "No env file found for environment '${ENVIRONMENT}'. Using .env."
fi

# Load variables (keeps them in the process' environment)
set -a
source "${ENV_FILE}"
set +a
log "Environment loaded: ${ENVIRONMENT}"

#--------------------------- Step 1 – Build Docker Images -----------------------
log "🔨 Building Docker images..."

# ---- Backend ---------------------------------------------------------
log "Building backend image '${BACKEND_IMAGE}'"
docker build -t "${BACKEND_IMAGE}" -f "${PROJECT_ROOT}/backend/Dockerfile" "${PROJECT_ROOT}/backend"

# ---- Frontend (if it exists) -----------------------------------------
if [[ -d "${FRONTEND_DIR}" && -f "${PROJECT_ROOT}/frontend/Dockerfile" ]]; then
  log "Building frontend image '${FRONTEND_IMAGE}'"
  docker build -t "${FRONTEND_IMAGE}" -f "${PROJECT_ROOT}/frontend/Dockerfile" "${PROJECT_ROOT}/frontend"
else
  warn "No frontend Dockerfile found – skipping frontend image build."
else
  warn "frontend directory missing – skipping."
fi

log "Images built (or already present)."

#--------------------------- Step 2 – Create Docker network & volumes -----------
log "Creating Docker volumes..."
docker volume create soc_postgres_data > /dev/null
docker volume create soc_redis_data   > /dev/null
docker volume create soc_es_data      > /dev/null
docker volume create soc_kafka_data   > /dev/null
docker volume create soc_otel_data    > /dev/null

#--------------------------- Step 3 – Pull dependent images (if not built) -----
log "Pulling external services images (Elasticsearch, Redis, Kafka, Jaeger)..."
docker pull docker.elastic.co/elasticsearch/elasticsearch:8.15.0
docker pull redis:7-alpine
docker pull bitnami/kafka:3.8
docker pull grafana/tempo:2.5   # or jaegertracing/all-in-one if you prefer Jaeger

#--------------------------- Step 4 – Run docker-compose up -------------------
log "Starting containers with docker-compose..."
docker compose -f "${COMPOSE_FILE}" up -d

#--------------------------- Step 5 – Run migrations & seed data ---------------
log "Running database migrations..."
docker compose exec -T backend python - <<PY
import asyncio
from core.database import init_db, sync_metadata
from core.config import settings
asyncio.run(init_db())
PY
log "Migrations applied."

# If you have a seeding step (e.g., create default roles), call it here:
# docker compose exec -T backend python - <<PY ... PY

#--------------------------- Step 6 – Wait for health checks ------------------
log "⏳ Waiting for services to become healthy..."
MAX_WAIT=60   # seconds
elapsed=0
while true; do
  # healthz is lightweight
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/healthz || echo "000")
  if [[ "$STATUS" == "200" ]]; then
    log "✅ healthz endpoint responded 200"
    break
  fi
  ((elapsed++))
  if (( elapsed > MAX_WAIT )); then
    error "Health check timed-out after ${MAX_WAIT}s"
  else
    sleep 1
    log "Waiting for healthz… (${elapsed}s/${MAX_WAIT}s)"
  fi
done

# Verify readiness & circuit-breaker status as well
log "Checking readiness endpoint..."
read_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/readyz || echo "000")
if [[ "$read_status" != "200" ]]; then
  warn "Readiness endpoint did not return 200 (status=$read_status). Continuing anyway."
else
  log "✅ readz endpoint healthy"
fi

# Circuit-breaker status sanity check
log "Fetching circuit-breaker status..."
curl -s http://localhost:8000/circuit-breaker-status | grep -q '"state"' && log "✅ Circuit-breaker status endpoint reachable"

#--------------------------- Step 7 – Validate OpenTelemetry ------------------
log "🔎 Validating OpenTelemetry instrumentation..."
# If you run a collector as a separate service, wait for it
if docker compose ps -q "${OTEL_COLLECTOR}" > /dev/null 2>&1; then
  log "Waiting for OTEL collector health..."
  otel_elapsed=0
  while ! curl -s http://localhost:4317/health > /dev/null 2>&1; do
    ((otel_elapsed++))
    [[ $otel_elapsed -gt 30 ]] && { warn "OTEL collector not ready after 30s"; break; }
    sleep 1
  done
  log "✅ OpenTelemetry collector is up"
fi

#--------------------------- Step 8 – Final sanity check -----------------------
log "🚀 Deployment appears successful!"
echo -e "\n=== Quick sanity test ==="
curl -s http://localhost:8000/routes | python -m json.tool | head -n 20
echo -e "\nIf you see a list of routes and the above script finished without errors, the deployment is up."

#--------------------------- Step 9 – Optional: Register Service in Swarm/K8s ----
# (Add your orchestration commands here if you move to Kubernetes later)

#--------------------------- Step 10 – Cleanup on Failure -----------------------
# Docker compose will automatically keep containers running; you can manually
# stop them with `docker compose down` if you need to roll back later.

log "🎉 Deployment script completed. You can now access:"
echo -e "  - API:      http://localhost:${API_PORT:-8000}"
echo -e "  - Frontend: http://localhost:${FRONTEND_PORT:-3000} (if built)"
echo -e "  - Metrics:  http://localhost:${OTEL_EXPORTER_PORT:-4317} (or view Jaeger UI)"
echo -e "\nTo stop everything:  docker compose down -v"