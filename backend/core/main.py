"""API Gateway - unified entrypoint routing to all microservices."""
import sys
from pathlib import Path
from typing import Optional
import logging

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi import status as http_status

from core.config import settings
from core.logging import setup_logging
from core.midware import RateLimitMiddleware, SecurityHeadersMiddleware, AuditLogMiddleware
from core.circuit_breaker import (
    redis_circuit_breaker,
    elasticsearch_circuit_breaker,
    kafka_circuit_breaker,
    CircuitBreakerError,
)
from core.otel_instrumentation import setup_otel, OperationMetrics, get_meter

logger = logging.getLogger("soc.gateway")

# OpenTelemetry metrics
meter = get_meter("api-gateway")
operation_metrics = OperationMetrics(meter)

SERVICE_ROUTES = {
    "/api/v1/auth": "http://localhost:8010/api/v1/auth",
    "/api/v1/assets": "http://localhost:8002/api/v1/assets",
    "/api/v1/vulnerabilities": "http://localhost:8003/api/v1/vulnerabilities",
    "/api/v1/intel": "http://localhost:8004/api/v1/intel",
    "/api/v1/incidents": "http://localhost:8005/api/v1/incidents",
    "/api/v1/copilot": "http://localhost:8006/api/v1/copilot",
    "/api/v1/endpoints": "http://localhost:8007/api/v1/endpoints",
    "/api/v1/network": "http://localhost:8008/api/v1/network",
    "/api/v1/mitre": "http://localhost:8009/api/v1/mitre",
    "/api/v1/cloud": "http://localhost:8011/api/v1/cloud",
    "/api/v1/hunting": "http://localhost:8012/api/v1/hunting",
    "/api/v1/identity": "http://localhost:8013/api/v1/identity",
    "/api/v1/email": "http://localhost:8014/api/v1/email",
    "/api/v1/autonomous": "http://localhost:8015/api/v1/autonomous",
    "/api/v1/predictive": "http://localhost:8016/api/v1/predictive",
}

SERVICE_HEALTH_ENDPOINTS = {
    prefix: f"{target.replace('/api/v1/auth', '').replace('/api/v1/', '')}/health"
    for prefix, target in SERVICE_ROUTES.items()
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()

    # Initialize OpenTelemetry instrumentation
    await setup_otel()
    logger.info("OpenTelemetry instrumentation initialized")

    # Initialize metrics
    meter = get_meter("api-gateway")
    app.state.operation_metrics = OperationMetrics(meter)

    app.state.client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            connect=5.0,
            read=30.0,
            write=30.0,
            pool=10.0,
        )
    )
    yield
    await app.state.client.aclose()


app = FastAPI(
    title=f"{settings.APP_NAME} - API Gateway",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuditLogMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)


def route_for(path: str) -> Optional[str]:
    for prefix in sorted(SERVICE_ROUTES.keys(), key=len, reverse=True):
        if path.startswith(prefix):
            return SERVICE_ROUTES[prefix]
    return None


@app.get("/health")
async def health():
    operation_metrics.record_request(
        duration_ms=0.0,  # Will be set after response
        method="GET",
        route="/health",
        status_code=200,
    )
    return {"status": "healthy", "service": "api-gateway"}


@app.get("/health/detailed")
async def detailed_health():
    """Check health of all downstream services"""
    results = {}
    for prefix, health_path in SERVICE_HEALTH_ENDPOINTS.items():
        service_name = prefix.split("/")[-1]
        target_base = SERVICE_ROUTES[prefix]
        # Extract base URL (remove /api/v1/service path)
        base_url = target_base.rsplit("/", 2)[0]
        health_url = f"{base_url}/health"

        try:
            resp = await app.state.client.get(health_url, timeout=5.0)
            results[service_name] = {
                "status": "healthy" if resp.status_code == 200 else "unhealthy",
                "status_code": resp.status_code,
            }
        except Exception as e:
            results[service_name] = {
                "status": "unreachable",
                "error": str(e),
            }

    all_healthy = all(s["status"] == "healthy" for s in results.values())
    return {
        "status": "healthy" if all_healthy else "degraded",
        "service": "api-gateway",
        "services": results,
    }


@app.get("/circuit-breaker-status")
async def circuit_breaker_status():
    """Get current status of all circuit breakers"""
    status = {}

    try:
        status["redis"] = {
            "state": redis_circuit_breaker.state.value,
            "failure_count": redis_circuit_breaker.failure_count,
            "threshold": redis_circuit_breaker.failure_threshold,
        }
    except Exception as e:
        status["redis"] = {"error": str(e)}

    try:
        status["elasticsearch"] = {
            "state": elasticsearch_circuit_breaker.state.value,
            "failure_count": elasticsearch_circuit_breaker.failure_count,
            "threshold": elasticsearch_circuit_breaker.failure_threshold,
        }
    except Exception as e:
        status["elasticsearch"] = {"error": str(e)}

    try:
        status["kafka"] = {
            "state": kafka_circuit_breaker.state.value,
            "failure_count": kafka_circuit_breaker.failure_count,
            "threshold": kafka_circuit_breaker.failure_threshold,
        }
    except Exception as e:
        status["kafka"] = {"error": str(e)}

    return {"service": "api-gateway", "circuit_breakers": status}


@app.get("/healthz")
async def healthz():
    """Lightweight health check for container orchestration"""
    return {"status": "healthy", "service": "api-gateway"}


@app.get("/readyz")
async def readyz():
    """Readiness check for container orchestration"""
    from core.redis import redis_client
    from core.elastic import elastic_client

    checks = {}

    # Check Redis
    try:
        if redis_client.client:
            await redis_client.client.ping()
            checks["redis"] = {"status": "ready"}
        else:
            checks["redis"] = {"status": "not_connected"}
    except Exception as e:
        checks["redis"] = {"status": "error", "detail": str(e)}

    # Check Elasticsearch
    try:
        if elastic_client.client:
            await elastic_client.client.ping()
            checks["elasticsearch"] = {"status": "ready"}
        else:
            checks["elasticsearch"] = {"status": "not_connected"}
    except Exception as e:
        checks["elasticsearch"] = {"status": "error", "detail": str(e)}

    all_ready = all(v["status"] == "ready" for v in checks.values())

    return {
        "status": "ready" if all_ready else "not_ready",
        "checks": checks,
    }


@app.get("/routes")
async def list_routes():
    return {k: v for k, v in sorted(SERVICE_ROUTES.items())}


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str):
    full_path = f"/{path}"
    target_base = route_for(full_path)
    if not target_base:
        return JSONResponse({"detail": "Route not found"}, status_code=http_status.HTTP_404_NOT_FOUND)

    client: httpx.AsyncClient = request.app.state.client

    # Reconstruct from original prefix
    target_url = None
    for prefix in sorted(SERVICE_ROUTES.keys(), key=len, reverse=True):
        if full_path.startswith(prefix):
            suffix = full_path[len(prefix):]
            target_url = f"{target_base}{suffix}"
            break

    if not target_url:
        return JSONResponse({"detail": "Route not found"}, status_code=http_status.HTTP_404_NOT_FOUND)

    body = await request.body()
    headers = dict(request.headers)
    headers.pop("host", None)

    try:
        resp = await client.request(
            method=request.method,
            url=target_url,
            content=body or None,
            headers=headers,
            params=dict(request.query_params),
        )
        return JSONResponse(
            content=resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )
    except httpx.TimeoutException:
        logger.error(f"Timeout proxying to {target_url}")
        return JSONResponse(
            {"detail": "Service unavailable: timeout"},
            status_code=http_status.HTTP_504_GATEWAY_TIMEOUT,
        )
    except httpx.ConnectError:
        logger.error(f"Connection error proxying to {target_url}")
        return JSONResponse(
            {"detail": "Service unavailable: connection error"},
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    except Exception as e:
        logger.error(f"Unexpected error proxying to {target_url}: {e}")
        return JSONResponse(
            {"detail": f"Service unavailable: {type(e).__name__}"},
            status_code=http_status.HTTP_503_SERVICE_UNAVAILABLE,
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.API_HOST, port=settings.API_PORT, reload=settings.DEBUG)
