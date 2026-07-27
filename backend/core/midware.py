import time
import logging
from typing import List, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from core.redis import redis_client

logger = logging.getLogger("soc.middleware")


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        max_requests: int = 100,
        window_seconds: int = 60,
        exempt_paths: Optional[List[str]] = None,
    ):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.exempt_paths = exempt_paths or ["/health", "/routes"]

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path.startswith("/api/") and redis_client.client:
            if any(request.url.path.startswith(path) for path in self.exempt_paths):
                return await call_next(request)

            user_id = request.headers.get("X-User-ID", request.client.host)
            bucket = f"rate_limit:{user_id}:{request.url.path}"

            try:
                current = await redis_client.get(bucket)
                if current and int(current) >= self.max_requests:
                    logger.warning(f"Rate limit exceeded for {user_id} on {request.url.path}")
                    return Response(
                        content='{"detail":"Rate limit exceeded"}',
                        status_code=429,
                        media_type="application/json",
                    )

                pipe = redis_client.client.pipeline()
                await pipe.incr(bucket)
                await pipe.expire(bucket, self.window_seconds)
                await pipe.execute()
            except Exception as e:
                logger.warning(f"Rate limiting unavailable (redis down): {e}")

        return await call_next(request)


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.time()
        response = await call_next(request)
        duration = time.time() - start

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            logger.info(
                "audit",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": response.status_code,
                    "duration_ms": round(duration * 1000),
                    "user_agent": request.headers.get("user-agent"),
                    "ip": request.client.host,
                },
            )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response
