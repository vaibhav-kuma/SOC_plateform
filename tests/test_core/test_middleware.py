import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from core.midware import RateLimitMiddleware, SecurityHeadersMiddleware, AuditLogMiddleware


class MockRequest:
    def __init__(self, path="/api/v1/test", method="GET", client_host="127.0.0.1", headers=None):
        self.url = MagicMock()
        self.url.path = path
        self.method = method
        self.client = MagicMock()
        self.client.host = client_host
        self.headers = headers or {}


class MockCallNext:
    def __init__(self, response=None):
        self.response = response or Response(content="OK", status_code=200)
        self.call_count = 0

    async def __call__(self, request):
        self.call_count += 1
        return self.response


@pytest.mark.asyncio
async def test_rate_limit_middleware_allows_request():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)

    with patch("core.midware.redis_client") as mock_redis_client:
        mock_redis_client.client = mock_redis
        middleware = RateLimitMiddleware(MagicMock(), max_requests=10, window_seconds=60)

        request = MockRequest(path="/api/v1/test")
        call_next = MockCallNext()

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200
        assert call_next.call_count == 1


@pytest.mark.asyncio
async def test_rate_limit_middleware_blocks_when_exceeded():
    mock_pipeline = AsyncMock()
    mock_pipeline.incr = AsyncMock()
    mock_pipeline.expire = AsyncMock()
    mock_pipeline.execute = AsyncMock()

    mock_redis_client = MagicMock()
    mock_redis_client.get = AsyncMock(return_value="100")
    mock_redis_client.client = MagicMock()
    mock_redis_client.client.pipeline = MagicMock(return_value=mock_pipeline)

    with patch("core.midware.redis_client", mock_redis_client):
        middleware = RateLimitMiddleware(MagicMock(), max_requests=10, window_seconds=60)

        request = MockRequest(path="/api/v1/test")
        call_next = MockCallNext()

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 429
        assert call_next.call_count == 0


@pytest.mark.asyncio
async def test_rate_limit_middleware_handles_redis_failure():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=Exception("Redis down"))

    with patch("core.midware.redis_client") as mock_redis_client:
        mock_redis_client.client = mock_redis
        middleware = RateLimitMiddleware(MagicMock(), max_requests=10, window_seconds=60)

        request = MockRequest(path="/api/v1/test")
        call_next = MockCallNext()

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200
        assert call_next.call_count == 1


@pytest.mark.asyncio
async def test_rate_limit_middleware_exempts_health_endpoint():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value="100")

    with patch("core.midware.redis_client") as mock_redis_client:
        mock_redis_client.client = mock_redis
        middleware = RateLimitMiddleware(MagicMock(), max_requests=10, window_seconds=60)

        request = MockRequest(path="/health")
        call_next = MockCallNext()

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200
        assert call_next.call_count == 1


@pytest.mark.asyncio
async def test_rate_limit_middleware_exempts_routes_endpoint():
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value="100")

    with patch("core.midware.redis_client") as mock_redis_client:
        mock_redis_client.client = mock_redis
        middleware = RateLimitMiddleware(MagicMock(), max_requests=10, window_seconds=60)

        request = MockRequest(path="/routes")
        call_next = MockCallNext()

        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200
        assert call_next.call_count == 1


@pytest.mark.asyncio
async def test_security_headers_middleware():
    middleware = SecurityHeadersMiddleware(MagicMock())
    request = MockRequest()
    call_next = MockCallNext()

    response = await middleware.dispatch(request, call_next)
    assert response.status_code == 200
    assert "X-Content-Type-Options" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "X-Frame-Options" in response.headers
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" in response.headers
    assert "Content-Security-Policy" in response.headers
    assert "Referrer-Policy" in response.headers
    assert "Permissions-Policy" in response.headers


@pytest.mark.asyncio
async def test_audit_log_middleware_logs_mutations():
    import logging
    from core.midware import AuditLogMiddleware

    middleware = AuditLogMiddleware(MagicMock())
    request = MockRequest(method="POST", path="/api/v1/assets")
    call_next = MockCallNext()

    with patch("core.midware.logger") as mock_logger:
        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200
        mock_logger.info.assert_called_once()
        log_args = mock_logger.info.call_args
        assert log_args[0][0] == "audit"
        extra = log_args[1]["extra"]
        assert extra["method"] == "POST"
        assert extra["path"] == "/api/v1/assets"


@pytest.mark.asyncio
async def test_audit_log_middleware_skips_get():
    from core.midware import AuditLogMiddleware

    middleware = AuditLogMiddleware(MagicMock())
    request = MockRequest(method="GET", path="/api/v1/assets")
    call_next = MockCallNext()

    with patch("core.midware.logger") as mock_logger:
        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200
        mock_logger.info.assert_not_called()