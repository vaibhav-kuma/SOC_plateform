import pytest
import asyncio
from datetime import timedelta
from core.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerError,
    CircuitState,
    redis_circuit_breaker,
    elasticsearch_circuit_breaker,
    kafka_circuit_breaker,
    circuit_breaker_protected,
)


class AsyncFunctionMock:
    def __init__(self, side_effect=None, return_value=None):
        self.side_effect = side_effect
        self.return_value = return_value
        self.call_count = 0

    async def __call__(self, *args, **kwargs):
        self.call_count += 1
        if self.side_effect:
            if isinstance(self.side_effect, Exception):
                raise self.side_effect
            if callable(self.side_effect):
                raise self.side_effect()
        return self.return_value


@pytest.mark.asyncio
async def test_circuit_breaker_closed_state():
    cb = CircuitBreaker(name="test", failure_threshold=3, timeout_seconds=1)

    success_func = AsyncFunctionMock(return_value="success")

    result = await cb.call(success_func)
    assert result == "success"
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_opens_after_threshold():
    cb = CircuitBreaker(name="test", failure_threshold=3, timeout_seconds=1)

    fail_func = AsyncFunctionMock(side_effect=ConnectionError("Service down"))

    for _ in range(3):
        with pytest.raises(CircuitBreakerError):
            await cb.call(fail_func)

    assert cb.state == CircuitState.OPEN
    assert cb.failure_count == 3


@pytest.mark.asyncio
async def test_circuit_breaker_rejects_when_open():
    cb = CircuitBreaker(name="test", failure_threshold=2, timeout_seconds=10)

    fail_func = AsyncFunctionMock(side_effect=ConnectionError("Service down"))

    for _ in range(2):
        with pytest.raises(CircuitBreakerError):
            await cb.call(fail_func)

    assert cb.state == CircuitState.OPEN

    success_func = AsyncFunctionMock(return_value="success")
    with pytest.raises(CircuitBreakerError) as exc_info:
        await cb.call(success_func)

    assert "OPEN" in str(exc_info.value)
    assert exc_info.value.service == "test"
    assert success_func.call_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_transitions():
    cb = CircuitBreaker(name="test", failure_threshold=2, timeout_seconds=1, success_threshold=1)

    fail_func = AsyncFunctionMock(side_effect=ConnectionError("Service down"))
    success_func = AsyncFunctionMock(return_value="success")

    for _ in range(2):
        with pytest.raises(CircuitBreakerError):
            await cb.call(fail_func)

    assert cb.state == CircuitState.OPEN

    await asyncio.sleep(1.1)

    result = await cb.call(success_func)
    assert result == "success"
    assert cb.state == CircuitState.CLOSED


@pytest.mark.asyncio
async def test_circuit_breaker_half_open_reopens_on_failure():
    cb = CircuitBreaker(name="test", failure_threshold=2, timeout_seconds=1, success_threshold=2)

    fail_func = AsyncFunctionMock(side_effect=ConnectionError("Service down"))

    for _ in range(2):
        with pytest.raises(CircuitBreakerError):
            await cb.call(fail_func)

    assert cb.state == CircuitState.OPEN

    await asyncio.sleep(1.1)

    with pytest.raises(CircuitBreakerError):
        await cb.call(fail_func)

    assert cb.state == CircuitState.OPEN


@pytest.mark.asyncio
async def test_circuit_breaker_unexpected_exception_does_not_trip():
    cb = CircuitBreaker(
        name="test",
        failure_threshold=2,
        timeout_seconds=10,
        expected_exceptions=(ConnectionError,),
    )

    unexpected_func = AsyncFunctionMock(side_effect=ValueError("Unexpected"))

    with pytest.raises(ValueError):
        await cb.call(unexpected_func)

    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_reset():
    cb = CircuitBreaker(name="test", failure_threshold=2, timeout_seconds=10)

    fail_func = AsyncFunctionMock(side_effect=ConnectionError("Service down"))

    for _ in range(2):
        with pytest.raises(CircuitBreakerError):
            await cb.call(fail_func)

    assert cb.state == CircuitState.OPEN

    cb.reset()

    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


@pytest.mark.asyncio
async def test_circuit_breaker_decorator_with_fallback():
    cb = CircuitBreaker(name="test", failure_threshold=2, timeout_seconds=10)

    fail_func = AsyncFunctionMock(side_effect=ConnectionError("Service down"))
    fallback_func = AsyncFunctionMock(return_value="fallback")

    for _ in range(2):
        with pytest.raises(CircuitBreakerError):
            await cb.call(fail_func)

    assert cb.state == CircuitState.OPEN

    @circuit_breaker_protected(cb, fallback=fallback_func)
    async def protected_func():
        return await fail_func()

    result = await protected_func()
    assert result == "fallback"
    assert fallback_func.call_count == 1


@pytest.mark.asyncio
async def test_circuit_breaker_decorator_without_fallback():
    cb = CircuitBreaker(name="test", failure_threshold=2, timeout_seconds=10)

    fail_func = AsyncFunctionMock(side_effect=ConnectionError("Service down"))

    for _ in range(2):
        with pytest.raises(CircuitBreakerError):
            await cb.call(fail_func)

    assert cb.state == CircuitState.OPEN

    @circuit_breaker_protected(cb)
    async def protected_func():
        return await fail_func()

    with pytest.raises(CircuitBreakerError):
        await protected_func()


def test_global_circuit_breakers_exist():
    assert redis_circuit_breaker.name == "redis"
    assert redis_circuit_breaker.failure_threshold == 10
    assert redis_circuit_breaker.timeout_seconds == 30

    assert elasticsearch_circuit_breaker.name == "elasticsearch"
    assert kafka_circuit_breaker.name == "kafka"


@pytest.mark.asyncio
async def test_circuit_breaker_get_state():
    cb = CircuitBreaker(name="test", failure_threshold=3, timeout_seconds=60)

    state = cb.get_state()
    assert state["name"] == "test"
    assert state["state"] == "closed"
    assert state["failure_count"] == 0
    assert state["threshold"] == 3