"""
Circuit Breaker Pattern Implementation for External Service Calls

This module provides a circuit breaker pattern to prevent cascading failures
when external services (Redis, Elasticsearch, Kafka) become unavailable.
"""

import asyncio
import time
import logging
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger("soc.circuit_breaker")

F = TypeVar("F", bound=Callable[..., Any])


class CircuitState(Enum):
    """Circuit breaker states"""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when circuit breaker is open"""

    def __init__(self, message: str, state: CircuitState = CircuitState.OPEN, service: str = ""):
        self.message = message
        self.state = state
        self.service = service
        super().__init__(message)


class CircuitBreaker:
    """
    Circuit breaker implementation for external service calls.

    Prevents cascading failures by:
    1. Tracking failures to an external service
    2. Tripping the circuit when failure threshold is exceeded
    3. Allowing test requests after a timeout period
    4. Resetting on successful requests

    Thread-safe implementation for async contexts.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        timeout_seconds: int = 60,
        success_threshold: int = 2,
        expected_exceptions: Optional[tuple] = None,
    ):
        self.name = name
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds
        self.success_threshold = success_threshold
        self.expected_exceptions = expected_exceptions or (Exception,)

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute a function with circuit breaker protection.

        Args:
            func: The function to execute
            *args: Positional arguments for the function
            **kwargs: Keyword arguments for the function

        Returns:
            The result of the function call

        Raises:
            CircuitBreakerError: If the circuit is open
            Exception: Re-raises any unexpected exceptions
        """
        async with self._lock:
            await self._check_state()

            if self._state == CircuitState.OPEN:
                logger.warning(f"Circuit breaker '{self.name}' is OPEN - skipping call")
                raise CircuitBreakerError(
                    f"Circuit breaker '{self.name}' is OPEN - service unavailable",
                    state=CircuitState.OPEN,
                    service=self.name,
                )

        try:
            result = await func(*args, **kwargs)
            await self._on_success()
            return result
        except self.expected_exceptions as e:
            await self._on_failure()
            raise CircuitBreakerError(
                f"Circuit breaker '{self.name}' tripped: {e}",
                state=self._state,
                service=self.name,
            ) from e
        except Exception as e:
            # Unexpected exceptions don't trip the circuit, but we log them
            logger.error(f"Unexpected error in {self.name}: {e}")
            raise

    async def _check_state(self) -> None:
        """Check and update circuit state based on timeout"""
        if self._state == CircuitState.OPEN:
            if self._last_failure_time is not None:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.timeout_seconds:
                    # Transition to half-open, allow test requests
                    self._state = CircuitState.HALF_OPEN
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"Circuit breaker '{self.name}' transitioning to HALF_OPEN")

    async def _on_success(self) -> None:
        """Handle successful operation"""
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
                    self._success_count = 0
                    logger.info(f"Circuit breaker '{self.name}' closed - service recovered")
            else:
                self._failure_count = 0

    async def _on_failure(self) -> None:
        """Handle failed operation"""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            self._success_count = 0

            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
                logger.warning(f"Circuit breaker '{self.name}' reopened - service still failing")
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                logger.error(
                    f"Circuit breaker '{self.name}' opened after {self._failure_count} failures"
                )

    def reset(self) -> None:
        """Reset the circuit breaker to closed state"""
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None
        self._state = CircuitState.CLOSED
        logger.info(f"Circuit breaker '{self.name}' manually reset")

    def get_state(self) -> dict:
        """Return current circuit breaker state for monitoring"""
        return {
            "name": self.name,
            "state": self._state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "last_failure_time": self._last_failure_time,
            "threshold": self.failure_threshold,
        }


# Global circuit breakers for external services
# Higher thresholds for services that may experience transient failures
redis_circuit_breaker = CircuitBreaker(
    name="redis",
    failure_threshold=10,
    timeout_seconds=30,
    success_threshold=2,
    expected_exceptions=(ConnectionError, TimeoutError, OSError),
)

elasticsearch_circuit_breaker = CircuitBreaker(
    name="elasticsearch",
    failure_threshold=10,
    timeout_seconds=60,
    success_threshold=2,
    expected_exceptions=(ConnectionError, TimeoutError, OSError),
)

kafka_circuit_breaker = CircuitBreaker(
    name="kafka",
    failure_threshold=10,
    timeout_seconds=60,
    success_threshold=2,
    expected_exceptions=(ConnectionError, TimeoutError, OSError),
)


def circuit_breaker_protected(circuit_breaker: CircuitBreaker, fallback: Optional[Callable] = None):
    """
    Decorator to protect a function with a circuit breaker.

    Args:
        circuit_breaker: The CircuitBreaker instance to use
        fallback: Optional fallback function to call when circuit is open

    Usage:
        @circuit_breaker_protected(redis_circuit_breaker)
        async def get_redis_value(key: str) -> Optional[str]:
            return await redis_client.get(key)

        @circuit_breaker_protected(elasticsearch_cb, fallback=lambda: [])
        async def search_es(query: dict) -> List[dict]:
            return await es_client.search(...)
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await circuit_breaker.call(func, *args, **kwargs)
            except CircuitBreakerError as e:
                logger.warning(f"Circuit breaker prevented call to {func.__name__}: {e.message}")
                if fallback:
                    result = fallback(*args, **kwargs)
                    if asyncio.iscoroutine(result):
                        return await result
                    return result
                raise
            except Exception as e:
                logger.error(f"Unexpected error in {func.__name__}: {e}")
                raise

        return wrapper

    return decorator