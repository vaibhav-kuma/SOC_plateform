"""
OpenTelemetry Instrumentation for SOC Platform

This module provides OpenTelemetry instrumentation for distributed tracing,
metrics collection, and logging for the entire application.
"""

import asyncio
import logging
import time
from typing import Optional

from opentelemetry import metrics, trace
from opentelemetry.instrumentation.asyncio import AsyncIOInstrumentor
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    ConsoleMetricExporter,
    MetricExporter,
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
)
from opentelemetry.semconv.resource import ResourceAttributes

from core.config import settings

logger = logging.getLogger("soc.otel")


class OTelInstrumentor:
    """Manages OpenTelemetry instrumentation for the application."""

    def __init__(self):
        self._tracer_provider: Optional[TracerProvider] = None
        self._meter_provider: Optional[MeterProvider] = None
        self._is_instrumented = False

    async def setup_instrumentation(self, exporter: MetricExporter = None):
        """Set up OpenTelemetry instrumentation.

        Args:
            exporter: Optional custom exporter for metrics.
        """
        try:
            # Configure tracer provider
            self._tracer_provider = TracerProvider(
                resource=trace.Resource.create(
                    {
                        ResourceAttributes.SERVICE_NAME: settings.APP_NAME,
                        ResourceAttributes.SERVICE_VERSION: "1.0.0",
                        ResourceAttributes.DEPLOYMENT_ENVIRONMENT: settings.ENV,
                    }
                )
            )

            # Add span processors
            span_exporter: SpanExporter = ConsoleSpanExporter()
            self._tracer_provider.add_span_processor(
                BatchSpanProcessor(span_exporter)
            )
            trace.set_tracer_provider(self._tracer_provider)

            # Configure meter provider
            if exporter is None:
                exporter = ConsoleMetricExporter()

            self._meter_provider = MeterProvider(
                metric_readers=[
                    PeriodicExportingMetricReader(
                        exporter,
                        export_interval_millis=5000,  # 5 seconds
                    )
                ]
            )
            metrics.set_meter_provider(self._meter_provider)

            # Install instrumentors
            AsyncIOInstrumentor().instrument()
            RequestsInstrumentor().instrument()

            self._is_instrumented = True
            logger.info("OpenTelemetry instrumentation configured successfully")

        except Exception as e:
            logger.error(f"Failed to configure OpenTelemetry: {e}")
            # Don't fail the application if OTel is unavailable

    async def shutdown_instrumentation(self):
        """Shut down OpenTelemetry instrumentation."""
        if self._meter_provider:
            await self._meter_provider.shutdown()

        if self._tracer_provider:
            await self._tracer_provider.shutdown()

        self._is_instrumented = False
        logger.info("OpenTelemetry instrumentation shut down")

    def get_tracer(self, name: str = "soc"):
        """Get a tracer instance.

        Args:
            name: Name for the tracer (defaults to "soc")

        Returns:
            Tracer instance
        """
        if self._tracer_provider:
            return self._tracer_provider.get_tracer(name)
        return None

    def get_meter(self, name: str = "soc"):
        """Get a meter instance.

        Args:
            name: Name for the meter (defaults to "soc")

        Returns:
            Meter instance
        """
        if self._meter_provider:
            return self._meter_provider.get_meter(name)
        return None


# Global OTel instrumentor instance
_otel_instrumentor = OTelInstrumentor()


def setup_otel(exporter: MetricExporter = None):
    """Convenience function to set up OpenTelemetry instrumentation."""
    return asyncio.create_task(_otel_instrumentor.setup_instrumentation(exporter))


async def get_tracer(name: str = "soc"):
    """Convenience function to get a tracer."""
    return _otel_instrumentor.get_tracer(name)


async def get_meter(name: str = "soc"):
    """Convenience function to get a meter."""
    return _otel_instrumentor.get_meter(name)


class DatabaseMetrics:
    """Collects metrics for database operations."""

    def __init__(self, meter=None):
        self.meter = meter
        self._setup_metrics()

    def _setup_metrics(self):
        """Set up database-related metrics."""
        if not self.meter:
            return

        try:
            self.db_queries = self.meter.create_histogram(
                name="db_queries_total",
                unit="ms",
                description="Database query duration",
                attributes=["operation", "table"],
            )

            self.db_errors = self.meter.create_counter(
                name="db_errors_total",
                description="Number of database errors",
                attributes=["operation", "error_type"],
            )

            self.db_connections = self.meter.create_up_down_counter(
                name="db_connections",
                description="Number of active database connections",
            )

            logger.debug("Database metrics initialized")

        except Exception as e:
            logger.warning(f"Failed to initialize database metrics: {e}")

    def record_query(self, duration_ms: float, operation: str, table: str):
        """Record a database query.

        Args:
            duration_ms: Query duration in milliseconds
            operation: Type of operation (SELECT, INSERT, etc.)
            table: Table name
        """
        if hasattr(self, "db_queries"):
            self.db_queries.record(duration_ms, {"operation": operation, "table": table})

    def record_error(self, operation: str, error_type: str):
        """Record a database error.

        Args:
            operation: Type of operation
            error_type: Type of error
        """
        if hasattr(self, "db_errors"):
            self.db_errors.add(1, {"operation": operation, "error_type": error_type})


class ExternalServiceMetrics:
    """Collects metrics for external service calls."""

    def __init__(self, meter=None):
        self.meter = meter
        self._setup_metrics()

    def _setup_metrics(self):
        """Set up external service metrics."""
        if not self.meter:
            return

        try:
            self.external_requests = self.meter.create_histogram(
                name="external_requests_total",
                unit="ms",
                description="External service request duration",
                attributes=["service", "method", "endpoint"],
            )

            self.external_errors = self.meter.create_counter(
                name="external_errors_total",
                description="Number of external service errors",
                attributes=["service", "method", "endpoint", "error_type"],
            )

            self.external_timeouts = self.meter.create_counter(
                name="external_timeouts_total",
                description="Number of external service timeouts",
                attributes=["service", "method", "endpoint"],
            )

            logger.debug("External service metrics initialized")

        except Exception as e:
            logger.warning(f"Failed to initialize external service metrics: {e}")

    def record_request(self, duration_ms: float, service: str, method: str, endpoint: str):
        """Record an external service request.

        Args:
            duration_ms: Request duration in milliseconds
            service: Service name (redis, elasticsearch, kafka)
            method: HTTP method
            endpoint: Endpoint/path
        """
        if hasattr(self, "external_requests"):
            self.external_requests.record(
                duration_ms, {"service": service, "method": method, "endpoint": endpoint}
            )

    def record_error(
        self, service: str, method: str, endpoint: str, error_type: str
    ):
        """Record an external service error.

        Args:
            service: Service name
            method: HTTP method
            endpoint: Endpoint/path
            error_type: Type of error
        """
        if hasattr(self, "external_errors"):
            self.external_errors.add(
                1,
                {
                    "service": service,
                    "method": method,
                    "endpoint": endpoint,
                    "error_type": error_type,
                },
            )

    def record_timeout(self, service: str, method: str, endpoint: str):
        """Record an external service timeout.

        Args:
            service: Service name
            method: HTTP method
            endpoint: Endpoint/path
        """
        if hasattr(self, "external_timeouts"):
            self.external_timeouts.add(
                1, {"service": service, "method": method, "endpoint": endpoint}
            )


class OperationMetrics:
    """Collects metrics for application operations."""

    def __init__(self, meter=None):
        self.meter = meter
        self._setup_metrics()

    def _setup_metrics(self):
        """Set up operation metrics."""
        if not self.meter:
            return

        try:
            self.request_duration = self.meter.create_histogram(
                name="request_duration_seconds",
                unit="ms",
                description="HTTP request duration",
                attributes=["method", "route", "status_code"],
            )

            self.active_requests = self.meter.create_up_down_counter(
                name="active_requests",
                description="Number of active HTTP requests",
                attributes=["method", "route"],
            )

            self.http_requests = self.meter.create_counter(
                name="http_requests_total",
                description="Total number of HTTP requests",
                attributes=["method", "route", "status_code"],
            )

            logger.debug("Operation metrics initialized")

        except Exception as e:
            logger.warning(f"Failed to initialize operation metrics: {e}")

    def record_request(
        self, duration_ms: float, method: str, route: str, status_code: int
    ):
        """Record an HTTP request.

        Args:
            duration_ms: Request duration in milliseconds
            method: HTTP method
            route: Request route/path
            status_code: HTTP status code
        """
        if hasattr(self, "request_duration"):
            self.request_duration.record(
                duration_ms, {"method": method, "route": route, "status_code": status_code}
            )

        if hasattr(self, "http_requests"):
            self.http_requests.add(1, {"method": method, "route": route, "status_code": status_code})

    def increment_active_requests(self, method: str, route: str):
        """Increment active requests counter.

        Args:
            method: HTTP method
            route: Request route/path
        """
        if hasattr(self, "active_requests"):
            self.active_requests.add(1, {"method": method, "route": route})

    def decrement_active_requests(self, method: str, route: str):
        """Decrement active requests counter.

        Args:
            method: HTTP method
            route: Request route/path
        """
        if hasattr(self, "active_requests"):
            self.active_requests.add(-1, {"method": method, "route": route})