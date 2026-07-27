import logging
from typing import Optional
from core.redis import redis_client
from core.elastic import elastic_client
from core.kafka import kafka_client

logger = logging.getLogger("soc.lifecycle")


async def start_infrastructure(require_redis: bool = False, require_elastic: bool = False, require_kafka: bool = False):
    """
    Start external infrastructure with graceful degradation.
    Services continue running even if optional dependencies are unavailable.

    Args:
        require_redis: If True, crash the service if Redis is unavailable
        require_elastic: If True, crash the service if Elasticsearch is unavailable
        require_kafka: If True, crash the service if Kafka is unavailable
    """
    if require_redis:
        await redis_client.start()
    else:
        try:
            await redis_client.start()
        except Exception as e:
            logger.warning(f"Redis unavailable: {e}")
            redis_client.client = None

    if require_elastic:
        await elastic_client.start()
    else:
        try:
            await elastic_client.start()
        except Exception as e:
            logger.warning(f"Elasticsearch unavailable: {e}")
            elastic_client.client = None

    if require_kafka:
        await kafka_client.start_producer()
    else:
        try:
            await kafka_client.start_producer()
        except Exception as e:
            logger.warning(f"Kafka unavailable: {e}")
            kafka_client.producer = None


async def stop_infrastructure():
    """Gracefully stop all external infrastructure connections."""
    try:
        await kafka_client.stop_producer()
    except Exception as e:
        logger.warning(f"Error stopping Kafka producer: {e}")

    try:
        await elastic_client.stop()
    except Exception as e:
        logger.warning(f"Error stopping Elasticsearch: {e}")

    try:
        await redis_client.stop()
    except Exception as e:
        logger.warning(f"Error stopping Redis: {e}")


def get_infrastructure_status() -> dict:
    """Return health status of external infrastructure for health endpoints."""
    return {
        "redis": "connected" if redis_client.client else "disconnected",
        "elasticsearch": "connected" if elastic_client.client else "disconnected",
        "kafka": "connected" if kafka_client.producer else "disconnected",
    }