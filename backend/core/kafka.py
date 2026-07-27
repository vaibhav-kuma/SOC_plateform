import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional, Callable
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaError, KafkaTimeoutError
from core.config import settings

logger = logging.getLogger("soc.kafka")


class KafkaClient:
    def __init__(self):
        self.producer: Optional[AIOKafkaProducer] = None
        self.consumers: dict = {}

    async def start_producer(self):
        self.producer = AIOKafkaProducer(
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            compression_type="gzip",
            request_timeout_ms=settings.KAFKA_REQUEST_TIMEOUT_MS,
            retry_backoff_ms=500,
            max_batch_size=16384,
            linger_ms=5,
        )
        await self.producer.start()

    async def stop_producer(self):
        if self.producer:
            try:
                await self.producer.stop()
            except Exception as e:
                logger.error(f"Error stopping Kafka producer: {e}")

    async def send(self, topic: str, value: dict, key: Optional[str] = None, retries: int = None):
        if not self.producer:
            await self.start_producer()

        retries = retries or settings.KAFKA_MAX_RETRIES
        last_error = None

        for attempt in range(retries + 1):
            try:
                await self.producer.send_and_wait(
                    topic,
                    value=value,
                    key=key.encode("utf-8") if key else None,
                )
                return
            except KafkaTimeoutError as e:
                last_error = e
                logger.warning(f"Kafka send timeout (attempt {attempt + 1}/{retries + 1}): {e}")
                if attempt < retries:
                    await asyncio.sleep(0.5 * (2 ** attempt))
            except KafkaError as e:
                last_error = e
                logger.error(f"Kafka send error: {e}")
                raise

        raise KafkaTimeoutError(f"Failed to send to Kafka after {retries + 1} attempts: {last_error}")

    async def send_event(self, event_type: str, data: dict, source: str):
        await self.send(
            topic="raw.events",
            value={
                "event_type": event_type,
                "source": source,
                "data": data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def send_alert(self, alert: dict):
        await self.send(topic="alerts", value=alert, key=alert.get("id"))

    async def create_consumer(
        self, topic: str, group_id: str, handler: Callable
    ) -> AIOKafkaConsumer:
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
            group_id=group_id,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            max_poll_records=100,
            session_timeout_ms=30000,
            heartbeat_interval_ms=10000,
        )
        await consumer.start()
        self.consumers[topic] = {"consumer": consumer, "handler": handler}
        return consumer

    async def consume(self, topic: str):
        consumer_info = self.consumers.get(topic)
        if not consumer_info:
            return
        consumer = consumer_info["consumer"]
        handler = consumer_info["handler"]
        try:
            async for msg in consumer:
                try:
                    await handler(msg.value)
                except Exception as e:
                    logger.error(f"Error handling message from {topic}: {e}")
        except KafkaError as e:
            logger.error(f"Kafka consumer error for {topic}: {e}")
            raise

    async def stop_all_consumers(self):
        for info in self.consumers.values():
            try:
                await info["consumer"].stop()
            except Exception as e:
                logger.error(f"Error stopping consumer: {e}")


kafka_client = KafkaClient()
