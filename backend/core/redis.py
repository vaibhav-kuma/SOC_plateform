from typing import Optional, Any, List
import json
import redis.asyncio as redis
from core.config import settings
import logging

logger = logging.getLogger("soc.redis")


class RedisClient:
    def __init__(self):
        self.client: Optional[redis.Redis] = None

    async def start(self):
        import urllib.parse
        parsed = urllib.parse.urlparse(settings.REDIS_URL)
        self.client = redis.Redis(
            host=parsed.hostname or "localhost",
            port=parsed.port or 6379,
            password=parsed.password or settings.REDIS_PASSWORD,
            db=int(parsed.path.lstrip("/") or 0),
            decode_responses=True,
            socket_connect_timeout=settings.REDIS_SOCKET_CONNECT_TIMEOUT,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            socket_keepalive=True,
            health_check_interval=settings.REDIS_HEALTH_CHECK_INTERVAL,
            retry_on_timeout=True,
            retry_on_error=[redis.ConnectionError, redis.TimeoutError],
        )
        await self.client.ping()

    async def stop(self):
        if self.client:
            try:
                await self.client.aclose()
            except Exception as e:
                logger.error(f"Error closing Redis connection: {e}")

    async def get(self, key: str) -> Optional[str]:
        if not self.client:
            return None
        try:
            return await self.client.get(key)
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis get failed for key {key}: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: int = 300):
        if not self.client:
            return
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            await self.client.setex(key, ttl, value)
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis set failed for key {key}: {e}")

    async def delete(self, key: str):
        if not self.client:
            return
        try:
            await self.client.delete(key)
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis delete failed for key {key}: {e}")

    async def publish(self, channel: str, message: Any):
        if not self.client:
            return
        try:
            if isinstance(message, (dict, list)):
                message = json.dumps(message)
            await self.client.publish(channel, message)
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis publish failed for channel {channel}: {e}")

    async def subscribe(self, channel: str):
        if not self.client:
            return None
        try:
            pubsub = self.client.pubsub()
            await pubsub.subscribe(channel)
            return pubsub
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis subscribe failed for channel {channel}: {e}")
            return None

    async def acquire_lock(self, lock_key: str, ttl: int = 30) -> bool:
        if not self.client:
            return False
        try:
            return bool(await self.client.setnx(lock_key, "1")) and bool(
                await self.client.expire(lock_key, ttl)
            )
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis acquire_lock failed for key {lock_key}: {e}")
            return False

    async def release_lock(self, lock_key: str):
        await self.delete(lock_key)

    async def pipeline(self):
        if not self.client:
            return None
        try:
            return self.client.pipeline()
        except (redis.ConnectionError, redis.TimeoutError) as e:
            logger.warning(f"Redis pipeline creation failed: {e}")
            return None


redis_client = RedisClient()
