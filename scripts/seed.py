"""Seed initial admin user and organization."""
import sys, asyncio, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

os.environ["DATABASE_URL"] = "postgresql+asyncpg://socuser:socpass@127.0.0.1:5434/socplatform"
os.environ["SYNC_DATABASE_URL"] = "postgresql://socuser:socpass@127.0.0.1:5434/socplatform"
os.environ["REDIS_URL"] = "redis://:redispass@localhost:6379/0"
os.environ["ELASTICSEARCH_HOSTS"] = '["http://localhost:9200"]'
os.environ["KAFKA_BOOTSTRAP_SERVERS"] = "localhost:9092"
os.environ["JWT_SECRET_KEY"] = "test-key"

from core.database import async_session_factory, engine
from core.security import hash_password
from common.models.base import Organization, User

async def seed():
    async with async_session_factory() as session:
        org = Organization(name="SOC Corp", slug="soc-corp")
        session.add(org)
        await session.flush()

        admin = User(
            email="admin@socplatform.io",
            password_hash=hash_password("Admin123!"),
            full_name="SOC Admin",
            org_id=org.id,
            role="admin",
            is_active=True,
        )
        session.add(admin)
        await session.commit()
        print(f"Seeded org={org.id} admin={admin.id}")

asyncio.run(seed())
