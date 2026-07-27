from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from core.config import settings
import logging

logger = logging.getLogger("soc.database")


def _create_engine():
    """Create async engine with configured pool settings"""
    return create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        pool_size=settings.DB_MAX_CONNECTIONS // 5,
        max_overflow=settings.DB_MAX_CONNECTIONS // 10,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_timeout=settings.DB_CONNECT_TIMEOUT,
        connect_args={
            "timeout": settings.DB_ASYNC_CONNECT_TIMEOUT,
            "server_settings": {"application_name": "soc-platform"},
        },
    )


engine = _create_engine()

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncSession:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    await engine.dispose()


async def check_db_connection() -> bool:
    """Check if database is reachable"""
    try:
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        return True
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return False
