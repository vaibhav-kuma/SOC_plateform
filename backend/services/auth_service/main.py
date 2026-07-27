import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.database import init_db, close_db
from core.redis import redis_client
from core.logging import setup_logging
from core.midware import RateLimitMiddleware, SecurityHeadersMiddleware
from api.v1.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    await init_db()
    try:
        await redis_client.start()
    except Exception as e:
        print(f"Redis unavailable: {e}")
        redis_client.client = None
    try:
        await elastic_client.start()
    except Exception as e:
        print(f"Elasticsearch unavailable: {e}")
        elastic_client.client = None
    try:
        await kafka_client.start_producer()
    except Exception as e:
        print(f"Kafka unavailable: {e}")
        kafka_client.producer = None
    yield
    try:
        await kafka_client.stop_producer()
    except Exception:
        pass
    try:
        await elastic_client.stop()
    except Exception:
        pass
    try:
        await redis_client.stop()
    except Exception:
        pass
    await close_db()


app = FastAPI(
    title=f"{settings.APP_NAME} - Auth Service",
    version="1.0.0",
    lifespan=lifespan,
    debug=settings.DEBUG,
    docs_url="/docs" if settings.DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware, max_requests=20, window_seconds=60)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "auth-service"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
    )
