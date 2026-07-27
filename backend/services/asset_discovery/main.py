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
from core.elastic import elastic_client
from core.kafka import kafka_client
from core.logging import setup_logging
from core.midware import RateLimitMiddleware, SecurityHeadersMiddleware
from api.v1.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    await init_db()
    await redis_client.start()
    await elastic_client.start()
    await kafka_client.start_producer()
    yield
    await kafka_client.stop_producer()
    await elastic_client.stop()
    await redis_client.stop()
    await close_db()


app = FastAPI(
    title=f"{settings.APP_NAME} - Asset Discovery",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "asset-discovery"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8002,
        reload=True,
    )
