from fastapi import APIRouter
from services.asset_discovery.api.v1.endpoints.discovery import router as discovery_router

api_router = APIRouter()
api_router.include_router(discovery_router)
