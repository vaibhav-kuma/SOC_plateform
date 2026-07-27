from fastapi import APIRouter
from services.cloud_security.api.v1.endpoints.cloud import router as cloud_router

api_router = APIRouter()
api_router.include_router(cloud_router)
