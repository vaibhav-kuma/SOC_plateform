from fastapi import APIRouter
from services.edr_service.api.v1.endpoints.endpoint import router as endpoint_router

api_router = APIRouter()
api_router.include_router(endpoint_router)
