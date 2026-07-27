from fastapi import APIRouter
from services.ndr_service.api.v1.endpoints.network import router as network_router

api_router = APIRouter()
api_router.include_router(network_router)
