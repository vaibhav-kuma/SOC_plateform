from fastapi import APIRouter
from services.hunting_service.api.v1.endpoints.hunting import router as hunting_router

api_router = APIRouter()
api_router.include_router(hunting_router)
