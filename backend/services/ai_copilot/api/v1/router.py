from fastapi import APIRouter
from services.ai_copilot.api.v1.endpoints.copilot import router as copilot_router

api_router = APIRouter()
api_router.include_router(copilot_router)
