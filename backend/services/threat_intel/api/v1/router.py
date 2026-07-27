from fastapi import APIRouter
from services.threat_intel.api.v1.endpoints.intel import router as intel_router

api_router = APIRouter()
api_router.include_router(intel_router)
