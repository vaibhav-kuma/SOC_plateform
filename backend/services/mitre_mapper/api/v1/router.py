from fastapi import APIRouter
from services.mitre_mapper.api.v1.endpoints.mitre import router as mitre_router

api_router = APIRouter()
api_router.include_router(mitre_router)
