from fastapi import APIRouter
from services.incident_response.api.v1.endpoints.incidents import router as incidents_router

api_router = APIRouter()
api_router.include_router(incidents_router)
