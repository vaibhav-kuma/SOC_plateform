from fastapi import APIRouter
from services.identity_security.api.v1.endpoints.identity import router as identity_router

api_router = APIRouter()
api_router.include_router(identity_router)
