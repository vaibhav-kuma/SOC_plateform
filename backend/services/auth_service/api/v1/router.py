from fastapi import APIRouter
from services.auth_service.api.v1.endpoints.auth import router as auth_router
from services.auth_service.api.v1.endpoints.users import router as users_router
from services.auth_service.api.v1.endpoints.organizations import router as orgs_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(users_router)
api_router.include_router(orgs_router)
