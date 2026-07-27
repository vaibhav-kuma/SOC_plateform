from fastapi import APIRouter
from api.v1.endpoints.email import router as email_router

router = APIRouter()
router.include_router(email_router, prefix="/email")
