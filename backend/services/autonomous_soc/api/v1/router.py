from fastapi import APIRouter
from api.v1.endpoints.autonomous import router as autonomous_router

router = APIRouter()
router.include_router(autonomous_router, prefix="/autonomous")
