from fastapi import APIRouter
from api.v1.endpoints.predictive import router as predictive_router

router = APIRouter()
router.include_router(predictive_router, prefix="/predictive")
