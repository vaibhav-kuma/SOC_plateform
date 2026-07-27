from fastapi import APIRouter
from services.vuln_scanner.api.v1.endpoints.vulnerabilities import router as vuln_router

api_router = APIRouter()
api_router.include_router(vuln_router)
