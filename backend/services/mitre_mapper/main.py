import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.config import settings
from core.database import init_db, close_db
from core.logging import setup_logging
from core.midware import RateLimitMiddleware, SecurityHeadersMiddleware
from core.infrastructure import start_infrastructure, stop_infrastructure, get_infrastructure_status
from api.v1.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    await init_db()
    await start_infrastructure()
    yield
    await stop_infrastructure()
    await close_db()


app = FastAPI(title=f"{settings.APP_NAME} - MITRE ATT&CK Mapper", version="1.0.0", lifespan=lifespan, docs_url="/docs" if settings.DEBUG else None)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


MITRE_TECHNIQUES = {
    "reconnaissance": {"id": "TA0043", "techniques": [
        {"id": "T1595", "name": "Active Scanning", "detections": 3, "coverage": 0.6},
        {"id": "T1592", "name": "Gather Victim Host Info", "detections": 2, "coverage": 0.4},
    ]},
    "resource_development": {"id": "TA0042", "techniques": [
        {"id": "T1583", "name": "Acquire Infrastructure", "detections": 1, "coverage": 0.2},
        {"id": "T1587", "name": "Develop Capabilities", "detections": 0, "coverage": 0.0},
    ]},
    "initial_access": {"id": "TA0001", "techniques": [
        {"id": "T1566", "name": "Phishing", "detections": 8, "coverage": 0.8},
        {"id": "T1190", "name": "Exploit Public-Facing Application", "detections": 5, "coverage": 0.5},
        {"id": "T1078", "name": "Valid Accounts", "detections": 6, "coverage": 0.6},
    ]},
    "execution": {"id": "TA0002", "techniques": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "detections": 12, "coverage": 0.9},
        {"id": "T1204", "name": "User Execution", "detections": 7, "coverage": 0.7},
    ]},
    "persistence": {"id": "TA0003", "techniques": [
        {"id": "T1547", "name": "Boot or Logon Autostart Execution", "detections": 4, "coverage": 0.4},
        {"id": "T1053", "name": "Scheduled Task/Job", "detections": 6, "coverage": 0.6},
    ]},
    "privilege_escalation": {"id": "TA0004", "techniques": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "detections": 5, "coverage": 0.5},
        {"id": "T1055", "name": "Process Injection", "detections": 3, "coverage": 0.3},
    ]},
    "defense_evasion": {"id": "TA0005", "techniques": [
        {"id": "T1055", "name": "Process Injection", "detections": 3, "coverage": 0.3},
        {"id": "T1070", "name": "Indicator Removal", "detections": 4, "coverage": 0.4},
        {"id": "T1564", "name": "Hide Artifacts", "detections": 2, "coverage": 0.2},
    ]},
    "credential_access": {"id": "TA0006", "techniques": [
        {"id": "T1003", "name": "OS Credential Dumping", "detections": 7, "coverage": 0.7},
        {"id": "T1110", "name": "Brute Force", "detections": 5, "coverage": 0.5},
    ]},
    "discovery": {"id": "TA0007", "techniques": [
        {"id": "T1082", "name": "System Information Discovery", "detections": 4, "coverage": 0.4},
        {"id": "T1069", "name": "Permission Groups Discovery", "detections": 2, "coverage": 0.2},
    ]},
    "lateral_movement": {"id": "TA0008", "techniques": [
        {"id": "T1021", "name": "Remote Services", "detections": 6, "coverage": 0.6},
        {"id": "T1550", "name": "Use Alternate Authentication Material", "detections": 3, "coverage": 0.3},
    ]},
    "collection": {"id": "TA0009", "techniques": [
        {"id": "T1005", "name": "Data from Local System", "detections": 2, "coverage": 0.2},
        {"id": "T1114", "name": "Email Collection", "detections": 1, "coverage": 0.1},
    ]},
    "command_and_control": {"id": "TA0011", "techniques": [
        {"id": "T1071", "name": "Application Layer Protocol", "detections": 8, "coverage": 0.8},
        {"id": "T1573", "name": "Encrypted Channel", "detections": 4, "coverage": 0.4},
        {"id": "T1095", "name": "Non-Application Layer Protocol", "detections": 2, "coverage": 0.2},
    ]},
    "exfiltration": {"id": "TA0010", "techniques": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "detections": 1, "coverage": 0.1},
        {"id": "T1567", "name": "Exfiltration Over Web Service", "detections": 2, "coverage": 0.2},
    ]},
    "impact": {"id": "TA0040", "techniques": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "detections": 3, "coverage": 0.3},
        {"id": "T1490", "name": "Inhibit System Recovery", "detections": 1, "coverage": 0.1},
    ]},
}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "mitre-mapper", "infrastructure": get_infrastructure_status()}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8009, reload=True)