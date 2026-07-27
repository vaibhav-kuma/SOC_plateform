import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.dependencies import get_current_user, require_permissions
from core.elastic import elastic_client
from core.kafka import kafka_client
from core.redis import redis_client
from services.edr_service.models.schemas import (
    EndpointEvent, EndpointResponse, EndpointDetailResponse,
    IsolationRequest, ProcessKillRequest, IOCBlockRequest,
    EndpointAlert,
)

router = APIRouter(prefix="/endpoints", tags=["EDR"])


# In-memory store for mock endpoints (replace with DB in production)
MOCK_ENDPOINTS = {}


@router.get("", response_model=List[EndpointResponse])
async def list_endpoints(
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: dict = Depends(get_current_user),
):
    org_id = current_user.get("org_id")
    # Return mock data for development
    if not MOCK_ENDPOINTS:
        MOCK_ENDPOINTS[str(uuid.uuid4())] = {
            "id": str(uuid.uuid4()),
            "hostname": "WKS-001",
            "ip_address": "10.0.1.101",
            "os": "Windows 11",
            "os_version": "23H2",
            "status": "online",
            "agent_version": "1.0.0",
            "last_seen": datetime.now(timezone.utc),
            "isolation_status": "none",
            "risk_score": 3.2,
        }
        MOCK_ENDPOINTS[str(uuid.uuid4())] = {
            "id": str(uuid.uuid4()),
            "hostname": "WKS-002",
            "ip_address": "10.0.1.102",
            "os": "Windows 10",
            "os_version": "22H2",
            "status": "online",
            "agent_version": "1.0.0",
            "last_seen": datetime.now(timezone.utc),
            "isolation_status": "none",
            "risk_score": 7.8,
        }
        MOCK_ENDPOINTS[str(uuid.uuid4())] = {
            "id": str(uuid.uuid4()),
            "hostname": "SRV-DC01",
            "ip_address": "10.0.0.10",
            "os": "Windows Server 2022",
            "os_version": "21H2",
            "status": "online",
            "agent_version": "1.0.0",
            "last_seen": datetime.now(timezone.utc),
            "isolation_status": "none",
            "risk_score": 9.1,
        }

    endpoints = list(MOCK_ENDPOINTS.values())
    if status:
        endpoints = [e for e in endpoints if e["status"] == status]
    if search:
        endpoints = [e for e in endpoints if search.lower() in e["hostname"].lower()]

    return endpoints


@router.get("/{endpoint_id}", response_model=EndpointDetailResponse)
async def get_endpoint(endpoint_id: str, current_user: dict = Depends(get_current_user)):
    endpoint = MOCK_ENDPOINTS.get(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return EndpointDetailResponse(
        **endpoint,
        running_processes=[
            {"pid": 1234, "name": "powershell.exe", "user": "SYSTEM", "cpu": 2.1, "memory": 45.6},
            {"pid": 5678, "name": "cmd.exe", "user": "jdoe", "cpu": 0.5, "memory": 12.3},
        ],
        network_connections=[
            {"local_ip": "10.0.1.101", "local_port": 54321, "remote_ip": "185.234.72.1", "remote_port": 443, "state": "established"},
        ],
        recent_alerts=[
            {"id": "alert-001", "title": "Suspicious PowerShell Execution", "severity": "high", "timestamp": datetime.now(timezone.utc).isoformat()},
        ],
        installed_applications=["Python 3.12", "Chrome 120", "Office 365", "Sysmon 15.0"],
    )


@router.post("/{endpoint_id}/isolate")
async def isolate_endpoint(
    endpoint_id: str,
    body: IsolationRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permissions(["edr:isolate"])),
):
    endpoint = MOCK_ENDPOINTS.get(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    endpoint["isolation_status"] = "isolated"
    endpoint["status"] = "isolated"

    await kafka_client.send_event(
        "endpoint_isolated",
        {"endpoint_id": endpoint_id, "hostname": endpoint["hostname"], "reason": body.reason},
        source="edr-service",
    )

    return {
        "message": f"Endpoint {endpoint['hostname']} isolated",
        "isolation_status": "isolated",
        "duration_minutes": body.duration_minutes,
    }


@router.post("/{endpoint_id}/release")
async def release_endpoint(
    endpoint_id: str,
    current_user: dict = Depends(require_permissions(["edr:isolate"])),
):
    endpoint = MOCK_ENDPOINTS.get(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    endpoint["isolation_status"] = "none"
    endpoint["status"] = "online"
    return {"message": f"Endpoint {endpoint['hostname']} released from isolation"}


@router.post("/{endpoint_id}/kill-process")
async def kill_process(
    endpoint_id: str,
    body: ProcessKillRequest,
    current_user: dict = Depends(require_permissions(["edr:kill"])),
):
    endpoint = MOCK_ENDPOINTS.get(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    await kafka_client.send_event(
        "process_killed",
        {"endpoint_id": endpoint_id, "process_name": body.process_name, "process_id": body.process_id},
        source="edr-service",
    )

    return {"message": f"Process {body.process_name} (PID: {body.process_id}) terminated"}


@router.post("/{endpoint_id}/block-ioc")
async def block_ioc(
    endpoint_id: str,
    body: IOCBlockRequest,
    current_user: dict = Depends(require_permissions(["edr:block"])),
):
    endpoint = MOCK_ENDPOINTS.get(endpoint_id)
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    await kafka_client.send_event(
        "ioc_blocked",
        {"endpoint_id": endpoint_id, "ioc_type": body.ioc_type, "ioc_value": body.ioc_value},
        source="edr-service",
    )

    return {"message": f"IOC {body.ioc_value} blocked on {endpoint['hostname']}"}


@router.post("/events/ingest")
async def ingest_event(
    event: EndpointEvent,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
):
    # Index event to Elasticsearch
    await elastic_client.index(
        f"edr-events-{datetime.now().strftime('%Y-%m-%d')}",
        event.model_dump(),
    )

    # Run detection rules
    background_tasks.add_task(run_detection_rules, event)

    return {"message": "Event ingested", "event_type": event.event_type}


async def run_detection_rules(event: EndpointEvent):
    # Sigma rule matching would happen here
    # For MVP, check for common suspicious patterns

    detections = []

    # 1. Suspicious PowerShell
    if event.process_name and "powershell" in event.process_name.lower():
        suspicious_indicators = [
            "-enc", "-e ", "base64", "bypass", "hidden",
            "downloadstring", "invoke-expression", "iex",
        ]
        if event.command_line and any(ind in event.command_line.lower() for ind in suspicious_indicators):
            detections.append({
                "title": "Suspicious PowerShell Execution",
                "category": "living_off_land",
                "severity": "high",
                "mitre": "T1059.001",
                "description": f"PowerShell with suspicious flags detected: {event.command_line[:200]}",
            })

    # 2. Malicious IP connection
    known_bad_ips = ["185.234.72.1", "45.33.32.156", "103.235.46.1"]
    if event.destination_ip and event.destination_ip in known_bad_ips:
        detections.append({
            "title": "Connection to Known Malicious IP",
            "category": "c2",
            "severity": "critical",
            "mitre": "T1071",
            "description": f"Process {event.process_name} connected to known malicious IP {event.destination_ip}",
        })

    # 3. LSASS Access (credential dumping)
    if event.process_name and "lsass" in event.process_name.lower():
        detections.append({
            "title": "Potential Credential Dumping - LSASS Access",
            "category": "credential_dumping",
            "severity": "critical",
            "mitre": "T1003.001",
            "description": "Process accessing LSASS potentially indicating credential dumping",
        })

    # Send detections to Kafka
    for detection in detections:
        alert = {
            "id": str(uuid.uuid4()),
            "source": "edr",
            "title": detection["title"],
            "description": detection["description"],
            "severity": detection["severity"],
            "category": detection["category"],
            "mitre_technique": detection["mitre"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_data": event.model_dump(),
            "status": "new",
        }
        await kafka_client.send_alert(alert)
