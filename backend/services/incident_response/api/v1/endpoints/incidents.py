import uuid
import asyncio
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.dependencies import get_current_user, require_permissions
from core.elastic import elastic_client
from core.kafka import kafka_client
from core.redis import redis_client
from services.incident_response.models.schemas import (
    IncidentCreate, IncidentUpdate, IncidentResponse, IncidentTimelineEntry,
    PlaybookCreate, PlaybookResponse, PlaybookExecutionRequest,
    ResponseAction, ResponseActionResult, IncidentStats,
)
from common.models.base import Incident, Playbook, Alert, User

router = APIRouter(prefix="/incidents", tags=["Incident Response"])

MOCK_PLAYBOOKS: dict = {}
MOCK_RESPONSE_ACTIONS: dict = {}


@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assignee_id: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    query = select(Incident).where(Incident.org_id == org_id)

    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if assignee_id:
        query = query.where(Incident.assignee_id == assignee_id)
    if search:
        query = query.where(
            or_(
                Incident.title.ilike(f"%{search}%"),
                Incident.description.ilike(f"%{search}%"),
            )
        )

    query = query.order_by(Incident.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    return result.scalars().all()


@router.post("", response_model=IncidentResponse, status_code=201)
async def create_incident(
    body: IncidentCreate,
    current_user: dict = Depends(require_permissions(["incidents:write"])),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    incident = Incident(
        org_id=org_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        status="open",
        alert_ids=body.alert_ids,
        assignee_id=body.assignee_id,
        timeline=[{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "incident_created",
            "actor": current_user.get("sub"),
            "description": "Incident created",
        }],
    )
    session.add(incident)

    # Update linked alerts
    if body.alert_ids:
        for alert_id in body.alert_ids:
            alert_result = await session.execute(
                select(Alert).where(Alert.id == alert_id)
            )
            alert = alert_result.scalar_one_or_none()
            if alert:
                alert.status = "investigating"

    await session.commit()
    await session.refresh(incident)

    await kafka_client.send_event(
        "incident_created",
        {"incident_id": str(incident.id), "title": incident.title, "severity": incident.severity},
        source="incident-response",
    )

    return incident


@router.get("/stats", response_model=IncidentStats)
async def get_incident_stats(
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    result = await session.execute(
        select(Incident).where(Incident.org_id == org_id)
    )
    incidents = result.scalars().all()

    stats = {
        "total": len(incidents), "open": 0, "investigating": 0,
        "contained": 0, "resolved": 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0,
    }

    for inc in incidents:
        stats[inc.status] = stats.get(inc.status, 0) + 1
        stats[inc.severity] = stats.get(inc.severity, 0) + 1

    # Calculate average resolution time
    resolved_incs = [i for i in incidents if i.resolved_at and i.created_at]
    if resolved_incs:
        avg_resolution = sum(
            (i.resolved_at - i.created_at).total_seconds() / 3600
            for i in resolved_incs
        ) / len(resolved_incs)
        stats["avg_resolution_time_hours"] = round(avg_resolution, 1)
    else:
        stats["avg_resolution_time_hours"] = 0

    stats["avg_response_time_hours"] = 0  # Would need first response tracking

    return stats


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Get assignee name
    assignee_name = None
    if incident.assignee_id:
        user_result = await session.execute(
            select(User).where(User.id == incident.assignee_id)
        )
        user = user_result.scalar_one_or_none()
        if user:
            assignee_name = user.full_name

    return IncidentResponse(
        **incident.__dict__,
        alert_ids=list(incident.alert_ids) if incident.alert_ids else [],
        assignee_id=str(incident.assignee_id) if incident.assignee_id else None,
        assignee_name=assignee_name,
    )


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    body: IncidentUpdate,
    current_user: dict = Depends(require_permissions(["incidents:write"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    for field, value in body.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(incident, field, value)

    if body.status == "resolved":
        incident.resolved_at = datetime.now(timezone.utc)

    incident.timeline = (incident.timeline or []) + [{
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "incident_updated",
        "actor": current_user.get("sub"),
        "description": f"Updated: status={body.status}" if body.status else "Updated",
    }]

    await session.commit()
    await session.refresh(incident)
    return incident


@router.post("/{incident_id}/assign")
async def assign_incident(
    incident_id: str,
    assignee_id: str = Query(...),
    current_user: dict = Depends(require_permissions(["incidents:write"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    user_result = await session.execute(
        select(User).where(User.id == assignee_id)
    )
    if not user_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="User not found")

    incident.assignee_id = assignee_id
    incident.timeline = (incident.timeline or []) + [{
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "assigned",
        "actor": current_user.get("sub"),
        "description": f"Assigned to {assignee_id}",
    }]
    await session.commit()
    return {"message": "Incident assigned successfully"}


@router.post("/{incident_id}/respond")
async def respond_to_incident(
    incident_id: str,
    action: ResponseAction,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permissions(["incidents:respond"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    action_id = str(uuid.uuid4())
    MOCK_RESPONSE_ACTIONS[action_id] = ResponseActionResult(
        action_id=action_id,
        action_type=action.action_type,
        target=action.target,
        status="pending",
        started_at=datetime.now(timezone.utc),
    )

    incident.timeline = (incident.timeline or []) + [{
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": f"response:{action.action_type}",
        "actor": current_user.get("sub"),
        "description": f"Executing {action.action_type} on {action.target}: {action.reason}",
    }]
    await session.commit()

    background_tasks.add_task(execute_response_action, action_id, action)

    return {"action_id": action_id, "status": "pending", "message": f"Response action {action.action_type} initiated"}


@router.get("/actions/{action_id}", response_model=ResponseActionResult)
async def get_action_status(action_id: str):
    action = MOCK_RESPONSE_ACTIONS.get(action_id)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    return action


# Playbooks
@router.get("/playbooks", response_model=List[PlaybookResponse])
async def list_playbooks(
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    result = await session.execute(
        select(Playbook).where(Playbook.org_id == org_id)
    )
    return result.scalars().all()


@router.post("/playbooks", response_model=PlaybookResponse, status_code=201)
async def create_playbook(
    body: PlaybookCreate,
    current_user: dict = Depends(require_permissions(["playbooks:write"])),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    playbook = Playbook(
        org_id=org_id,
        name=body.name,
        description=body.description,
        trigger_type=body.trigger_type,
        trigger_config=body.trigger_config,
        steps=body.steps,
    )
    session.add(playbook)
    await session.commit()
    await session.refresh(playbook)
    return playbook


@router.post("/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str,
    request: PlaybookExecutionRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permissions(["playbooks:execute"])),
    session: AsyncSession = Depends(get_session),
):
    playbook_result = await session.execute(
        select(Playbook).where(Playbook.id == playbook_id)
    )
    playbook = playbook_result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    incident_result = await session.execute(
        select(Incident).where(Incident.id == request.incident_id)
    )
    incident = incident_result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    execution_id = str(uuid.uuid4())
    background_tasks.add_task(
        run_playbook_steps, playbook, incident, request.parameters, execution_id
    )

    return {"execution_id": execution_id, "message": f"Playbook '{playbook.name}' execution started"}


async def execute_response_action(action_id: str, action: ResponseAction):
    MOCK_RESPONSE_ACTIONS[action_id].status = "executing"
    await asyncio.sleep(2)

    try:
        await kafka_client.send_event(
            f"response:{action.action_type}",
            {"action_id": action_id, "target": action.target, "parameters": action.parameters},
            source="incident-response",
        )
        MOCK_RESPONSE_ACTIONS[action_id].status = "completed"
        MOCK_RESPONSE_ACTIONS[action_id].completed_at = datetime.now(timezone.utc)
        MOCK_RESPONSE_ACTIONS[action_id].result = {"success": True, "message": f"{action.action_type} executed on {action.target}"}
    except Exception as e:
        MOCK_RESPONSE_ACTIONS[action_id].status = "failed"
        MOCK_RESPONSE_ACTIONS[action_id].error = str(e)


async def run_playbook_steps(playbook: Playbook, incident: Incident, parameters: dict, execution_id: str):
    for step in playbook.steps:
        action_type = step.get("action")
        target = step.get("target")
        await asyncio.sleep(1)
        await kafka_client.send_event(
            f"playbook_step:{action_type}",
            {"execution_id": execution_id, "step": step, "incident_id": str(incident.id)},
            source="incident-response",
        )
