from datetime import datetime
from typing import List, Optional, Any, Dict
from uuid import UUID
from pydantic import BaseModel, Field


class IncidentCreate(BaseModel):
    title: str = Field(min_length=1)
    description: Optional[str] = None
    severity: str = Field(default="medium", pattern=r"^(critical|high|medium|low|info)$")
    alert_ids: List[str] = []
    assignee_id: Optional[str] = None
    tags: List[str] = []


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    assignee_id: Optional[str] = None
    tags: Optional[List[str]] = None


class IncidentResponse(BaseModel):
    id: UUID
    title: str
    description: Optional[str]
    severity: str
    status: str
    alert_ids: List[str]
    assignee_id: Optional[str]
    assignee_name: Optional[str] = None
    playbook_id: Optional[str]
    timeline: List[Dict[str, Any]]
    tags: List[str]
    ai_narrative: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]

    class Config:
        from_attributes = True


class IncidentTimelineEntry(BaseModel):
    timestamp: datetime
    action: str
    actor: str
    description: str
    details: Optional[Dict[str, Any]] = None


class PlaybookCreate(BaseModel):
    name: str = Field(min_length=1)
    description: Optional[str] = None
    trigger_type: str  # alert_severity, alert_source, manual
    trigger_config: Optional[Dict[str, Any]] = None
    steps: List[Dict[str, Any]]
    is_active: bool = True


class PlaybookResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    trigger_type: str
    steps: List[Dict[str, Any]]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class PlaybookExecutionRequest(BaseModel):
    playbook_id: str
    incident_id: str
    parameters: Optional[Dict[str, Any]] = None


class ResponseAction(BaseModel):
    action_type: str  # isolate_endpoint, kill_process, block_ip, block_domain, disable_user, revoke_tokens, quarantine_file
    target: str
    parameters: Optional[Dict[str, Any]] = None
    reason: str


class ResponseActionResult(BaseModel):
    action_id: str
    action_type: str
    target: str
    status: str  # pending, executing, completed, failed
    started_at: datetime
    completed_at: Optional[datetime]
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class IncidentStats(BaseModel):
    total: int
    open: int
    investigating: int
    contained: int
    resolved: int
    critical: int
    high: int
    medium: int
    low: int
    avg_response_time_hours: float
    avg_resolution_time_hours: float
