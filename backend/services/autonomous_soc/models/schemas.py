from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class PlaybookType(str, Enum):
    ENRICH = "enrich"
    CONTAIN = "contain"
    ERADICATE = "eradicate"
    RECOVER = "recover"


class PlaybookSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionStatus(str, Enum):
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    CANCELLED = "cancelled"


class PlaybookBase(BaseModel):
    name: str
    description: Optional[str] = None
    playbook_type: PlaybookType
    trigger_type: str
    conditions: Dict[str, Any]
    actions: List[str]
    severity: PlaybookSeverity
    enabled: bool = True


class PlaybookCreate(PlaybookBase):
    pass


class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    playbook_type: Optional[PlaybookType] = None
    trigger_type: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    actions: Optional[List[str]] = None
    severity: Optional[PlaybookSeverity] = None
    enabled: Optional[bool] = None


class Playbook(PlaybookBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ExecutionLog(BaseModel):
    step: str
    action: str
    status: str
    message: str
    timestamp: datetime


class Execution(BaseModel):
    id: str
    playbook_id: str
    playbook_name: str
    status: ExecutionStatus
    triggered_by: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ExecutionDetail(Execution):
    logs: List[ExecutionLog] = []
    trigger_event: Optional[Dict[str, Any]] = None
    output: Optional[Dict[str, Any]] = None


class CorrelationRuleBase(BaseModel):
    name: str
    description: Optional[str] = None
    rule_type: str
    conditions: Dict[str, Any]
    severity: PlaybookSeverity
    enabled: bool = True


class CorrelationRuleCreate(CorrelationRuleBase):
    pass


class CorrelationRule(CorrelationRuleBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TopPlaybook(BaseModel):
    id: str
    name: str
    execution_count: int
    success_rate: float


class ExecutionTrendPoint(BaseModel):
    date: str
    total: int
    success: int
    failed: int


class AutonomousStats(BaseModel):
    total_playbooks: int
    enabled_playbooks: int
    total_executions: int
    success_rate: float
    fail_rate: float
    running_executions: int
    pending_executions: int
    active_rules: int
    top_triggered_playbooks: List[TopPlaybook]
    execution_trend: List[ExecutionTrendPoint]
    executions_last_24h: int
    avg_duration_seconds: float
