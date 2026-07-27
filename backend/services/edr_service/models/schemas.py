from datetime import datetime
from typing import List, Optional, Any, Dict
from uuid import UUID
from pydantic import BaseModel, Field


class EndpointEvent(BaseModel):
    event_type: str  # process, network, file, registry, dns
    timestamp: datetime
    hostname: str
    os: str
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    registry_key: Optional[str] = None
    registry_value: Optional[str] = None
    dns_query: Optional[str] = None
    dns_response: Optional[str] = None


class EndpointResponse(BaseModel):
    id: UUID
    hostname: str
    ip_address: Optional[str]
    os: str
    os_version: Optional[str]
    status: str  # online, offline, isolated
    agent_version: Optional[str]
    last_seen: datetime
    isolation_status: str = "none"
    risk_score: float = 0.0

    class Config:
        from_attributes = True


class EndpointDetailResponse(EndpointResponse):
    running_processes: List[Dict[str, Any]] = []
    network_connections: List[Dict[str, Any]] = []
    recent_alerts: List[Dict[str, Any]] = []
    installed_applications: List[str] = []


class IsolationRequest(BaseModel):
    reason: str = Field(min_length=1)
    duration_minutes: Optional[int] = 60


class ProcessKillRequest(BaseModel):
    process_id: int
    process_name: str
    reason: str


class IOCBlockRequest(BaseModel):
    ioc_type: str  # ip, domain, hash, process
    ioc_value: str
    reason: str


class DetectionRule(BaseModel):
    name: str
    description: str
    category: str  # malware, ransomware, persistence, lateral_movement, etc.
    mitre_technique_id: Optional[str] = None
    sigma_rule: Optional[str] = None
    severity: str
    enabled: bool = True


class EndpointAlert(BaseModel):
    id: str
    endpoint_id: str
    title: str
    description: str
    severity: str
    category: str
    mitre_technique: Optional[str]
    process_name: Optional[str]
    user: Optional[str]
    command_line: Optional[str]
    timestamp: datetime
    status: str = "new"
