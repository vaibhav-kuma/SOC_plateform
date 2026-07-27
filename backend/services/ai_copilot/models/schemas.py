from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str  # user, assistant, system
    content: str
    timestamp: Optional[datetime] = None


class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None  # alert_id, incident_id, asset_id


class ChatResponse(BaseModel):
    response: str
    conversation_id: str
    sources: Optional[List[Dict[str, Any]]] = None
    suggestions: Optional[List[str]] = None
    actions: Optional[List[Dict[str, Any]]] = None


class InvestigationRequest(BaseModel):
    alert_id: str
    include_logs: bool = True
    include_intel: bool = True
    time_range_hours: int = 24


class InvestigationResponse(BaseModel):
    alert_id: str
    summary: str
    root_cause: str
    impact_assessment: str
    affected_assets: List[Dict[str, Any]]
    mitre_techniques: List[str]
    kill_chain_phase: Optional[str]
    recommended_actions: List[str]
    timeline: List[Dict[str, Any]]
    confidence_score: float
    generated_at: datetime


class IncidentSummaryRequest(BaseModel):
    incident_id: str


class IncidentSummaryResponse(BaseModel):
    incident_id: str
    executive_summary: str
    technical_details: str
    attack_timeline: str
    impacted_systems: List[str]
    indicators: List[Dict[str, Any]]
    remediation_steps: List[str]
    lessons_learned: Optional[str]


class ReportRequest(BaseModel):
    report_type: str  # incident, executive, compliance, threat_brief
    incident_ids: Optional[List[str]] = None
    time_range_days: int = 7
    format: str = "markdown"


class ThreatExplanation(BaseModel):
    alert_title: str
    what_happened: str
    why_it_matters: str
    how_it_works: str
    mitre_details: Optional[Dict[str, Any]] = None
    severity_explanation: str


class AIQueryRequest(BaseModel):
    query: str
    context: Optional[Dict[str, Any]] = None


class AIQueryResponse(BaseModel):
    answer: str
    confidence: float
    related_alerts: Optional[List[Dict[str, Any]]] = None
    related_assets: Optional[List[Dict[str, Any]]] = None
    data_sources_used: List[str]
