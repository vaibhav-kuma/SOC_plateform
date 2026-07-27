from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field


class HuntingQueryCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=2000)
    query: str = Field(..., min_length=1)
    data_sources: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class HuntingQuery(BaseModel):
    id: str
    title: str
    description: str
    query: str
    data_sources: List[str]
    tags: List[str]
    mitre_techniques: List[str]
    status: str = "draft"
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class HuntingQueryResponse(HuntingQuery):
    last_run: Optional[datetime] = None
    result_count: int = 0


class HuntingResult(BaseModel):
    id: str
    query_id: str
    matched_events: List[Dict[str, Any]]
    total_matches: int
    severity: str
    execution_time_ms: int
    created_at: datetime


class HypothesisCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=2000)
    mitre_techniques: List[str] = Field(default_factory=list)
    status: str = Field(default="active", pattern=r"^(active|investigating|confirmed|dismissed)$")


class Hypothesis(BaseModel):
    id: str
    title: str
    description: str
    mitre_techniques: List[str]
    status: str
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class HuntingStats(BaseModel):
    total_queries: int
    active_queries: int
    archived_queries: int
    total_hypotheses: int
    active_hypotheses: int
    suspicious_findings: int
    total_results: int
    queries_by_data_source: Dict[str, int]
    queries_by_mitre_technique: Dict[str, int]
