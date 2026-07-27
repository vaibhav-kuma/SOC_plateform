from datetime import datetime
from typing import List, Optional, Any, Dict
from uuid import UUID
from pydantic import BaseModel, Field


class IOCRequest(BaseModel):
    ioc_type: str = Field(..., pattern=r"^(ip|domain|hash|url|email)$")
    ioc_value: str
    threat_score: float = Field(default=0.0, ge=0, le=100)
    source: str = "manual"
    tags: List[str] = []
    description: Optional[str] = None
    reference: Optional[str] = None


class IOCResponse(BaseModel):
    id: UUID
    ioc_type: str
    ioc_value: str
    threat_score: float
    source: str
    tags: List[str]
    is_active: bool
    first_seen: datetime
    last_seen: Optional[datetime] = None
    reputation: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class IOCBulkImport(BaseModel):
    iocs: List[IOCRequest]


class ThreatFeed(BaseModel):
    id: str
    name: str
    provider: str  # misp, otx, abuseipdb, virustotal
    status: str  # active, inactive, error
    last_sync: Optional[datetime] = None
    ioc_count: int
    refresh_interval_minutes: int = 60


class ThreatActor(BaseModel):
    id: str
    name: str
    aliases: List[str] = []
    motivation: Optional[str] = None
    country: Optional[str] = None
    first_seen: Optional[datetime] = None
    active: bool = True
    targeted_sectors: List[str] = []
    tools: List[str] = []
    malware: List[str] = []
    campaigns: List[str] = []


class IntelSearchRequest(BaseModel):
    query: str
    ioc_types: Optional[List[str]] = None
    sources: Optional[List[str]] = None
    min_score: Optional[float] = None
    max_results: int = 50


class EnrichmentResponse(BaseModel):
    ioc_value: str
    ioc_type: str
    threat_score: float
    sources_checked: List[str]
    findings: List[Dict[str, Any]]
    reputation: str  # malicious, suspicious, unknown, benign
    last_analysis: datetime
