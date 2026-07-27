from datetime import datetime
from typing import List, Optional, Any, Dict
from uuid import UUID
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    asset_ids: Optional[List[UUID]] = None
    targets: Optional[List[str]] = None
    scan_type: str = Field(default="quick", pattern=r"^(quick|full|web|container|cloud)$")
    engines: List[str] = Field(default=["nuclei"], description="nuclei, nmap_vuln, trivy, zap")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    targets_count: int
    created_at: datetime


class VulnerabilityResponse(BaseModel):
    id: UUID
    asset_id: UUID
    cve_id: Optional[str]
    cvss_score: Optional[float]
    severity: str
    description: str
    exploit_available: bool
    remediation: Optional[str]
    status: str
    ai_explanation: Optional[Dict[str, Any]] = None
    discovered_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityDetailResponse(VulnerabilityResponse):
    asset_hostname: Optional[str]
    asset_ip: Optional[str]
    proof: Optional[str]  # Evidence of the vulnerability
    references: List[str] = []
    cwe_id: Optional[str]
    affected_component: Optional[str]
    patch_available: bool
    ai_business_impact: Optional[str]
    ai_exploitation_risk: Optional[str]
    ai_fix_recommendation: Optional[str]


class VulnStatsResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    by_type: Dict[str, int]
    top_cves: List[Dict[str, Any]]
    avg_cvss: float
    patched_percentage: float


class CVEResponse(BaseModel):
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    affected_assets: int
    exploit_available: bool
    published_date: Optional[datetime]
    references: List[str]


class VulnAIAnalysis(BaseModel):
    cve_id: str
    ai_description: str
    exploitation_risk: str
    business_impact: str
    fix_recommendations: str
    priority_score: int
    estimated_patch_time_hours: float
