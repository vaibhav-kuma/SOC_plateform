from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional


class EmailAnalysisRequest(BaseModel):
    from_: str = Field(..., alias="from")
    to: str
    subject: str
    body: str
    headers: dict = Field(default_factory=dict)

    class Config:
        populate_by_name = True


class EmailFinding(BaseModel):
    type: str
    severity: str
    description: str


class EmailAnalysis(BaseModel):
    id: str
    request: EmailAnalysisRequest
    risk_score: float = Field(ge=0, le=1)
    is_phishing: bool
    findings: list[EmailFinding] = Field(default_factory=list)
    analyzed_at: datetime


class EmailThreat(BaseModel):
    id: str
    type: str
    severity: str
    message_id: str
    detected_at: datetime
    status: str
    description: str


class EmailMessage(BaseModel):
    id: str
    from_: str = Field(..., alias="from")
    to: str
    subject: str
    body: str
    headers: dict = Field(default_factory=dict)
    risk_level: str
    risk_score: float
    status: str
    analyzed_at: datetime
    threats: list[EmailThreat] = Field(default_factory=list)

    class Config:
        populate_by_name = True


class EmailStats(BaseModel):
    total_analyzed: int
    threats_detected: int
    false_positives: int
    quarantined: int
    risk_levels: dict[str, int]


class EmailPolicyRule(BaseModel):
    check_spf: bool = True
    check_dkim: bool = True
    check_dmarc: bool = True
    quarantine_score_threshold: float = 0.7
    block_attachments: bool = False
    allowed_domains: list[str] = Field(default_factory=list)
    blocked_domains: list[str] = Field(default_factory=list)


class EmailPolicyCreate(BaseModel):
    name: str
    description: str = ""
    rules: EmailPolicyRule = Field(default_factory=EmailPolicyRule)


class EmailPolicy(BaseModel):
    id: str
    name: str
    description: str
    rules: EmailPolicyRule
    enabled: bool = True
    created_at: datetime
    updated_at: datetime
