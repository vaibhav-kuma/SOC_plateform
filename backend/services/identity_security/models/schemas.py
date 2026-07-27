from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


class IdentityUser(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    department: str
    role: str
    risk_score: float
    risk_level: str
    mfa_enabled: bool
    last_login: Optional[datetime] = None
    account_status: str
    created_at: datetime


class IdentityUserDetail(BaseModel):
    id: str
    username: str
    email: str
    full_name: str
    department: str
    role: str
    risk_score: float
    risk_level: str
    mfa_enabled: bool
    last_login: Optional[datetime] = None
    account_status: str
    created_at: datetime
    recent_activity: List[dict]
    risk_factors: List[str]
    active_sessions: int
    failed_login_attempts_24h: int
    groups: List[str]
    permissions: List[str]


class IdentityAnomaly(BaseModel):
    id: str
    user_id: str
    username: str
    anomaly_type: str
    severity: str
    description: str
    detected_at: datetime
    investigated: bool
    investigated_by: Optional[str] = None
    investigation_notes: Optional[str] = None
    risk_score_impact: float
    metadata: dict


class PrivilegedAccount(BaseModel):
    id: str
    username: str
    full_name: str
    account_type: str
    privilege_level: str
    mfa_enabled: bool
    last_used: Optional[datetime] = None
    password_age_days: int
    has_api_key: bool
    api_key_last_rotated: Optional[datetime] = None
    risk_score: float
    status: str
    groups: List[str]


class IdentityStats(BaseModel):
    total_users: int
    active_users: int
    inactive_users: int
    total_anomalies: int
    critical_anomalies: int
    high_anomalies: int
    investigated_anomalies: int
    pending_anomalies: int
    privileged_accounts: int
    mfa_enforcement_rate: float
    average_risk_score: float
    high_risk_users: int
    total_policies: int
    active_policies: int
    blocked_users_24h: int
    last_updated: datetime


class IdentityPolicyCreate(BaseModel):
    name: str
    description: str
    policy_type: str
    severity: str
    conditions: dict
    actions: List[str]
    enabled: bool
    notify_channels: List[str]


class IdentityPolicy(BaseModel):
    id: str
    name: str
    description: str
    policy_type: str
    severity: str
    conditions: dict
    actions: List[str]
    enabled: bool
    notify_channels: List[str]
    created_by: str
    created_at: datetime
    updated_at: datetime
    match_count: int
