import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from core.dependencies import get_current_user
from services.identity_security.models.schemas import (
    IdentityUser, IdentityUserDetail, IdentityAnomaly,
    PrivilegedAccount, IdentityStats, IdentityPolicy, IdentityPolicyCreate,
)

router = APIRouter(prefix="/identity", tags=["Identity Security"])

MOCK_USERS = [
    {"id": "usr-001", "username": "jdoe", "email": "jdoe@acme.com", "full_name": "John Doe", "department": "Engineering", "role": "admin", "risk_score": 15.2, "risk_level": "low", "mfa_enabled": True, "last_login": datetime.now(timezone.utc), "account_status": "active", "created_at": datetime(2024, 3, 1, 0, 0, 0), "recent_activity": [{"action": "login", "timestamp": datetime.now(timezone.utc).isoformat(), "ip": "10.0.1.42", "location": "Office-NYC"}, {"action": "git_push", "timestamp": datetime.now(timezone.utc).isoformat(), "repo": "backend-api"}], "risk_factors": [], "active_sessions": 2, "failed_login_attempts_24h": 0, "groups": ["engineering", "admins"], "permissions": ["users:read", "users:write", "settings:read"]},
    {"id": "usr-002", "username": "asmith", "email": "asmith@acme.com", "full_name": "Alice Smith", "department": "Finance", "role": "user", "risk_score": 45.7, "risk_level": "medium", "mfa_enabled": False, "last_login": datetime(2025, 6, 10, 3, 15, 0), "account_status": "active", "created_at": datetime(2024, 5, 12, 0, 0, 0), "recent_activity": [{"action": "login", "timestamp": "2025-06-10T03:15:00Z", "ip": "185.220.101.34", "location": "Unknown"}, {"action": "export_report", "timestamp": "2025-06-10T03:20:00Z", "report": "financial_q2"}], "risk_factors": ["Off-hours access (03:15)", "Login from unknown location"], "active_sessions": 1, "failed_login_attempts_24h": 3, "groups": ["finance"], "permissions": ["reports:read"]},
    {"id": "usr-003", "username": "bwilson", "email": "bwilson@acme.com", "full_name": "Bob Wilson", "department": "IT", "role": "admin", "risk_score": 72.3, "risk_level": "high", "mfa_enabled": True, "last_login": datetime.now(timezone.utc), "account_status": "active", "created_at": datetime(2023, 11, 20, 0, 0, 0), "recent_activity": [{"action": "sudo_exec", "timestamp": datetime.now(timezone.utc).isoformat(), "command": "useradd -G sudo temp_admin"}, {"action": "ssh_key_add", "timestamp": datetime.now(timezone.utc).isoformat(), "key_fingerprint": "SHA256:abc123"}], "risk_factors": ["Privilege escalation detected", "New SSH key added"], "active_sessions": 4, "failed_login_attempts_24h": 0, "groups": ["it", "admins", "security"], "permissions": ["*"]},
    {"id": "usr-004", "username": "ctaylor", "email": "ctaylor@acme.com", "full_name": "Carol Taylor", "department": "HR", "role": "user", "risk_score": 88.1, "risk_level": "critical", "mfa_enabled": False, "last_login": datetime(2025, 6, 15, 22, 45, 0), "account_status": "active", "created_at": datetime(2024, 8, 5, 0, 0, 0), "recent_activity": [{"action": "login", "timestamp": "2025-06-15T22:45:00Z", "ip": "203.0.113.50", "location": "Moscow, RU"}, {"action": "login", "timestamp": "2025-06-15T23:10:00Z", "ip": "10.0.5.12", "location": "Office-CHI"}, {"action": "bulk_export", "timestamp": "2025-06-15T23:15:00Z", "records": 12500}], "risk_factors": ["Impossible travel (NYC to Moscow in 10 min)", "MFA not enabled", "Bulk data export after hours"], "active_sessions": 2, "failed_login_attempts_24h": 8, "groups": ["hr"], "permissions": ["employee:read", "reports:read"]},
    {"id": "usr-005", "username": "dlee", "email": "dlee@acme.com", "full_name": "David Lee", "department": "Engineering", "role": "user", "risk_score": 5.0, "risk_level": "low", "mfa_enabled": True, "last_login": datetime.now(timezone.utc), "account_status": "active", "created_at": datetime(2025, 1, 15, 0, 0, 0), "recent_activity": [{"action": "login", "timestamp": datetime.now(timezone.utc).isoformat(), "ip": "10.0.1.50", "location": "Office-NYC"}, {"action": "code_review", "timestamp": datetime.now(timezone.utc).isoformat(), "repo": "frontend-app"}], "risk_factors": [], "active_sessions": 1, "failed_login_attempts_24h": 0, "groups": ["engineering"], "permissions": ["code:read", "code:write"]},
]

MOCK_ANOMALIES = [
    {"id": "anom-001", "user_id": "usr-004", "username": "ctaylor", "anomaly_type": "impossible_travel", "severity": "critical", "description": "User logged in from NYC and Moscow within 10 minutes", "detected_at": datetime(2025, 6, 15, 23, 20, 0), "investigated": False, "investigated_by": None, "investigation_notes": None, "risk_score_impact": 25.0, "metadata": {"ip_origin": "203.0.113.50", "ip_destination": "10.0.5.12", "distance_km": 7510, "time_diff_minutes": 10}},
    {"id": "anom-002", "user_id": "usr-002", "username": "asmith", "anomaly_type": "off_hours_access", "severity": "high", "description": "User accessed financial reports at 03:15 AM outside working hours", "detected_at": datetime(2025, 6, 10, 3, 20, 0), "investigated": False, "investigated_by": None, "investigation_notes": None, "risk_score_impact": 15.0, "metadata": {"hour": 3, "usual_hours": "09:00-18:00", "resource": "financial_q2_report"}},
    {"id": "anom-003", "user_id": "usr-003", "username": "bwilson", "anomaly_type": "privilege_escalation", "severity": "high", "description": "Admin created a new sudo user 'temp_admin' with elevated privileges", "detected_at": datetime(2025, 6, 16, 8, 5, 0), "investigated": False, "investigated_by": None, "investigation_notes": None, "risk_score_impact": 20.0, "metadata": {"command": "useradd -G sudo temp_admin", "target_user": "temp_admin", "timestamp": "2025-06-16T08:05:00Z"}},
]

MOCK_PRIVILEGED_ACCOUNTS = [
    {"id": "pa-001", "username": "root_svc", "full_name": "Root Service Account", "account_type": "service", "privilege_level": "superadmin", "mfa_enabled": False, "last_used": datetime(2025, 6, 16, 12, 0, 0), "password_age_days": 340, "has_api_key": True, "api_key_last_rotated": datetime(2024, 8, 1, 0, 0, 0), "risk_score": 65.0, "status": "active", "groups": ["domain_admins"]},
    {"id": "pa-002", "username": "bwilson", "full_name": "Bob Wilson", "account_type": "human", "privilege_level": "admin", "mfa_enabled": True, "last_used": datetime.now(timezone.utc), "password_age_days": 45, "has_api_key": False, "api_key_last_rotated": None, "risk_score": 72.3, "status": "active", "groups": ["it", "admins", "security"]},
    {"id": "pa-003", "username": "deploy_bot", "full_name": "Deployment Bot", "account_type": "service", "privilege_level": "admin", "mfa_enabled": False, "last_used": datetime(2025, 6, 15, 0, 0, 0), "password_age_days": 180, "has_api_key": True, "api_key_last_rotated": datetime(2025, 1, 1, 0, 0, 0), "risk_score": 30.0, "status": "active", "groups": ["deploy", "ci_cd"]},
]

MOCK_POLICIES = [
    {"id": "pol-001", "name": "Off-Hours Login Restriction", "description": "Block logins outside business hours for non-admin users", "policy_type": "access_control", "severity": "high", "conditions": {"time_range": {"start": "22:00", "end": "06:00"}, "apply_to_roles": ["user"], "exclude_mfa": True}, "actions": ["block_login", "notify_admin"], "enabled": True, "notify_channels": ["email", "slack"], "created_by": "admin", "created_at": datetime(2025, 1, 10, 0, 0, 0), "updated_at": datetime(2025, 6, 1, 0, 0, 0), "match_count": 23},
    {"id": "pol-002", "name": "Impossible Travel Detection", "description": "Flag accounts with logins from geographically impossible locations", "policy_type": "detection", "severity": "critical", "conditions": {"min_speed_kmh": 900, "lookback_minutes": 60}, "actions": ["flag_anomaly", "force_mfa_challenge", "notify_soc"], "enabled": True, "notify_channels": ["slack", "pagerduty"], "created_by": "soc_team", "created_at": datetime(2025, 2, 14, 0, 0, 0), "updated_at": datetime(2025, 5, 20, 0, 0, 0), "match_count": 7},
]


def _base_user_dict(u):
    return {k: v for k, v in u.items() if k in ("id", "username", "email", "full_name", "department", "role", "risk_score", "risk_level", "mfa_enabled", "last_login", "account_status", "created_at")}


@router.get("/users", response_model=List[IdentityUser])
async def list_users(
    risk_level: Optional[str] = None,
    department: Optional[str] = None,
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    users = MOCK_USERS
    if risk_level:
        users = [u for u in users if u["risk_level"] == risk_level]
    if department:
        users = [u for u in users if u["department"] == department]
    if status:
        users = [u for u in users if u["account_status"] == status]
    return [_base_user_dict(u) for u in users]


@router.get("/users/{user_id}", response_model=IdentityUserDetail)
async def get_user_detail(user_id: str, current_user: dict = Depends(get_current_user)):
    for u in MOCK_USERS:
        if u["id"] == user_id:
            return u
    raise HTTPException(status_code=404, detail="User not found")


@router.post("/users/{user_id}/risk-score")
async def recalculate_risk_score(user_id: str, current_user: dict = Depends(get_current_user)):
    for u in MOCK_USERS:
        if u["id"] == user_id:
            old_score = u["risk_score"]
            new_score = round(min(old_score + 5.0, 100.0), 1)
            u["risk_score"] = new_score
            if new_score >= 75:
                u["risk_level"] = "critical"
            elif new_score >= 50:
                u["risk_level"] = "high"
            elif new_score >= 25:
                u["risk_level"] = "medium"
            else:
                u["risk_level"] = "low"
            return {"user_id": user_id, "previous_risk_score": old_score, "new_risk_score": new_score, "risk_level": u["risk_level"], "recalculated_at": datetime.now(timezone.utc).isoformat()}
    raise HTTPException(status_code=404, detail="User not found")


@router.get("/anomalies", response_model=List[IdentityAnomaly])
async def list_anomalies(
    anomaly_type: Optional[str] = None,
    severity: Optional[str] = None,
    investigated: Optional[bool] = None,
    current_user: dict = Depends(get_current_user),
):
    anomalies = MOCK_ANOMALIES
    if anomaly_type:
        anomalies = [a for a in anomalies if a["anomaly_type"] == anomaly_type]
    if severity:
        anomalies = [a for a in anomalies if a["severity"] == severity]
    if investigated is not None:
        anomalies = [a for a in anomalies if a["investigated"] == investigated]
    return anomalies


@router.post("/anomalies/{anomaly_id}/investigate")
async def investigate_anomaly(anomaly_id: str, current_user: dict = Depends(get_current_user)):
    for a in MOCK_ANOMALIES:
        if a["id"] == anomaly_id:
            if a["investigated"]:
                raise HTTPException(status_code=400, detail="Anomaly already investigated")
            a["investigated"] = True
            a["investigated_by"] = current_user.get("sub", "unknown")
            a["investigation_notes"] = "Investigated and closed by analyst"
            return {"anomaly_id": anomaly_id, "status": "investigated", "investigated_by": a["investigated_by"], "timestamp": datetime.now(timezone.utc).isoformat()}
    raise HTTPException(status_code=404, detail="Anomaly not found")


@router.get("/privileged-accounts", response_model=List[PrivilegedAccount])
async def list_privileged_accounts(
    privilege_level: Optional[str] = None,
    account_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    accounts = MOCK_PRIVILEGED_ACCOUNTS
    if privilege_level:
        accounts = [a for a in accounts if a["privilege_level"] == privilege_level]
    if account_type:
        accounts = [a for a in accounts if a["account_type"] == account_type]
    return accounts


@router.get("/stats", response_model=IdentityStats)
async def get_identity_stats(current_user: dict = Depends(get_current_user)):
    critical = sum(1 for a in MOCK_ANOMALIES if a["severity"] == "critical")
    high = sum(1 for a in MOCK_ANOMALIES if a["severity"] == "high")
    investigated = sum(1 for a in MOCK_ANOMALIES if a["investigated"])
    pending = len(MOCK_ANOMALIES) - investigated
    mfa_count = sum(1 for u in MOCK_USERS if u["mfa_enabled"])
    high_risk = sum(1 for u in MOCK_USERS if u["risk_level"] in ("high", "critical"))
    avg_risk = round(sum(u["risk_score"] for u in MOCK_USERS) / len(MOCK_USERS), 1)
    active = sum(1 for u in MOCK_USERS if u["account_status"] == "active")
    inactive = sum(1 for u in MOCK_USERS if u["account_status"] != "active")
    active_pol = sum(1 for p in MOCK_POLICIES if p["enabled"])

    return IdentityStats(
        total_users=len(MOCK_USERS),
        active_users=active,
        inactive_users=inactive,
        total_anomalies=len(MOCK_ANOMALIES),
        critical_anomalies=critical,
        high_anomalies=high,
        investigated_anomalies=investigated,
        pending_anomalies=pending,
        privileged_accounts=len(MOCK_PRIVILEGED_ACCOUNTS),
        mfa_enforcement_rate=round(mfa_count / len(MOCK_USERS) * 100, 1),
        average_risk_score=avg_risk,
        high_risk_users=high_risk,
        total_policies=len(MOCK_POLICIES),
        active_policies=active_pol,
        blocked_users_24h=1,
        last_updated=datetime.now(timezone.utc),
    )


@router.post("/policies", response_model=IdentityPolicy, status_code=201)
async def create_policy(body: IdentityPolicyCreate, current_user: dict = Depends(get_current_user)):
    policy = {
        "id": f"pol-{uuid.uuid4().hex[:8]}",
        "name": body.name,
        "description": body.description,
        "policy_type": body.policy_type,
        "severity": body.severity,
        "conditions": body.conditions,
        "actions": body.actions,
        "enabled": body.enabled,
        "notify_channels": body.notify_channels,
        "created_by": current_user.get("sub", "unknown"),
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
        "match_count": 0,
    }
    MOCK_POLICIES.append(policy)
    return policy


@router.get("/policies", response_model=List[IdentityPolicy])
async def list_policies(
    policy_type: Optional[str] = None,
    enabled: Optional[bool] = None,
    current_user: dict = Depends(get_current_user),
):
    policies = MOCK_POLICIES
    if policy_type:
        policies = [p for p in policies if p["policy_type"] == policy_type]
    if enabled is not None:
        policies = [p for p in policies if p["enabled"] == enabled]
    return policies
