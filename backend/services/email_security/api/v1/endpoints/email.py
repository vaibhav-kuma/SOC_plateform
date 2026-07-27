from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from core.dependencies import get_current_user
from models.schemas import (
    EmailAnalysisRequest,
    EmailMessage,
    EmailThreat,
    EmailStats,
    EmailPolicy,
    EmailPolicyCreate,
)

router = APIRouter()

_messages: list[EmailMessage] = [
    EmailMessage(
        id="msg-001",
        from_="attacker@phish-example.com",
        to="user@company.com",
        subject="Urgent: Verify your account",
        body="Click here to verify your account credentials immediately.",
        headers={"reply-to": "malicious@evil.com", "spf": "fail", "dkim": "fail", "dmarc": "fail"},
        risk_level="critical",
        risk_score=0.95,
        status="quarantined",
        analyzed_at=datetime.now() - timedelta(hours=2),
        threats=[
            EmailThreat(id="threat-001", type="phishing", severity="critical", message_id="msg-001", detected_at=datetime.now() - timedelta(hours=2), status="active", description="Suspicious link with typosquatted domain"),
            EmailThreat(id="threat-002", type="spoofing", severity="high", message_id="msg-001", detected_at=datetime.now() - timedelta(hours=2), status="active", description="SPF and DKIM authentication failed"),
        ],
    ),
    EmailMessage(
        id="msg-002",
        from_="vendor@trusted-partner.com",
        to="user@company.com",
        subject="Invoice attached",
        body="Please find the invoice for last month's services attached.",
        headers={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        risk_level="safe",
        risk_score=0.05,
        status="analyzed",
        analyzed_at=datetime.now() - timedelta(hours=5),
        threats=[],
    ),
    EmailMessage(
        id="msg-003",
        from_="ceo@company.com",
        to="finance@company.com",
        subject="Urgent wire transfer",
        body="I need you to process an urgent wire transfer of $50,000 to the following account.",
        headers={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        risk_level="high",
        risk_score=0.78,
        status="analyzed",
        analyzed_at=datetime.now() - timedelta(hours=1),
        threats=[
            EmailThreat(id="threat-003", type="bec", severity="high", message_id="msg-003", detected_at=datetime.now() - timedelta(hours=1), status="active", description="Impersonation of internal executive requesting wire transfer"),
        ],
    ),
    EmailMessage(
        id="msg-004",
        from_="unknown@malware-bait.net",
        to="user@company.com",
        subject="Your package is waiting",
        body="Track your package here: http://evil.com/track",
        headers={"spf": "neutral", "dkim": "fail", "dmarc": "fail"},
        risk_level="medium",
        risk_score=0.62,
        status="reported",
        analyzed_at=datetime.now() - timedelta(hours=8),
        threats=[
            EmailThreat(id="threat-004", type="malware", severity="medium", message_id="msg-004", detected_at=datetime.now() - timedelta(hours=8), status="active", description="URL points to known malware distribution domain"),
        ],
    ),
    EmailMessage(
        id="msg-005",
        from_="newsletter@marketing-email.com",
        to="user@company.com",
        subject="Monthly newsletter",
        body="Here is your monthly update with the latest news.",
        headers={"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        risk_level="low",
        risk_score=0.15,
        status="analyzed",
        analyzed_at=datetime.now() - timedelta(days=1),
        threats=[],
    ),
]

_policies: list[EmailPolicy] = [
    EmailPolicy(
        id="policy-001",
        name="Strict inbound policy",
        description="Strict SPF/DKIM/DMARC enforcement with low quarantine threshold",
        rules={"check_spf": True, "check_dkim": True, "check_dmarc": True, "quarantine_score_threshold": 0.6, "block_attachments": True, "allowed_domains": [], "blocked_domains": ["phish-example.com", "malware-bait.net"]},
        enabled=True,
        created_at=datetime.now() - timedelta(days=30),
        updated_at=datetime.now() - timedelta(days=7),
    ),
    EmailPolicy(
        id="policy-002",
        name="Internal communication policy",
        description="Relaxed checks for internal domains, strict for external",
        rules={"check_spf": True, "check_dkim": False, "check_dmarc": False, "quarantine_score_threshold": 0.85, "block_attachments": False, "allowed_domains": ["company.com"], "blocked_domains": []},
        enabled=True,
        created_at=datetime.now() - timedelta(days=60),
        updated_at=datetime.now() - timedelta(days=1),
    ),
]


@router.post("/analyze")
async def analyze_email(request: EmailAnalysisRequest, current_user: dict = Depends(get_current_user)):
    risk_score = 0.0
    findings = []
    is_phishing = False
    headers = request.headers

    if headers.get("spf") == "fail":
        risk_score += 0.3
        findings.append({"type": "spoofing", "severity": "high", "description": "SPF check failed"})
    if headers.get("dkim") == "fail":
        risk_score += 0.25
        findings.append({"type": "spoofing", "severity": "high", "description": "DKIM signature verification failed"})
    if headers.get("dmarc") == "fail":
        risk_score += 0.2
        findings.append({"type": "spoofing", "severity": "medium", "description": "DMARC policy check failed"})

    suspicious_keywords = ["urgent", "verify", "account", "password", "click here", "wire transfer", "suspended"]
    body_lower = request.body.lower()
    subject_lower = request.subject.lower()
    keyword_hits = sum(1 for kw in suspicious_keywords if kw in body_lower or kw in subject_lower)
    risk_score += keyword_hits * 0.1

    if keyword_hits >= 2:
        findings.append({"type": "phishing", "severity": "medium", "description": f"Email contains {keyword_hits} suspicious keywords"})

    risk_score = min(risk_score, 1.0)
    is_phishing = risk_score >= 0.5

    message_id = f"msg-{len(_messages) + 1:03d}"
    now = datetime.now()
    threats = []
    if is_phishing:
        threats.append(EmailThreat(
            id=f"threat-{len([t for m in _messages for t in m.threats]) + 1:03d}",
            type="phishing" if risk_score >= 0.6 else "spam",
            severity="critical" if risk_score >= 0.8 else "high" if risk_score >= 0.6 else "medium",
            message_id=message_id,
            detected_at=now,
            status="active",
            description="Automated phishing detection triggered",
        ))

    message = EmailMessage(
        id=message_id,
        from_=request.from_,
        to=request.to,
        subject=request.subject,
        body=request.body,
        headers=request.headers,
        risk_level="critical" if risk_score >= 0.8 else "high" if risk_score >= 0.6 else "medium" if risk_score >= 0.4 else "low" if risk_score >= 0.2 else "safe",
        risk_score=risk_score,
        status="quarantined" if risk_score >= 0.7 else "analyzed",
        analyzed_at=now,
        threats=threats,
    )
    _messages.append(message)

    return {
        "message_id": message_id,
        "risk_score": risk_score,
        "is_phishing": is_phishing,
        "findings": findings,
        "status": message.status,
        "threats": [t.model_dump() for t in threats],
    }


@router.get("/messages")
async def list_messages(
    status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    results = _messages
    if status:
        results = [m for m in results if m.status == status]
    if risk_level:
        results = [m for m in results if m.risk_level == risk_level]
    if date_from:
        from_dt = datetime.fromisoformat(date_from)
        results = [m for m in results if m.analyzed_at >= from_dt]
    if date_to:
        to_dt = datetime.fromisoformat(date_to)
        results = [m for m in results if m.analyzed_at <= to_dt]
    return {"total": len(results), "messages": [m.model_dump() for m in results]}


@router.get("/messages/{message_id}")
async def get_message(message_id: str, current_user: dict = Depends(get_current_user)):
    for msg in _messages:
        if msg.id == message_id:
            return msg.model_dump()
    raise HTTPException(status_code=404, detail="Message not found")


@router.post("/messages/{message_id}/report")
async def report_message(message_id: str, report_type: str = Query(...), current_user: dict = Depends(get_current_user)):
    if report_type not in ("false_positive", "miss"):
        raise HTTPException(status_code=400, detail="report_type must be false_positive or miss")
    for msg in _messages:
        if msg.id == message_id:
            msg.status = "reported"
            return {"message_id": message_id, "report_type": report_type, "status": "reported"}
    raise HTTPException(status_code=404, detail="Message not found")


@router.get("/threats")
async def list_threats(
    threat_type: Optional[str] = Query(None, alias="type"),
    severity: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
):
    all_threats = [t for m in _messages for t in m.threats]
    if threat_type:
        all_threats = [t for t in all_threats if t.type == threat_type]
    if severity:
        all_threats = [t for t in all_threats if t.severity == severity]
    return {"total": len(all_threats), "threats": [t.model_dump() for t in all_threats]}


@router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    total = len(_messages)
    threats_count = sum(1 for m in _messages if m.threats)
    false_positives = sum(1 for m in _messages if m.status == "reported")
    quarantined = sum(1 for m in _messages if m.status == "quarantined")
    risk_levels = {}
    for m in _messages:
        risk_levels[m.risk_level] = risk_levels.get(m.risk_level, 0) + 1
    return EmailStats(
        total_analyzed=total,
        threats_detected=threats_count,
        false_positives=false_positives,
        quarantined=quarantined,
        risk_levels=risk_levels,
    ).model_dump()


@router.post("/policies")
async def create_policy(policy: EmailPolicyCreate, current_user: dict = Depends(get_current_user)):
    now = datetime.now()
    new_policy = EmailPolicy(
        id=f"policy-{len(_policies) + 1:03d}",
        name=policy.name,
        description=policy.description,
        rules=policy.rules.model_dump(),
        enabled=True,
        created_at=now,
        updated_at=now,
    )
    _policies.append(new_policy)
    return new_policy.model_dump()


@router.get("/policies")
async def list_policies(current_user: dict = Depends(get_current_user)):
    return {"total": len(_policies), "policies": [p.model_dump() for p in _policies]}
