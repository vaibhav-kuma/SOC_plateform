from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List
from datetime import datetime, timedelta
from uuid import uuid4
from core.dependencies import get_current_user
from models.schemas import (
    Playbook, PlaybookCreate, PlaybookUpdate, PlaybookType, PlaybookSeverity,
    Execution, ExecutionDetail, ExecutionLog, ExecutionStatus,
    CorrelationRule, CorrelationRuleCreate,
    AutonomousStats, TopPlaybook, ExecutionTrendPoint
)

router = APIRouter()


MOCK_PLAYBOOKS = [
    Playbook(
        id="pb-001",
        name="Malicious IP Blocking",
        description="Automatically block malicious IPs on the firewall",
        playbook_type=PlaybookType.CONTAIN,
        trigger_type="alert_severity_high",
        conditions={"source_ip_reputation": "malicious", "confidence": "> 80"},
        actions=["block_ip_firewall", "update_incident", "notify_soc", "create_ticket"],
        severity=PlaybookSeverity.HIGH,
        enabled=True,
        created_at=datetime.now() - timedelta(days=30),
        updated_at=datetime.now() - timedelta(days=2),
    ),
    Playbook(
        id="pb-002",
        name="Endpoint Isolation",
        description="Isolate compromised endpoints and collect forensics",
        playbook_type=PlaybookType.CONTAIN,
        trigger_type="malware_detected",
        conditions={"malware_type": "ransomware", "endpoint_criticality": "high"},
        actions=["isolate_endpoint", "collect_forensics", "kill_processes", "scan_network"],
        severity=PlaybookSeverity.CRITICAL,
        enabled=True,
        created_at=datetime.now() - timedelta(days=25),
        updated_at=datetime.now() - timedelta(days=1),
    ),
    Playbook(
        id="pb-003",
        name="IOC Enrichment",
        description="Enrich indicators of compromise from multiple threat intel feeds",
        playbook_type=PlaybookType.ENRICH,
        trigger_type="new_ioc_detected",
        conditions={"ioc_type": "hash", "source": "any"},
        actions=["query_vt", "query_xforce", "enrich_feed", "update_ioc_db"],
        severity=PlaybookSeverity.MEDIUM,
        enabled=False,
        created_at=datetime.now() - timedelta(days=20),
        updated_at=datetime.now() - timedelta(days=1),
    ),
]

MOCK_EXECUTIONS = [
    Execution(
        id="exec-001",
        playbook_id="pb-001",
        playbook_name="Malicious IP Blocking",
        status=ExecutionStatus.SUCCESS,
        triggered_by="alert-auto-001",
        started_at=datetime.now() - timedelta(hours=6),
        completed_at=datetime.now() - timedelta(hours=5, minutes=55),
        duration_seconds=300.5,
        error_message=None,
    ),
    Execution(
        id="exec-002",
        playbook_id="pb-001",
        playbook_name="Malicious IP Blocking",
        status=ExecutionStatus.SUCCESS,
        triggered_by="alert-auto-002",
        started_at=datetime.now() - timedelta(hours=4),
        completed_at=datetime.now() - timedelta(hours=3, minutes=58),
        duration_seconds=120.0,
        error_message=None,
    ),
    Execution(
        id="exec-003",
        playbook_id="pb-002",
        playbook_name="Endpoint Isolation",
        status=ExecutionStatus.FAILED,
        triggered_by="alert-auto-003",
        started_at=datetime.now() - timedelta(hours=3),
        completed_at=datetime.now() - timedelta(hours=2, minutes=55),
        duration_seconds=300.0,
        error_message="Failed to isolate endpoint: network timeout",
    ),
    Execution(
        id="exec-004",
        playbook_id="pb-002",
        playbook_name="Endpoint Isolation",
        status=ExecutionStatus.RUNNING,
        triggered_by="alert-auto-004",
        started_at=datetime.now() - timedelta(minutes=30),
        completed_at=None,
        duration_seconds=None,
        error_message=None,
    ),
    Execution(
        id="exec-005",
        playbook_id="pb-003",
        playbook_name="IOC Enrichment",
        status=ExecutionStatus.SUCCESS,
        triggered_by="alert-auto-005",
        started_at=datetime.now() - timedelta(hours=1),
        completed_at=datetime.now() - timedelta(minutes=55),
        duration_seconds=300.0,
        error_message=None,
    ),
]

MOCK_EXECUTION_DETAILS = {
    "exec-001": [
        ExecutionLog(step="1", action="block_ip_firewall", status="success", message="IP 185.220.101.x blocked on firewall-01", timestamp=datetime.now() - timedelta(hours=5, minutes=58)),
        ExecutionLog(step="2", action="update_incident", status="success", message="Incident INC-2024-0891 updated with block action", timestamp=datetime.now() - timedelta(hours=5, minutes=57)),
        ExecutionLog(step="3", action="notify_soc", status="success", message="Slack notification sent to #soc-alerts", timestamp=datetime.now() - timedelta(hours=5, minutes=56)),
        ExecutionLog(step="4", action="create_ticket", status="success", message="Ticket SVC-2024-1234 created", timestamp=datetime.now() - timedelta(hours=5, minutes=55)),
    ],
    "exec-002": [
        ExecutionLog(step="1", action="block_ip_firewall", status="success", message="IP 45.33.32.x blocked on firewall-02", timestamp=datetime.now() - timedelta(hours=3, minutes=59)),
        ExecutionLog(step="2", action="update_incident", status="success", message="Incident INC-2024-0892 updated", timestamp=datetime.now() - timedelta(hours=3, minutes=58)),
        ExecutionLog(step="3", action="notify_soc", status="success", message="PagerDuty notification sent", timestamp=datetime.now() - timedelta(hours=3, minutes=58)),
    ],
    "exec-003": [
        ExecutionLog(step="1", action="isolate_endpoint", status="failed", message="Network timeout while isolating ENDP-0042", timestamp=datetime.now() - timedelta(hours=2, minutes=58)),
        ExecutionLog(step="2", action="collect_forensics", status="skipped", message="Skipped due to isolation failure", timestamp=datetime.now() - timedelta(hours=2, minutes=56)),
    ],
    "exec-004": [
        ExecutionLog(step="1", action="isolate_endpoint", status="running", message="Isolating endpoint ENDP-0089...", timestamp=datetime.now() - timedelta(minutes=28)),
    ],
    "exec-005": [
        ExecutionLog(step="1", action="query_vt", status="success", message="VirusTotal: 3/68 engines detected", timestamp=datetime.now() - timedelta(minutes=58)),
        ExecutionLog(step="2", action="query_xforce", status="success", message="X-Force: Threat score 85/100", timestamp=datetime.now() - timedelta(minutes=57)),
        ExecutionLog(step="3", action="enrich_feed", status="success", message="Enriched feed updated with 2 new indicators", timestamp=datetime.now() - timedelta(minutes=56)),
        ExecutionLog(step="4", action="update_ioc_db", status="success", message="IOC database updated", timestamp=datetime.now() - timedelta(minutes=55)),
    ],
}

MOCK_RULES = [
    CorrelationRule(
        id="rule-001",
        name="Multiple Failed Logins",
        description="Detect brute force attempts via multiple failed logins in a short window",
        rule_type="threshold",
        conditions={"event": "failed_login", "threshold": 5, "window": "5m"},
        severity=PlaybookSeverity.MEDIUM,
        enabled=True,
        created_at=datetime.now() - timedelta(days=45),
        updated_at=datetime.now() - timedelta(days=10),
    ),
    CorrelationRule(
        id="rule-002",
        name="Port Scan Detection",
        description="Identify reconnaissance activity through port scanning behavior",
        rule_type="pattern",
        conditions={"event": "connection_attempt", "unique_ports": "> 20", "window": "1m"},
        severity=PlaybookSeverity.HIGH,
        enabled=True,
        created_at=datetime.now() - timedelta(days=40),
        updated_at=datetime.now() - timedelta(days=5),
    ),
    CorrelationRule(
        id="rule-003",
        name="Data Exfiltration Detection",
        description="Alert on large outbound data transfers to unknown destinations",
        rule_type="anomaly",
        conditions={"event": "outbound_traffic", "volume_mb": "> 500", "dest_unknown": True},
        severity=PlaybookSeverity.CRITICAL,
        enabled=False,
        created_at=datetime.now() - timedelta(days=35),
        updated_at=datetime.now() - timedelta(days=3),
    ),
]


@router.get("/playbooks", response_model=List[Playbook])
def list_playbooks(current_user: dict = Depends(get_current_user)):
    return MOCK_PLAYBOOKS


@router.post("/playbooks", response_model=Playbook, status_code=201)
def create_playbook(payload: PlaybookCreate, current_user: dict = Depends(get_current_user)):
    now = datetime.now()
    playbook = Playbook(
        id=f"pb-{uuid4().hex[:8]}",
        name=payload.name,
        description=payload.description,
        playbook_type=payload.playbook_type,
        trigger_type=payload.trigger_type,
        conditions=payload.conditions,
        actions=payload.actions,
        severity=payload.severity,
        enabled=payload.enabled,
        created_at=now,
        updated_at=now,
    )
    MOCK_PLAYBOOKS.append(playbook)
    return playbook


@router.get("/playbooks/{playbook_id}", response_model=Playbook)
def get_playbook(playbook_id: str, current_user: dict = Depends(get_current_user)):
    for pb in MOCK_PLAYBOOKS:
        if pb.id == playbook_id:
            return pb
    raise HTTPException(status_code=404, detail="Playbook not found")


@router.put("/playbooks/{playbook_id}", response_model=Playbook)
def update_playbook(playbook_id: str, payload: PlaybookUpdate, current_user: dict = Depends(get_current_user)):
    for i, pb in enumerate(MOCK_PLAYBOOKS):
        if pb.id == playbook_id:
            update_data = payload.model_dump(exclude_unset=True)
            for field, value in update_data.items():
                setattr(MOCK_PLAYBOOKS[i], field, value)
            MOCK_PLAYBOOKS[i].updated_at = datetime.now()
            return MOCK_PLAYBOOKS[i]
    raise HTTPException(status_code=404, detail="Playbook not found")


@router.delete("/playbooks/{playbook_id}", status_code=204)
def delete_playbook(playbook_id: str, current_user: dict = Depends(get_current_user)):
    for i, pb in enumerate(MOCK_PLAYBOOKS):
        if pb.id == playbook_id:
            MOCK_PLAYBOOKS.pop(i)
            return
    raise HTTPException(status_code=404, detail="Playbook not found")


@router.post("/playbooks/{playbook_id}/execute", response_model=Execution)
def execute_playbook(playbook_id: str, background_tasks: BackgroundTasks, current_user: dict = Depends(get_current_user)):
    playbook = None
    for pb in MOCK_PLAYBOOKS:
        if pb.id == playbook_id:
            playbook = pb
            break
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    now = datetime.now()
    execution = Execution(
        id=f"exec-{uuid4().hex[:8]}",
        playbook_id=playbook.id,
        playbook_name=playbook.name,
        status=ExecutionStatus.PENDING,
        triggered_by=current_user.get("username", "system"),
        started_at=now,
        completed_at=None,
        duration_seconds=None,
        error_message=None,
    )
    MOCK_EXECUTIONS.append(execution)
    MOCK_EXECUTION_DETAILS[execution.id] = [
        ExecutionLog(step="1", action="initiate", status="pending", message=f"Playbook {playbook.name} execution queued", timestamp=now)
    ]
    return execution


@router.get("/executions", response_model=List[Execution])
def list_executions(status: str = None, current_user: dict = Depends(get_current_user)):
    if status:
        return [e for e in MOCK_EXECUTIONS if e.status.value == status]
    return MOCK_EXECUTIONS


@router.get("/executions/{execution_id}", response_model=ExecutionDetail)
def get_execution(execution_id: str, current_user: dict = Depends(get_current_user)):
    for e in MOCK_EXECUTIONS:
        if e.id == execution_id:
            logs = MOCK_EXECUTION_DETAILS.get(execution_id, [])
            return ExecutionDetail(
                id=e.id,
                playbook_id=e.playbook_id,
                playbook_name=e.playbook_name,
                status=e.status,
                triggered_by=e.triggered_by,
                started_at=e.started_at,
                completed_at=e.completed_at,
                duration_seconds=e.duration_seconds,
                error_message=e.error_message,
                logs=logs,
                trigger_event={"alert_id": execution_id, "source": "siem"},
                output={"actions_completed": len(logs)},
            )
    raise HTTPException(status_code=404, detail="Execution not found")


@router.get("/rules", response_model=List[CorrelationRule])
def list_rules(current_user: dict = Depends(get_current_user)):
    return MOCK_RULES


@router.post("/rules", response_model=CorrelationRule, status_code=201)
def create_rule(payload: CorrelationRuleCreate, current_user: dict = Depends(get_current_user)):
    now = datetime.now()
    rule = CorrelationRule(
        id=f"rule-{uuid4().hex[:8]}",
        name=payload.name,
        description=payload.description,
        rule_type=payload.rule_type,
        conditions=payload.conditions,
        severity=payload.severity,
        enabled=payload.enabled,
        created_at=now,
        updated_at=now,
    )
    MOCK_RULES.append(rule)
    return rule


@router.get("/stats", response_model=AutonomousStats)
def get_stats(current_user: dict = Depends(get_current_user)):
    total = len(MOCK_EXECUTIONS)
    success_count = sum(1 for e in MOCK_EXECUTIONS if e.status == ExecutionStatus.SUCCESS)
    failed_count = sum(1 for e in MOCK_EXECUTIONS if e.status == ExecutionStatus.FAILED)
    running_count = sum(1 for e in MOCK_EXECUTIONS if e.status == ExecutionStatus.RUNNING)
    pending_count = sum(1 for e in MOCK_EXECUTIONS if e.status == ExecutionStatus.PENDING)
    success_rate = (success_count / total * 100) if total else 0.0
    fail_rate = (failed_count / total * 100) if total else 0.0
    durations = [e.duration_seconds for e in MOCK_EXECUTIONS if e.duration_seconds is not None]
    avg_duration = sum(durations) / len(durations) if durations else 0.0
    last_24h = sum(1 for e in MOCK_EXECUTIONS if e.started_at >= datetime.now() - timedelta(hours=24))
    playbook_counts = {}
    for e in MOCK_EXECUTIONS:
        playbook_counts[e.playbook_id] = playbook_counts.get(e.playbook_id, 0) + 1
    top_playbooks = []
    for pb in MOCK_PLAYBOOKS:
        count = playbook_counts.get(pb.id, 0)
        pb_success = sum(1 for e in MOCK_EXECUTIONS if e.playbook_id == pb.id and e.status == ExecutionStatus.SUCCESS)
        pb_total = sum(1 for e in MOCK_EXECUTIONS if e.playbook_id == pb.id)
        top_playbooks.append(TopPlaybook(
            id=pb.id,
            name=pb.name,
            execution_count=count,
            success_rate=(pb_success / pb_total * 100) if pb_total else 0.0,
        ))
    top_playbooks.sort(key=lambda x: x.execution_count, reverse=True)
    trend = []
    for i in range(7):
        day = datetime.now() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        day_total = [e for e in MOCK_EXECUTIONS if day_start <= e.started_at < day_end]
        trend.append(ExecutionTrendPoint(
            date=day_start.strftime("%Y-%m-%d"),
            total=len(day_total),
            success=sum(1 for e in day_total if e.status == ExecutionStatus.SUCCESS),
            failed=sum(1 for e in day_total if e.status == ExecutionStatus.FAILED),
        ))
    trend.reverse()
    return AutonomousStats(
        total_playbooks=len(MOCK_PLAYBOOKS),
        enabled_playbooks=sum(1 for pb in MOCK_PLAYBOOKS if pb.enabled),
        total_executions=total,
        success_rate=round(success_rate, 2),
        fail_rate=round(fail_rate, 2),
        running_executions=running_count,
        pending_executions=pending_count,
        active_rules=sum(1 for r in MOCK_RULES if r.enabled),
        top_triggered_playbooks=top_playbooks[:5],
        execution_trend=trend,
        executions_last_24h=last_24h,
        avg_duration_seconds=round(avg_duration, 2),
    )
