import asyncio
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.dependencies import get_current_user
from core.elastic import elastic_client
from core.redis import redis_client
from services.hunting_service.models.schemas import (
    HuntingQuery, HuntingQueryCreate, HuntingQueryResponse,
    HuntingResult, Hypothesis, HypothesisCreate, HuntingStats,
)

logger = logging.getLogger("soc.hunting")

router = APIRouter(prefix="/hunting", tags=["Threat Hunting"])

_queries_db = [
    {
        "id": "a1b2c3d4-0001-4000-8000-000000000001",
        "title": "Suspicious PowerShell Execution",
        "description": "Detects PowerShell processes launched with encoded commands or suspicious parameters",
        "query": "process.parent_name: powershell.exe AND process.command_line: (*-EncodedCommand* OR *-e * OR *-WindowStyle Hidden*)",
        "data_sources": ["windows_event_log", "sysmon", "edr"],
        "tags": ["powershell", "lolbins", "execution"],
        "mitre_techniques": ["T1059.001"],
        "status": "active",
        "created_by": "system",
        "created_at": datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": "a1b2c3d4-0002-4000-8000-000000000002",
        "title": "Unusual Outbound SMB Connections",
        "description": "Detects SMB client connections to external IP addresses, which may indicate data exfiltration",
        "query": "network.destination.port: 445 AND NOT network.destination.ip: (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)",
        "data_sources": ["network_logs", "zeek", "firewall"],
        "tags": ["smb", "exfiltration", "lateral-movement"],
        "mitre_techniques": ["T1021.002", "T1048"],
        "status": "active",
        "created_by": "analyst1",
        "created_at": datetime(2025, 2, 1, 14, 30, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2025, 3, 10, 9, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": "a1b2c3d4-0003-4000-8000-000000000003",
        "title": "DNS Tunneling Detection",
        "description": "Identifies potential DNS tunneling by detecting high volume of DNS queries to unusual domains",
        "query": "dns.query_count: > 100 AND dns.unique_domains: < 5 AND dns.query_type: TXT",
        "data_sources": ["dns_logs", "zeek"],
        "tags": ["dns", "tunneling", "c2"],
        "mitre_techniques": ["T1572", "T1041"],
        "status": "draft",
        "created_by": "analyst2",
        "created_at": datetime(2025, 3, 5, 8, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2025, 3, 5, 8, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": "a1b2c3d4-0004-4000-8000-000000000004",
        "title": "Privilege Escalation via Token Manipulation",
        "description": "Detects attempts to escalate privileges by manipulating access tokens",
        "query": "event_id: 4672 AND (process.name: secedit.exe OR process.name: whoami.exe OR process.name: runas.exe)",
        "data_sources": ["windows_event_log", "sysmon"],
        "tags": ["privilege-escalation", "token-manipulation", "defense-evasion"],
        "mitre_techniques": ["T1134", "T1134.001"],
        "status": "active",
        "created_by": "analyst1",
        "created_at": datetime(2025, 4, 12, 16, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2025, 4, 12, 16, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": "a1b2c3d4-0005-4000-8000-000000000005",
        "title": "Anomalous Scheduled Task Creation",
        "description": "Detects creation of scheduled tasks by non-system accounts, often used for persistence",
        "query": "event_id: 4698 AND NOT user.name: (*SYSTEM* OR *LOCAL SERVICE* OR *NETWORK SERVICE*)",
        "data_sources": ["windows_event_log", "sysmon"],
        "tags": ["persistence", "scheduled-task", "privilege-escalation"],
        "mitre_techniques": ["T1053.005"],
        "status": "archived",
        "created_by": "system",
        "created_at": datetime(2024, 11, 20, 12, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2024, 12, 1, 8, 0, 0, tzinfo=timezone.utc),
    },
]

_hypotheses_db = [
    {
        "id": "b1c2d3e4-0001-4000-8000-000000000001",
        "title": "APT-C-36 may be targeting our finance department",
        "description": "Recent spear-phishing emails with malicious Excel attachments observed targeting finance team. Correlate with anyrundll32.exe or regsvr32.exe executions.",
        "mitre_techniques": ["T1566.001", "T1204.002", "T1218.010"],
        "status": "investigating",
        "created_by": "analyst1",
        "created_at": datetime(2025, 5, 1, 9, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2025, 5, 3, 14, 0, 0, tzinfo=timezone.utc),
    },
    {
        "id": "b1c2d3e4-0002-4000-8000-000000000002",
        "title": "Potential Cobalt Strike Beacon activity on DMZ servers",
        "description": "Suspicious HTTPS callbacks from DMZ web servers to known malicious IP ranges observed in netflow data.",
        "mitre_techniques": ["T1071.001", "T1573", "T1063"],
        "status": "active",
        "created_by": "analyst2",
        "created_at": datetime(2025, 5, 10, 11, 0, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2025, 5, 10, 11, 0, 0, tzinfo=timezone.utc),
    },
]

_results_db = []


@router.post("/queries", response_model=HuntingQueryResponse, status_code=201)
async def create_hunting_query(
    body: HuntingQueryCreate,
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user.get("sub", "unknown")
    now = datetime.now(timezone.utc)
    record = {
        "id": str(uuid.uuid4()),
        "title": body.title,
        "description": body.description,
        "query": body.query,
        "data_sources": body.data_sources,
        "tags": body.tags,
        "mitre_techniques": body.mitre_techniques,
        "status": "draft",
        "created_by": user_id,
        "created_at": now,
        "updated_at": now,
        "last_run": None,
        "result_count": 0,
    }
    _queries_db.append(record)
    return record


@router.get("/queries", response_model=List[HuntingQueryResponse])
async def list_hunting_queries(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    data_source: Optional[str] = None,
    tag: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    filtered = list(_queries_db)
    if status:
        filtered = [q for q in filtered if q["status"] == status]
    if data_source:
        filtered = [q for q in filtered if data_source in q["data_sources"]]
    if tag:
        filtered = [q for q in filtered if tag in q["tags"]]
    start = (page - 1) * page_size
    end = start + page_size
    return filtered[start:end]


@router.get("/queries/{query_id}", response_model=HuntingQueryResponse)
async def get_hunting_query(
    query_id: str,
    current_user: dict = Depends(get_current_user),
):
    for q in _queries_db:
        if q["id"] == query_id:
            results = [r for r in _results_db if r["query_id"] == query_id]
            q["last_run"] = max((r["created_at"] for r in results), default=None)
            q["result_count"] = len(results)
            return q
    raise HTTPException(status_code=404, detail="Hunting query not found")


@router.post("/queries/{query_id}/run", status_code=202)
async def run_hunting_query(
    query_id: str,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
):
    query_obj = None
    for q in _queries_db:
        if q["id"] == query_id:
            query_obj = q
            break
    if not query_obj:
        raise HTTPException(status_code=404, detail="Hunting query not found")
    background_tasks.add_task(_execute_hunting_query, query_id)
    return {"message": "Hunting query execution started", "query_id": query_id}


async def _execute_hunting_query(query_id: str):
    query_obj = None
    for q in _queries_db:
        if q["id"] == query_id:
            query_obj = q
            break
    if not query_obj:
        return
    now = datetime.now(timezone.utc)
    result_id = str(uuid.uuid4())
    matched_events = [
        {
            "timestamp": now.isoformat(),
            "event_id": f"evt-{result_id[:8]}-001",
            "source": query_obj["data_sources"][0] if query_obj["data_sources"] else "unknown",
            "host": "srv-web-01",
            "description": f"Matched pattern for {query_obj['title']}",
        }
    ]
    execution_time = 120
    result_record = {
        "id": result_id,
        "query_id": query_id,
        "matched_events": matched_events,
        "total_matches": len(matched_events),
        "severity": "medium",
        "execution_time_ms": execution_time,
        "created_at": now,
    }
    _results_db.append(result_record)
    try:
        await elastic_client.index(
            "hunting_results",
            {
                "query_id": query_id,
                "query_title": query_obj["title"],
                "result_id": result_id,
                "total_matches": len(matched_events),
                "matched_events": matched_events,
                "created_at": now.isoformat(),
            },
        )
    except Exception as e:
        logger.warning(f"Failed to index hunting result to Elasticsearch: {e}")
    try:
        await redis_client.set(
            f"hunting:result:{result_id}",
            result_record,
            ttl=3600,
        )
    except Exception as e:
        logger.warning(f"Failed to cache hunting result in Redis: {e}")
    for q in _queries_db:
        if q["id"] == query_id:
            q["updated_at"] = now
            break


@router.get("/queries/{query_id}/results", response_model=List[HuntingResult])
async def get_hunting_query_results(
    query_id: str,
    current_user: dict = Depends(get_current_user),
):
    for q in _queries_db:
        if q["id"] == query_id:
            break
    else:
        raise HTTPException(status_code=404, detail="Hunting query not found")
    results = [r for r in _results_db if r["query_id"] == query_id]
    if not results:
        try:
            es_results = await elastic_client.search(
                "hunting_results",
                {"query": {"term": {"query_id": query_id}}},
            )
            if es_results and "hits" in es_results:
                for hit in es_results["hits"].get("hits", []):
                    results.append(hit.get("_source", {}))
        except Exception as e:
            logger.warning(f"Failed to search hunting results in Elasticsearch: {e}")
    return results


@router.post("/hypotheses", response_model=Hypothesis, status_code=201)
async def create_hypothesis(
    body: HypothesisCreate,
    current_user: dict = Depends(get_current_user),
):
    user_id = current_user.get("sub", "unknown")
    now = datetime.now(timezone.utc)
    record = {
        "id": str(uuid.uuid4()),
        "title": body.title,
        "description": body.description,
        "mitre_techniques": body.mitre_techniques,
        "status": body.status,
        "created_by": user_id,
        "created_at": now,
        "updated_at": now,
    }
    _hypotheses_db.append(record)
    return record


@router.get("/hypotheses", response_model=List[Hypothesis])
async def list_hypotheses(
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    if status:
        return [h for h in _hypotheses_db if h["status"] == status]
    return list(_hypotheses_db)


@router.get("/stats", response_model=HuntingStats)
async def get_hunting_stats(
    current_user: dict = Depends(get_current_user),
):
    total_queries = len(_queries_db)
    active_queries = sum(1 for q in _queries_db if q["status"] == "active")
    archived_queries = sum(1 for q in _queries_db if q["status"] == "archived")
    total_hypotheses = len(_hypotheses_db)
    active_hypotheses = sum(1 for h in _hypotheses_db if h["status"] in ("active", "investigating"))
    suspicious_findings = sum(1 for r in _results_db if r.get("severity") in ("high", "critical"))
    total_results = len(_results_db)
    queries_by_data_source = {}
    for q in _queries_db:
        for ds in q["data_sources"]:
            queries_by_data_source[ds] = queries_by_data_source.get(ds, 0) + 1
    queries_by_mitre = {}
    for q in _queries_db:
        for mt in q["mitre_techniques"]:
            queries_by_mitre[mt] = queries_by_mitre.get(mt, 0) + 1
    return HuntingStats(
        total_queries=total_queries,
        active_queries=active_queries,
        archived_queries=archived_queries,
        total_hypotheses=total_hypotheses,
        active_hypotheses=active_hypotheses,
        suspicious_findings=suspicious_findings,
        total_results=total_results,
        queries_by_data_source=queries_by_data_source,
        queries_by_mitre_technique=queries_by_mitre,
    )
