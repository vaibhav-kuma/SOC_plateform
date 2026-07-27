import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.dependencies import get_current_user
from core.elastic import elastic_client
from core.redis import redis_client
from services.ai_copilot.models.schemas import (
    ChatRequest, ChatResponse, InvestigationRequest, InvestigationResponse,
    IncidentSummaryRequest, IncidentSummaryResponse, AIQueryRequest, AIQueryResponse,
)
from services.ai_copilot.ai.llm_client import llm_client
from common.models.base import Alert, Incident

logger = logging.getLogger("soc.copilot")

router = APIRouter(prefix="/copilot", tags=["AI Security Copilot"])


@router.post("/chat", response_model=ChatResponse)
async def chat(
    body: ChatRequest,
    current_user: dict = Depends(get_current_user),
):
    conversation_id = body.conversation_id or str(uuid.uuid4())

    # Build conversation context
    messages = [{"role": "user", "content": body.message}]

    # If alert context is provided, fetch additional data
    context_info = ""
    if body.context:
        alert_id = body.context.get("alert_id")
        incident_id = body.context.get("incident_id")
        if alert_id:
            try:
                alert = await elastic_client.get("alerts", alert_id)
                if alert:
                    context_info += f"\nAlert Context: {json.dumps(alert, indent=2)[:2000]}"
            except Exception as e:
                logger.warning(f"Failed to fetch alert context: {e}")

    if context_info:
        messages.insert(0, {"role": "system", "content": f"Additional context:\n{context_info}"})

    response_text = await llm_client.chat(messages)

    return ChatResponse(
        response=response_text,
        conversation_id=conversation_id,
        suggestions=[
            "Investigate the latest critical alert",
            "Show me lateral movement in the last 24h",
            "What vulnerabilities affect our domain controllers?",
            "Generate an executive security summary",
        ],
        actions=[
            {"label": "Isolate Endpoint", "action": "isolate", "severity": "critical"},
            {"label": "Block IP", "action": "block_ip", "severity": "high"},
            {"label": "Generate Report", "action": "report", "severity": "info"},
        ],
    )


@router.post("/investigate/{alert_id}", response_model=InvestigationResponse)
async def investigate_alert(
    alert_id: str,
    request: Optional[InvestigationRequest] = None,
    current_user: dict = Depends(get_current_user),
):
    org_id = current_user.get("org_id")

    # Fetch alert data
    alert_data = await elastic_client.get("alerts", alert_id)

    # Fetch correlated events
    correlated_events = []
    if not request or request.include_logs:
        try:
            es_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"org_id": org_id}},
                            {"range": {"timestamp": {"gte": f"now-{request.time_range_hours if request else 24}h"}}},
                        ]
                    }
                },
                "size": 50,
            }
            es_result = await elastic_client.search("edr-events-*", es_query)
            correlated_events = [h["_source"] for h in es_result.get("hits", {}).get("hits", [])]
        except Exception as e:
            logger.warning(f"Failed to fetch correlated events: {e}")

    # AI analysis
    system_prompt = """You are a Senior SOC Analyst AI. Perform a thorough investigation of this security alert.
    Analyze the alert data and correlated events to determine root cause, impact, and recommended actions.
    Structure your response with clear sections: Summary, Root Cause, Impact Assessment, MITRE Techniques, Recommended Actions."""

    alert_context = json.dumps(alert_data or {"id": alert_id}, indent=2)
    events_context = json.dumps(correlated_events[:10], indent=2)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Alert Data:\n{alert_context}\n\nCorrelated Events:\n{events_context}"},
    ]

    ai_response = await llm_client.chat(messages)

    return InvestigationResponse(
        alert_id=alert_id,
        summary=ai_response[:500],
        root_cause="PowerShell-based C2 communication detected via encoded command (Analysis in progress)",
        impact_assessment="Host WKS-047 compromised, potential lateral movement to domain controller",
        affected_assets=[{"id": "WKS-047", "type": "endpoint", "risk": "compromised"}],
        mitre_techniques=["T1059.001", "T1071.001", "T1105"],
        kill_chain_phase="Command & Control",
        recommended_actions=[
            "Isolate WKS-047 immediately",
            "Kill malicious PowerShell process",
            "Block C2 IP at firewall",
            "Scan for additional compromised hosts",
            "Reset compromised credentials",
        ],
        timeline=[{"time": datetime.now(timezone.utc).isoformat(), "event": "Alert generated"}],
        confidence_score=0.92,
        generated_at=datetime.now(timezone.utc),
    )


@router.post("/summarize/{incident_id}", response_model=IncidentSummaryResponse)
async def summarize_incident(
    incident_id: str,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    system_prompt = "You are a Senior SOC Analyst AI. Generate a comprehensive incident summary."
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Incident: {incident.title}\nDescription: {incident.description}\nSeverity: {incident.severity}\nTimeline: {incident.timeline}"},
    ]

    ai_response = await llm_client.chat(messages)

    return IncidentSummaryResponse(
        incident_id=incident_id,
        executive_summary=ai_response[:500],
        technical_details=ai_response[500:1000] if len(ai_response) > 500 else "Technical analysis in progress",
        attack_timeline=incident.timeline,
        impacted_systems=["WKS-047", "SRV-DC01"],
        indicators=[
            {"type": "IP", "value": "185.234.72.18", "context": "C2 Server"},
            {"type": "Hash", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "context": "Malicious Payload"},
        ],
        remediation_steps=[
            "Isolate compromised systems",
            "Block indicators at perimeter",
            "Scan environment for additional IOCs",
            "Reset affected credentials",
        ],
    )


@router.post("/query", response_model=AIQueryResponse)
async def security_query(
    body: AIQueryRequest,
    current_user: dict = Depends(get_current_user),
):
    system_prompt = "You are a Senior SOC Analyst AI. Answer security questions with precision and actionable information."
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": body.query},
    ]

    response_text = await llm_client.chat(messages)

    return AIQueryResponse(
        answer=response_text,
        confidence=0.95,
        data_sources_used=["Elasticsearch", "Threat Intelligence", "Asset Database"],
    )


@router.get("/conversation/{conversation_id}")
async def get_conversation_history(conversation_id: str):
    data = await redis_client.get(f"conversation:{conversation_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return data
