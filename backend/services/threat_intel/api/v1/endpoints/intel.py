import uuid
import hashlib
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy import select, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.dependencies import get_current_user, require_permissions
from core.elastic import elastic_client
from core.kafka import kafka_client
from core.redis import redis_client
from services.threat_intel.models.schemas import (
    IOCRequest, IOCResponse, IOCBulkImport, ThreatFeed,
    ThreatActor, IntelSearchRequest, EnrichmentResponse,
)
from common.models.base import IOC

router = APIRouter(prefix="/intel", tags=["Threat Intelligence"])


MOCK_FEEDS = [
    ThreatFeed(id="feed-1", name="AlienVault OTX", provider="otx", status="active", ioc_count=15420, refresh_interval_minutes=60),
    ThreatFeed(id="feed-2", name="AbuseIPDB", provider="abuseipdb", status="active", ioc_count=89234, refresh_interval_minutes=30),
    ThreatFeed(id="feed-3", name="MISP Community", provider="misp", status="active", ioc_count=4521, refresh_interval_minutes=120),
    ThreatFeed(id="feed-4", name="VirusTotal", provider="virustotal", status="active", ioc_count=0, refresh_interval_minutes=60),
]

MOCK_THREAT_ACTORS = [
    ThreatActor(
        id="actor-1", name="APT29", aliases=["Cozy Bear", "The Dukes"],
        motivation="Cyber espionage", country="Russia",
        targeted_sectors=["Government", "Healthcare"],
        tools=["PowerShell", "Cobalt Strike", "Mimikatz"],
        malware=["SolarWinds backdoor"],
    ),
    ThreatActor(
        id="actor-2", name="Lazarus Group", aliases=["HIDDEN COBRA"],
        motivation="Financial gain", country="North Korea",
        targeted_sectors=["Finance", "Cryptocurrency"],
        tools=["macOS malware", "Windows malware"],
        malware=["AppleJeus", "RustBucket"],
    ),
]


@router.get("/iocs", response_model=List[IOCResponse])
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ioc_type: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    min_score: Optional[float] = None,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    query = select(IOC).where(IOC.org_id == org_id)

    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if source:
        query = query.where(IOC.source == source)
    if min_score is not None:
        query = query.where(IOC.threat_score >= min_score)
    if search:
        query = query.where(IOC.ioc_value.ilike(f"%{search}%"))

    query = query.order_by(IOC.threat_score.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await session.execute(query)
    return result.scalars().all()


@router.post("/iocs", response_model=IOCResponse, status_code=201)
async def create_ioc(
    body: IOCRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permissions(["intel:write"])),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")

    # Normalize IOC value
    if body.ioc_type == "hash":
        body.ioc_value = body.ioc_value.lower()

    existing = await session.execute(
        select(IOC).where(IOC.org_id == org_id, IOC.ioc_value == body.ioc_value)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="IOC already exists")

    ioc = IOC(
        org_id=org_id,
        ioc_type=body.ioc_type,
        ioc_value=body.ioc_value,
        threat_score=body.threat_score,
        source=body.source,
        tags=body.tags,
    )
    session.add(ioc)
    await session.commit()
    await session.refresh(ioc)

    # Publish to Kafka for distribution to detection services
    await kafka_client.send(
        "ioc.updates",
        {"ioc_id": str(ioc.id), "ioc_type": ioc.ioc_type, "ioc_value": ioc.ioc_value, "threat_score": ioc.threat_score, "action": "create"},
    )

    return ioc


@router.post("/iocs/bulk", response_model=dict)
async def bulk_import_iocs(
    body: IOCBulkImport,
    current_user: dict = Depends(require_permissions(["intel:write"])),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    imported = 0
    skipped = 0

    for ioc_req in body.iocs:
        existing = await session.execute(
            select(IOC).where(IOC.org_id == org_id, IOC.ioc_value == ioc_req.ioc_value)
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        ioc = IOC(
            org_id=org_id,
            ioc_type=ioc_req.ioc_type,
            ioc_value=ioc_req.ioc_value,
            threat_score=ioc_req.threat_score,
            source=ioc_req.source,
            tags=ioc_req.tags,
        )
        session.add(ioc)
        imported += 1

    await session.commit()
    return {"imported": imported, "skipped": skipped, "total": len(body.iocs)}


@router.get("/iocs/{ioc_id}", response_model=IOCResponse)
async def get_ioc(ioc_id: str, current_user: dict = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    result = await session.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


@router.post("/iocs/{ioc_id}/enrich", response_model=EnrichmentResponse)
async def enrich_ioc(
    ioc_id: str,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permissions(["intel:enrich"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(IOC).where(IOC.id == ioc_id))
    ioc = result.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Mock enrichment (in prod, call VirusTotal, OTX, AbuseIPDB APIs)
    enrichment_result = await mock_enrich(ioc.ioc_value, ioc.ioc_type)
    return enrichment_result


@router.get("/feeds", response_model=List[ThreatFeed])
async def list_feeds(current_user: dict = Depends(get_current_user)):
    return MOCK_FEEDS


@router.post("/feeds/{feed_id}/sync")
async def sync_feed(
    feed_id: str,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permissions(["intel:write"])),
):
    feed = next((f for f in MOCK_FEEDS if f.id == feed_id), None)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    background_tasks.add_task(sync_threat_feed, feed_id)
    return {"message": f"Sync started for {feed.name}"}


@router.get("/actors", response_model=List[ThreatActor])
async def list_actors(current_user: dict = Depends(get_current_user)):
    return MOCK_THREAT_ACTORS


@router.post("/search")
async def search_intel(
    body: IntelSearchRequest,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    query = select(IOC).where(IOC.org_id == org_id)

    if body.ioc_types:
        query = query.where(IOC.ioc_type.in_(body.ioc_types))
    if body.sources:
        query = query.where(IOC.source.in_(body.sources))
    if body.min_score is not None:
        query = query.where(IOC.threat_score >= body.min_score)

    query = query.where(
        or_(
            IOC.ioc_value.ilike(f"%{body.query}%"),
            IOC.tags.cast(str).ilike(f"%{body.query}%"),
        )
    )
    query = query.limit(body.max_results)
    result = await session.execute(query)
    return result.scalars().all()


@router.get("/stats")
async def intel_stats(current_user: dict = Depends(get_current_user), session: AsyncSession = Depends(get_session)):
    org_id = current_user.get("org_id")
    result = await session.execute(select(IOC).where(IOC.org_id == org_id))
    iocs = result.scalars().all()

    by_type = {}
    by_source = {}
    active = 0
    malicious = 0
    for ioc in iocs:
        by_type[ioc.ioc_type] = by_type.get(ioc.ioc_type, 0) + 1
        by_source[ioc.source] = by_source.get(ioc.source, 0) + 1
        if ioc.is_active:
            active += 1
        if ioc.threat_score >= 70:
            malicious += 1

    return {
        "total_iocs": len(iocs),
        "active_iocs": active,
        "malicious_iocs": malicious,
        "by_type": by_type,
        "by_source": by_source,
        "feeds_connected": len(MOCK_FEEDS),
        "threat_actors_tracked": len(MOCK_THREAT_ACTORS),
    }


async def sync_threat_feed(feed_id: str):
    # In production: fetch from MISP/OTX/AbuseIPDB APIs
    await asyncio.sleep(5)


async def mock_enrich(value: str, ioc_type: str) -> EnrichmentResponse:
    import random
    malicious_sources = []
    if ioc_type == "ip":
        malicious_sources = [
            {"source": "AbuseIPDB", "category": "scanning", "confidence": 85, "last_reported": datetime.now(timezone.utc).isoformat()},
            {"source": "VirusTotal", "category": "malicious", "confidence": 72, "last_reported": datetime.now(timezone.utc).isoformat()},
        ]
    elif ioc_type == "domain":
        malicious_sources = [
            {"source": "OTX", "category": "malware", "confidence": 78, "last_reported": datetime.now(timezone.utc).isoformat()},
        ]
    elif ioc_type == "hash":
        malicious_sources = [
            {"source": "VirusTotal", "category": "trojan", "confidence": 92, "detection_ratio": "18/72", "last_reported": datetime.now(timezone.utc).isoformat()},
        ]

    return EnrichmentResponse(
        ioc_value=value,
        ioc_type=ioc_type,
        threat_score=random.uniform(30, 95),
        sources_checked=["abuseipdb", "virustotal", "otx", "misp"],
        findings=malicious_sources,
        reputation="malicious" if malicious_sources else "unknown",
        last_analysis=datetime.now(timezone.utc),
    )
