import asyncio
import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy import select, or_, func
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.dependencies import get_current_user, require_permissions, get_organization
from core.elastic import elastic_client
from core.kafka import kafka_client
from core.redis import redis_client
from services.asset_discovery.models.schemas import (
    ScanTargetRequest, ScanResponse, AssetResponse, AssetDetailResponse,
    NetworkTopologyResponse, NetworkTopologyNode, NetworkTopologyEdge,
    CloudAccountRequest, CloudAccountResponse, AssetDiscoveryResult,
)
from services.asset_discovery.integrations.nmap_scanner import NmapScanner
from common.models.base import Asset

logger = logging.getLogger("soc.assets")

router = APIRouter(prefix="/assets", tags=["Asset Discovery"])


@router.get("", response_model=List[AssetResponse])
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    asset_type: Optional[str] = None,
    search: Optional[str] = None,
    risk_min: Optional[float] = None,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    query = select(Asset).where(Asset.org_id == org_id)

    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if risk_min is not None:
        query = query.where(Asset.risk_score >= risk_min)
    if search:
        query = query.where(
            or_(
                Asset.hostname.ilike(f"%{search}%"),
                Asset.ip_address.cast(str).ilike(f"%{search}%"),
            )
        )

    query = query.order_by(Asset.risk_score.desc().nullslast())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await session.execute(query)
    return result.scalars().all()


@router.get("/stats")
async def get_asset_stats(
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    query = select(Asset).where(Asset.org_id == org_id)
    result = await session.execute(query)
    assets = result.scalars().all()

    total = len(assets)
    by_type = {}
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for a in assets:
        by_type[a.asset_type or "unknown"] = by_type.get(a.asset_type or "unknown", 0) + 1
        score = a.risk_score or 0
        if score >= 9:
            risk_distribution["critical"] += 1
        elif score >= 7:
            risk_distribution["high"] += 1
        elif score >= 4:
            risk_distribution["medium"] += 1
        else:
            risk_distribution["low"] += 1

    return {
        "total_assets": total,
        "by_type": by_type,
        "risk_distribution": risk_distribution,
        "recently_discovered": sum(
            1 for a in assets if a.created_at and (datetime.now(timezone.utc) - a.created_at).days < 1
        ),
    }


@router.get("/{asset_id}", response_model=AssetDetailResponse)
async def get_asset(
    asset_id: str,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Get vulnerabilities count from ES
    vuln_count = 0
    try:
        es_result = await elastic_client.count(
            "vulnerabilities",
            {"query": {"term": {"asset_id": asset_id}}},
        )
        vuln_count = es_result
    except Exception as e:
        logger.warning(f"Failed to get vulnerability count from Elasticsearch: {e}")

    return AssetDetailResponse(
        **asset.__dict__,
        vulnerabilities_count=vuln_count,
    )


@router.post("/scan", response_model=ScanResponse)
async def start_scan(
    body: ScanTargetRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permissions(["assets:scan"])),
    session: AsyncSession = Depends(get_session),
):
    scan_id = str(uuid.uuid4())
    org_id = current_user.get("org_id")

    await redis_client.set(
        f"scan:{scan_id}",
        {
            "status": "pending",
            "org_id": org_id,
            "targets": body.targets,
            "scan_type": body.scan_type,
            "progress": 0,
        },
        ttl=3600,
    )

    scanner = NmapScanner()
    background_tasks.add_task(
        run_discovery_scan,
        scan_id=scan_id,
        org_id=org_id,
        targets=body.targets,
        ports=body.ports,
        scan_type=body.scan_type,
        scanner=scanner,
        session_factory=get_session,
    )

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        total_targets=len(body.targets),
    )


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_status(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    data = await redis_client.get(f"scan:{scan_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data


@router.get("/topology", response_model=NetworkTopologyResponse)
async def get_network_topology(
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    result = await session.execute(
        select(Asset).where(Asset.org_id == org_id).limit(500)
    )
    assets = result.scalars().all()

    nodes = []
    edges = []
    for asset in assets:
        nodes.append(NetworkTopologyNode(
            id=str(asset.id),
            label=asset.hostname or str(asset.ip_address),
            type=asset.asset_type or "host",
            ip=str(asset.ip_address) if asset.ip_address else None,
            risk_score=asset.risk_score or 0,
        ))

    return NetworkTopologyResponse(nodes=nodes, edges=edges)


async def run_discovery_scan(
    scan_id: str,
    org_id: str,
    targets: List[str],
    ports: Optional[str],
    scan_type: str,
    scanner: NmapScanner,
    session_factory,
):
    await redis_client.set(f"scan:{scan_id}", None, ttl=3600)
    scan_data = {
        "scan_id": scan_id,
        "status": "running",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    await redis_client.set(f"scan:{scan_id}", scan_data, ttl=3600)

    try:
        results = await scanner.scan(targets, ports, scan_type)

        async with session_factory() as session:
            for r in results:
                asset = Asset(
                    org_id=org_id,
                    hostname=r.hostname,
                    ip_address=r.ip_address,
                    mac_address=r.mac_address,
                    os=r.os,
                    os_version=r.os_version,
                    asset_type=r.asset_type,
                    tags=r.tags,
                    attributes={
                        "open_ports": r.open_ports,
                        "services": r.services,
                    },
                )

                # Check if asset already exists by IP
                existing = await session.execute(
                    select(Asset).where(
                        Asset.org_id == org_id,
                        Asset.ip_address == r.ip_address,
                    )
                )
                existing_asset = existing.scalar_one_or_none()
                if existing_asset:
                    existing_asset.last_seen = datetime.now(timezone.utc)
                    existing_asset.attributes = asset.attributes
                    if r.hostname:
                        existing_asset.hostname = r.hostname
                    if r.os:
                        existing_asset.os = r.os
                else:
                    session.add(asset)

                # Send to ES for search
                await elastic_client.index(
                    "assets",
                    {
                        "org_id": org_id,
                        "hostname": r.hostname,
                        "ip_address": r.ip_address,
                        "os": r.os,
                        "asset_type": r.asset_type,
                        "open_ports": r.open_ports,
                        "risk_score": 0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )

                # Send discovery event to Kafka
                await kafka_client.send_event(
                    "asset_discovered",
                    {
                        "asset_id": str(asset.id) if not existing_asset else str(existing_asset.id),
                        "ip": r.ip_address,
                        "hostname": r.hostname,
                        "asset_type": r.asset_type,
                    },
                    source="asset-discovery",
                )

            await session.commit()

        scan_data["status"] = "completed"
        scan_data["assets_found"] = len(results)
        scan_data["completed_at"] = datetime.now(timezone.utc).isoformat()

    except Exception as e:
        scan_data["status"] = "failed"
        scan_data["error"] = str(e)

    await redis_client.set(f"scan:{scan_id}", scan_data, ttl=3600)
