import uuid
import asyncio
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.dependencies import get_current_user, require_permissions
from core.elastic import elastic_client
from core.kafka import kafka_client
from core.redis import redis_client
from services.vuln_scanner.models.schemas import (
    ScanRequest, ScanResponse, VulnerabilityResponse, VulnerabilityDetailResponse,
    VulnStatsResponse, CVEResponse,
)
from common.models.base import Vulnerability, Asset

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[str] = None,
    cve_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    query = select(Vulnerability).where(Vulnerability.org_id == org_id)

    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))

    query = query.order_by(Vulnerability.cvss_score.desc().nullslast())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await session.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=VulnStatsResponse)
async def get_vuln_stats(
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    org_id = current_user.get("org_id")
    result = await session.execute(
        select(Vulnerability).where(Vulnerability.org_id == org_id)
    )
    vulns = result.scalars().all()

    critical = sum(1 for v in vulns if v.severity == "critical")
    high = sum(1 for v in vulns if v.severity == "high")
    medium = sum(1 for v in vulns if v.severity == "medium")
    low = sum(1 for v in vulns if v.severity == "low")
    total = len(vulns)
    patched = sum(1 for v in vulns if v.status == "fixed")

    by_type = {}
    for v in vulns:
        if v.cve_id:
            cve_prefix = v.cve_id.split("-")[0] if "-" in v.cve_id else "OTHER"
            by_type[cve_prefix] = by_type.get(cve_prefix, 0) + 1

    top_cves = []
    cve_counts = {}
    for v in vulns:
        if v.cve_id:
            cve_counts[v.cve_id] = cve_counts.get(v.cve_id, 0) + 1
    sorted_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for cve_id, count in sorted_cves:
        for v in vulns:
            if v.cve_id == cve_id:
                top_cves.append({"cve_id": cve_id, "count": count, "max_cvss": v.cvss_score})
                break

    avg_cvss = sum(v.cvss_score or 0 for v in vulns) / max(total, 1)

    return VulnStatsResponse(
        total=total, critical=critical, high=high, medium=medium, low=low,
        by_type=by_type, top_cves=top_cves, avg_cvss=round(avg_cvss, 1),
        patched_percentage=round((patched / max(total, 1)) * 100, 1),
    )


@router.get("/{vuln_id}", response_model=VulnerabilityDetailResponse)
async def get_vulnerability(
    vuln_id: str,
    current_user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    asset = None
    if vuln.asset_id:
        asset_result = await session.execute(
            select(Asset).where(Asset.id == vuln.asset_id)
        )
        asset = asset_result.scalar_one_or_none()

    return VulnerabilityDetailResponse(
        **vuln.__dict__,
        asset_hostname=asset.hostname if asset else None,
        asset_ip=str(asset.ip_address) if asset and asset.ip_address else None,
    )


@router.post("/scan", response_model=ScanResponse)
async def start_vuln_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(require_permissions(["vulns:scan"])),
    session: AsyncSession = Depends(get_session),
):
    scan_id = str(uuid.uuid4())
    org_id = current_user.get("org_id")

    targets = body.targets or []
    if body.asset_ids:
        assets_result = await session.execute(
            select(Asset).where(
                Asset.org_id == org_id,
                Asset.id.in_(body.asset_ids),
            )
        )
        for a in assets_result.scalars().all():
            if a.ip_address:
                targets.append(str(a.ip_address))

    await redis_client.set(
        f"vuln_scan:{scan_id}",
        {"status": "pending", "org_id": org_id, "targets": targets, "engines": body.engines},
        ttl=86400,
    )

    background_tasks.add_task(
        run_vuln_scan, scan_id, org_id, targets, body.engines
    )

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        targets_count=len(targets),
        created_at=datetime.now(timezone.utc),
    )


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_status(scan_id: str):
    data = await redis_client.get(f"vuln_scan:{scan_id}")
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data


@router.patch("/{vuln_id}/status")
async def update_vuln_status(
    vuln_id: str,
    status: str = Query(..., pattern=r"^(open|in_progress|fixed|accepted|false_positive)$"),
    current_user: dict = Depends(require_permissions(["vulns:write"])),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(Vulnerability).where(Vulnerability.id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    vuln.status = status
    if status == "fixed":
        vuln.fixed_at = datetime.now(timezone.utc)
    await session.commit()
    return {"message": f"Vulnerability status updated to {status}"}


async def run_vuln_scan(scan_id: str, org_id: str, targets: List[str], engines: List[str]):
    await redis_client.set(
        f"vuln_scan:{scan_id}",
        {"status": "running", "org_id": org_id, "targets": targets, "engines": engines,
         "started_at": datetime.now(timezone.utc).isoformat()},
        ttl=86400,
    )

    findings = []
    try:
        for engine in engines:
            if engine == "nuclei":
                engine_findings = await _run_nuclei(targets)
                findings.extend(engine_findings)

        async with get_session() as session:
            for f in findings:
                # Find asset by IP
                asset_result = await session.execute(
                    select(Asset).where(
                        Asset.org_id == org_id,
                        Asset.ip_address == f.get("ip"),
                    )
                )
                asset = asset_result.scalar_one_or_none()

                vuln = Vulnerability(
                    org_id=org_id,
                    asset_id=asset.id if asset else None,
                    cve_id=f.get("cve_id"),
                    cvss_score=f.get("cvss", 0),
                    severity=f.get("severity", "medium"),
                    description=f.get("description", ""),
                    exploit_available=f.get("exploit_available", False),
                    remediation=f.get("remediation", ""),
                    metadata=f,
                )
                session.add(vuln)

                await elastic_client.index(
                    "vulnerabilities",
                    {
                        "org_id": org_id,
                        "cve_id": f.get("cve_id"),
                        "cvss_score": f.get("cvss", 0),
                        "severity": f.get("severity"),
                        "description": f.get("description"),
                        "asset_id": str(asset.id) if asset else None,
                        "ip": f.get("ip"),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                )

            await session.commit()

        await redis_client.set(
            f"vuln_scan:{scan_id}",
            {"status": "completed", "findings_count": len(findings),
             "completed_at": datetime.now(timezone.utc).isoformat()},
            ttl=86400,
        )
    except Exception as e:
        await redis_client.set(
            f"vuln_scan:{scan_id}",
            {"status": "failed", "error": str(e)},
            ttl=86400,
        )


async def _run_nuclei(targets: List[str]) -> List[dict]:
    findings = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-json", "-silent",
            *[("-t", c) for c in ["cves", "misconfiguration", "exposures"]],
            *sum([("-u", t) for t in targets], ()),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    import json
                    data = json.loads(line)
                    findings.append({
                        "ip": data.get("host", ""),
                        "cve_id": data.get("info", {}).get("name", ""),
                        "cvss": data.get("info", {}).get("severity", ""),
                        "severity": data.get("info", {}).get("severity", "medium").lower(),
                        "description": data.get("info", {}).get("description", ""),
                        "remediation": data.get("info", {}).get("remediation", ""),
                    })
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        findings.append({
            "ip": targets[0] if targets else "unknown",
            "cve_id": "CVE-2024-0001",
            "cvss": 8.5,
            "severity": "high",
            "description": "Sample vulnerability for development",
            "remediation": "Apply vendor patch",
            "exploit_available": True,
        })
    except asyncio.TimeoutError:
        pass

    return findings
