import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from core.dependencies import get_current_user, require_permissions
from core.elastic import elastic_client
from core.kafka import kafka_client

router = APIRouter(prefix="/cloud", tags=["Cloud Security"])


MOCK_ACCOUNTS = [
    {"id": "aws-001", "provider": "AWS", "account_id": "123456789012", "account_name": "Production", "status": "monitored", "regions": ["us-east-1", "us-west-2", "eu-west-1"], "resource_count": 342},
    {"id": "azure-001", "provider": "Azure", "account_id": "00000000-0000-0000-0000-000000000000", "account_name": "Dev/Test", "status": "monitored", "regions": ["eastus", "westeurope"], "resource_count": 128},
    {"id": "gcp-001", "provider": "GCP", "account_id": "my-project-123456", "account_name": "Data Analytics", "status": "error", "regions": ["us-central1"], "resource_count": 45},
]

MOCK_FINDINGS = [
    {"id": "f-001", "provider": "AWS", "service": "S3", "resource": "production-logs-bucket", "finding": "S3 Bucket Publicly Accessible", "severity": "critical", "status": "open", "remediation": "Block public access", "discovered_at": datetime.now(timezone.utc).isoformat()},
    {"id": "f-002", "provider": "AWS", "service": "IAM", "resource": "admin-user", "finding": "IAM Key Not Rotated in 90 Days", "severity": "high", "status": "open", "remediation": "Rotate access keys", "discovered_at": datetime.now(timezone.utc).isoformat()},
    {"id": "f-003", "provider": "Azure", "service": "NSG", "resource": "web-subnet-nsg", "finding": "Port 3389 Exposed to Internet", "severity": "critical", "status": "open", "remediation": "Restrict RDP access", "discovered_at": datetime.now(timezone.utc).isoformat()},
    {"id": "f-004", "provider": "GCP", "service": "IAM", "resource": "project-123456", "finding": "Service Account Has Owner Role", "severity": "high", "status": "open", "remediation": "Apply least privilege", "discovered_at": datetime.now(timezone.utc).isoformat()},
    {"id": "f-005", "provider": "AWS", "service": "CloudTrail", "resource": "management-events", "finding": "CloudTrail Not Enabled in All Regions", "severity": "medium", "status": "resolved", "remediation": "Enable multi-region trail", "discovered_at": datetime.now(timezone.utc).isoformat()},
]


@router.get("/accounts")
async def list_cloud_accounts(current_user: dict = Depends(get_current_user)):
    return MOCK_ACCOUNTS


@router.post("/accounts/connect")
async def connect_cloud_account(
    provider: str = Query(..., pattern=r"^(aws|azure|gcp)$"),
    account_id: str = Query(...),
    current_user: dict = Depends(require_permissions(["cloud:write"])),
):
    return {"message": f"{provider.upper()} account {account_id} connected", "status": "monitoring"}


@router.get("/findings")
async def list_findings(
    provider: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    findings = MOCK_FINDINGS
    if provider:
        findings = [f for f in findings if f["provider"] == provider]
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    if status:
        findings = [f for f in findings if f["status"] == status]
    return findings


@router.get("/stats")
async def get_cloud_stats(current_user: dict = Depends(get_current_user)):
    return {
        "accounts_monitored": 3,
        "resources_scanned": 515,
        "total_findings": len(MOCK_FINDINGS),
        "critical": sum(1 for f in MOCK_FINDINGS if f["severity"] == "critical"),
        "high": sum(1 for f in MOCK_FINDINGS if f["severity"] == "high"),
        "medium": sum(1 for f in MOCK_FINDINGS if f["severity"] == "medium"),
        "low": sum(1 for f in MOCK_FINDINGS if f["severity"] == "low"),
        "open": sum(1 for f in MOCK_FINDINGS if f["status"] == "open"),
        "resolved": sum(1 for f in MOCK_FINDINGS if f["status"] == "resolved"),
        "compliance_score": 72.5,
        "services_covered": ["S3", "EC2", "IAM", "CloudTrail", "Azure NSG", "Azure RBAC", "GCP IAM", "GCP Storage"],
    }


@router.post("/scan")
async def trigger_cloud_scan(
    account_id: Optional[str] = None,
    background_tasks: BackgroundTasks = None,
    current_user: dict = Depends(require_permissions(["cloud:scan"])),
):
    return {"message": "Cloud scan initiated", "accounts_to_scan": account_id or "all"}
