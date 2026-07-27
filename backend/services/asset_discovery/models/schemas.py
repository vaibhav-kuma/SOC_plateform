from datetime import datetime
from typing import List, Optional, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field


class ScanTargetRequest(BaseModel):
    targets: List[str] = Field(..., description="IPs, CIDRs, hostnames to scan")
    scan_type: str = Field(default="quick", pattern=r"^(quick|full|stealth|vulnerability)$")
    ports: Optional[str] = Field(default=None, description="e.g., '22,80,443' or '1-1000'")
    discovery_methods: Optional[List[str]] = Field(default=None, description="nmap, ping, dns, cloud")


class ScanResponse(BaseModel):
    scan_id: str
    status: str  # pending, running, completed, failed
    total_targets: int
    targets_scanned: int = 0
    assets_found: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class AssetResponse(BaseModel):
    id: UUID
    hostname: Optional[str]
    ip_address: Optional[str]
    mac_address: Optional[str]
    os: Optional[str]
    os_version: Optional[str]
    asset_type: str
    risk_score: float
    tags: List[str]
    open_ports: Optional[List[int]]
    services: Optional[List[Dict[str, Any]]]
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class AssetDetailResponse(AssetResponse):
    metadata: Dict[str, Any]
    vulnerabilities_count: int = 0
    alerts_count: int = 0


class AssetDiscoveryResult(BaseModel):
    hostname: Optional[str] = None
    ip_address: str
    mac_address: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    open_ports: List[int] = []
    services: List[Dict[str, Any]] = []
    asset_type: str = "host"
    tags: List[str] = []


class NetworkTopologyNode(BaseModel):
    id: str
    label: str
    type: str  # host, router, switch, firewall, cloud, container
    ip: Optional[str] = None
    risk_score: float = 0.0
    group: Optional[str] = None


class NetworkTopologyEdge(BaseModel):
    source: str
    target: str
    label: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None


class NetworkTopologyResponse(BaseModel):
    nodes: List[NetworkTopologyNode]
    edges: List[NetworkTopologyEdge]


class CloudAccountRequest(BaseModel):
    provider: str  # aws, azure, gcp
    credentials: Dict[str, Any]


class CloudAccountResponse(BaseModel):
    id: str
    provider: str
    account_id: str
    account_name: str
    status: str
    regions: List[str]
    resource_count: int
