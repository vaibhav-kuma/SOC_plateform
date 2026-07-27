import uuid
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from core.dependencies import get_current_user
from core.elastic import elastic_client
from core.kafka import kafka_client

router = APIRouter(prefix="/network", tags=["Network Detection"])

MOCK_FLOWS = [
    {"id": "flow-1", "src_ip": "10.0.1.101", "dst_ip": "185.234.72.18", "dst_port": 443, "protocol": "HTTPS", "bytes_sent": 1452300, "bytes_received": 45200, "duration_sec": 120, "threat_score": 85, "detection": "c2_beacon"},
    {"id": "flow-2", "src_ip": "10.0.1.102", "dst_ip": "52.84.120.45", "dst_port": 80, "protocol": "HTTP", "bytes_sent": 4500, "bytes_received": 125000, "duration_sec": 5, "threat_score": 15, "detection": None},
    {"id": "flow-3", "src_ip": "10.0.0.10", "dst_ip": "10.0.1.101", "dst_port": 445, "protocol": "SMB", "bytes_sent": 8900, "bytes_received": 24500, "duration_sec": 30, "threat_score": 65, "detection": "lateral_movement"},
]


@router.get("/flows")
async def list_network_flows(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1),
    current_user: dict = Depends(get_current_user),
):
    # In production: query from Elasticsearch
    return MOCK_FLOWS


@router.get("/alerts")
async def list_network_alerts(
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    alerts = [
        {"id": "net-001", "title": "C2 Beacon Detected", "source_ip": "10.0.1.101", "dest_ip": "185.234.72.18", "protocol": "HTTPS", "severity": "critical", "confidence": 95, "rule": "C2_Beacon_Detection", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"id": "net-002", "title": "Lateral Movement via SMB", "source_ip": "10.0.0.10", "dest_ip": "10.0.1.101", "protocol": "SMB", "severity": "high", "confidence": 85, "rule": "Lateral_Movement_SMB", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"id": "net-003", "title": "DNS Tunneling Anomaly", "source_ip": "10.0.1.102", "dest_ip": "8.8.8.8", "protocol": "DNS", "severity": "medium", "confidence": 60, "rule": "DNS_Tunneling", "timestamp": datetime.now(timezone.utc).isoformat()},
    ]
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]
    return alerts


@router.get("/stats")
async def get_network_stats(current_user: dict = Depends(get_current_user)):
    return {
        "total_flows_24h": 45231,
        "total_alerts": 18,
        "critical_alerts": 2,
        "high_alerts": 5,
        "medium_alerts": 8,
        "low_alerts": 3,
        "top_detections": [
            {"name": "C2 Beacon", "count": 2},
            {"name": "Lateral Movement", "count": 5},
            {"name": "Port Scan", "count": 8},
            {"name": "DNS Anomaly", "count": 3},
        ],
        "active_sensors": 3,
        "bytes_analyzed_24h": "2.4 TB",
    }
