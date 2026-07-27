from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List
from datetime import datetime, timedelta
from uuid import uuid4
from core.dependencies import get_current_user
from models.schemas import (
    ThreatForecast, RiskTrend, AnomalyScore, SeverityEnum,
    AttackPathway, MLModel, MLModelDetail, FeatureImportance,
    ModelStatusEnum, PredictiveStats
)

router = APIRouter()


MOCK_FORECAST = [
    ThreatForecast(
        date=(datetime.now() + timedelta(days=i)).strftime("%Y-%m-%d"),
        threat_level="HIGH" if i < 3 else "MEDIUM",
        predicted_incidents=[42, 38, 55, 29, 33, 27, 31][i],
        top_threat_types=[
            ["Ransomware", "Phishing", "DDoS"],
            ["Phishing", "Credential Theft", "Malware"],
            ["Ransomware", "Data Exfiltration", "Supply Chain"],
            ["Phishing", "Insider Threat", "Malware"],
            ["Credential Theft", "DDoS", "Phishing"],
            ["Malware", "Insider Threat", "Phishing"],
            ["DDoS", "Ransomware", "Credential Theft"],
        ][i],
        confidence=[87.5, 84.2, 91.3, 78.9, 82.1, 75.6, 79.4][i],
        risk_score=[78.3, 72.1, 85.6, 61.4, 65.8, 58.2, 63.7][i],
        affected_assets=[23, 18, 31, 14, 17, 12, 15][i],
        recommended_actions=[
            ["Patch critical vulnerabilities", "Enable MFA", "Isolate high-value assets"],
            ["Deploy phishing simulations", "Update email filters", "Enable DMARC"],
            ["Backup critical data", "Review firewall rules", "Deploy honeypots"],
            ["Review user access", "Conduct security awareness", "Monitor VPN logs"],
            ["Reset compromised credentials", "Audit service accounts", "Enable PAM"],
            ["Update EDR policies", "Scan endpoints", "Review privilege escalation"],
            ["Scale DDoS protection", "Rate limit APIs", "Enable WAF rules"],
        ][i],
    )
    for i in range(7)
]

MOCK_RISK_TRENDS = [
    RiskTrend(
        date=(datetime.now() - timedelta(days=29 - i)).strftime("%Y-%m-%d"),
        risk_score=[62.3, 58.7, 64.1, 71.5, 68.2, 55.9, 60.4, 73.8, 69.1, 66.7,
                    72.4, 59.3, 63.8, 77.2, 74.5, 61.0, 57.6, 70.2, 75.9, 65.3,
                    68.8, 80.1, 76.4, 71.9, 67.2, 63.5, 78.6, 82.3, 79.7, 74.1][i],
        total_risks=[28, 24, 31, 37, 33, 22, 26, 39, 35, 30,
                     34, 25, 29, 42, 38, 27, 23, 36, 41, 32,
                     35, 45, 40, 37, 31, 28, 43, 48, 44, 39][i],
        critical_count=[3, 2, 4, 6, 5, 1, 2, 7, 5, 4,
                        5, 2, 3, 8, 6, 3, 1, 5, 8, 4,
                        4, 9, 7, 6, 3, 2, 7, 10, 8, 6][i],
        high_count=[8, 6, 9, 11, 10, 5, 7, 12, 10, 8,
                    11, 6, 8, 14, 12, 7, 5, 10, 13, 9,
                    10, 14, 12, 11, 8, 7, 13, 15, 13, 11][i],
        medium_count=[12, 11, 13, 14, 13, 10, 11, 14, 14, 12,
                      12, 11, 12, 14, 14, 11, 10, 14, 14, 13,
                      14, 15, 14, 14, 13, 12, 15, 16, 15, 14][i],
        low_count=[5, 5, 5, 6, 5, 6, 6, 6, 6, 6,
                   6, 6, 6, 6, 6, 6, 7, 7, 6, 6,
                   7, 7, 7, 6, 7, 7, 8, 7, 8, 8][i],
        mitigated_count=[18, 20, 22, 25, 26, 19, 21, 27, 29, 24,
                          25, 21, 23, 28, 30, 22, 19, 26, 29, 25,
                          27, 31, 30, 28, 24, 22, 30, 33, 32, 28][i],
    )
    for i in range(30)
]

MOCK_ANOMALIES = [
    AnomalyScore(
        id="anom-001",
        source="Network Traffic",
        score=0.94,
        severity=SeverityEnum.CRITICAL,
        timestamp=datetime.now() - timedelta(minutes=15),
        description="Unusual outbound data transfer to unknown IP range",
        feature_name="bytes_out_per_second",
        baseline_value=1250.0,
        observed_value=18400.0,
        deviation_percent=1372.0,
    ),
    AnomalyScore(
        id="anom-002",
        source="Authentication Logs",
        score=0.87,
        severity=SeverityEnum.HIGH,
        timestamp=datetime.now() - timedelta(hours=1),
        description="Geographically impossible login sequence detected",
        feature_name="login_velocity",
        baseline_value=1.2,
        observed_value=14.0,
        deviation_percent=1066.67,
    ),
    AnomalyScore(
        id="anom-003",
        source="Process Execution",
        score=0.82,
        severity=SeverityEnum.HIGH,
        timestamp=datetime.now() - timedelta(hours=3),
        description="Unrecognized process spawning from browser",
        feature_name="process_spawn_rate",
        baseline_value=0.3,
        observed_value=8.0,
        deviation_percent=2566.67,
    ),
    AnomalyScore(
        id="anom-004",
        source="DNS Queries",
        score=0.76,
        severity=SeverityEnum.MEDIUM,
        timestamp=datetime.now() - timedelta(hours=5),
        description="DGA-like domain resolution pattern detected",
        feature_name="dga_score",
        baseline_value=0.02,
        observed_value=0.78,
        deviation_percent=3800.0,
    ),
    AnomalyScore(
        id="anom-005",
        source="Database Access",
        score=0.71,
        severity=SeverityEnum.MEDIUM,
        timestamp=datetime.now() - timedelta(hours=8),
        description="Unusual bulk query pattern on sensitive table",
        feature_name="queries_per_minute",
        baseline_value=45.0,
        observed_value=320.0,
        deviation_percent=611.11,
    ),
    AnomalyScore(
        id="anom-006",
        source="Email Security",
        score=0.65,
        severity=SeverityEnum.MEDIUM,
        timestamp=datetime.now() - timedelta(hours=12),
        description="Spear phishing email with polymorphic payload detected",
        feature_name="phishing_confidence",
        baseline_value=0.15,
        observed_value=0.88,
        deviation_percent=486.67,
    ),
    AnomalyScore(
        id="anom-007",
        source="Cloud API Calls",
        score=0.58,
        severity=SeverityEnum.LOW,
        timestamp=datetime.now() - timedelta(hours=18),
        description="IAM role assumed from unusual geolocation",
        feature_name="geo_anomaly_score",
        baseline_value=0.05,
        observed_value=0.62,
        deviation_percent=1140.0,
    ),
    AnomalyScore(
        id="anom-008",
        source="File Integrity",
        score=0.52,
        severity=SeverityEnum.LOW,
        timestamp=datetime.now() - timedelta(hours=24),
        description="Unexpected modification to system binary",
        feature_name="file_hash_change_rate",
        baseline_value=0.01,
        observed_value=0.45,
        deviation_percent=4400.0,
    ),
]

MOCK_ATTACK_PATHWAYS = [
    AttackPathway(
        id="path-001",
        name="Internet-Facing RCE to Domain Compromise",
        description="Exploitation of unpatched web server vulnerability leads to remote code execution, followed by privilege escalation and lateral movement to Domain Controller",
        mitre_techniques=["T1190", "T1059", "T1068", "T1021", "T1482", "T1550"],
        mitre_tactics=["Initial Access", "Execution", "Privilege Escalation", "Lateral Movement", "Discovery", "Defense Evasion"],
        probability=0.72,
        impact="CRITICAL",
        affected_assets=["web-01", "web-02", "app-01", "dc-01", "sql-01"],
        recommended_controls=["Patch web server CVEs", "Deploy WAF", "Enforce least privilege", "Network segmentation", "Monitor service account usage"],
        entry_points=["CVE-2025-2345", "CVE-2025-1234"],
    ),
    AttackPathway(
        id="path-002",
        name="Phishing to Credential Theft to Data Exfiltration",
        description="Targeted spear phishing campaign delivers credential harvesting payload, leading to privileged account compromise and data exfiltration to external storage",
        mitre_techniques=["T1566", "T1598", "T1056", "T1078", "T1041", "T1021"],
        mitre_tactics=["Initial Access", "Reconnaissance", "Credential Access", "Persistence", "Exfiltration", "Lateral Movement"],
        probability=0.85,
        impact="HIGH",
        affected_assets=["user-1001", "user-1045", "email-gateway", "sharepoint-01", "onedrive-sync"],
        recommended_controls=["Advanced phishing filters", "MFA enforcement", "EDR on endpoints", "Data loss prevention", "User awareness training"],
        entry_points=["targeted_phishing_campaign_apr2025"],
    ),
    AttackPathway(
        id="path-003",
        name="Supply Chain Dependency Compromise",
        description="Compromised third-party library in CI/CD pipeline injects backdoor into production builds, enabling persistent remote access to containerized workloads",
        mitre_techniques=["T1195", "T1195.001", "T1554", "T1525", "T1578", "T1204"],
        mitre_tactics=["Initial Access", "Execution", "Persistence", "Defense Evasion", "Impact", "Collection"],
        probability=0.61,
        impact="HIGH",
        affected_assets=["jenkins-01", "nexus-01", "k8s-api", "container-registry", "prod-namespace"],
        recommended_controls=["Software supply chain security", "SBOM generation", "Container image scanning", "Immutable infrastructure", "CI/CD pipeline audit"],
        entry_points=["compromised-npm-package-pyutil-v2.1.4", "malicious-github-action"],
    ),
]

MOCK_MODELS = [
    MLModel(
        id="model-001",
        name="Threat Frequency Predictor",
        model_type="Time Series (Prophet)",
        status=ModelStatusEnum.DEPLOYED,
        accuracy=0.913,
        last_trained_at=datetime.now() - timedelta(days=2),
        version="3.2.1",
        description="Forecasts daily threat incident volumes using seasonal decomposition and changepoint detection across 24 months of historical SOC data",
        created_at=datetime.now() - timedelta(days=180),
        predictions_count=12450,
    ),
    MLModel(
        id="model-002",
        name="Anomaly Detection Ensemble",
        model_type="Isolation Forest + Autoencoder",
        status=ModelStatusEnum.DEPLOYED,
        accuracy=0.887,
        last_trained_at=datetime.now() - timedelta(days=5),
        version="2.1.0",
        description="Ensemble of unsupervised learners detecting outliers in network, authentication, and process telemetry with real-time scoring pipeline",
        created_at=datetime.now() - timedelta(days=150),
        predictions_count=89200,
    ),
    MLModel(
        id="model-003",
        name="Risk Scoring Engine",
        model_type="Gradient Boosted Trees (XGBoost)",
        status=ModelStatusEnum.DEPLOYED,
        accuracy=0.924,
        last_trained_at=datetime.now() - timedelta(days=7),
        version="4.0.2",
        description="Multi-class risk classifier scoring assets and users on vulnerability data, threat intel, and behavioral baselines",
        created_at=datetime.now() - timedelta(days=200),
        predictions_count=67500,
    ),
    MLModel(
        id="model-004",
        name="Attack Pathway Predictor",
        model_type="Graph Neural Network (GCN)",
        status=ModelStatusEnum.TRAINING,
        accuracy=0.0,
        last_trained_at=None,
        version="1.0.0",
        description="Graph-based model predicting likely attack paths by analyzing asset connectivity, vulnerability chains, and threat actor TTP correlations",
        created_at=datetime.now() - timedelta(days=45),
        predictions_count=0,
    ),
    MLModel(
        id="model-005",
        name="MITRE Technique Classifier",
        model_type="Transformer (BERT-based)",
        status=ModelStatusEnum.DEPLOYED,
        accuracy=0.856,
        last_trained_at=datetime.now() - timedelta(days=14),
        version="2.3.1",
        description="NLP model classifying raw security alerts into MITRE ATT&CK techniques using fine-tuned security domain embeddings",
        created_at=datetime.now() - timedelta(days=120),
        predictions_count=45300,
    ),
]

MOCK_MODEL_DETAILS = {
    "model-001": MLModelDetail(
        id="model-001",
        name="Threat Frequency Predictor",
        model_type="Time Series (Prophet)",
        status=ModelStatusEnum.DEPLOYED,
        accuracy=0.913,
        last_trained_at=datetime.now() - timedelta(days=2),
        version="3.2.1",
        description="Forecasts daily threat incident volumes using seasonal decomposition and changepoint detection across 24 months of historical SOC data",
        created_at=datetime.now() - timedelta(days=180),
        predictions_count=12450,
        feature_importance=[
            FeatureImportance(feature="day_of_week", importance=0.32, category="Temporal"),
            FeatureImportance(feature="month_of_year", importance=0.28, category="Temporal"),
            FeatureImportance(feature="prior_day_incidents", importance=0.18, category="Historical"),
            FeatureImportance(feature="cve_publish_count", importance=0.12, category="External"),
            FeatureImportance(feature="holiday_indicator", importance=0.07, category="Temporal"),
            FeatureImportance(feature="weekend_indicator", importance=0.03, category="Temporal"),
        ],
        training_metrics={
            "mae": 3.24,
            "rmse": 4.87,
            "mape": 0.112,
            "r2_score": 0.891,
            "cross_val_mean": 0.903,
            "cross_val_std": 0.021,
        },
        data_sources=["SiemLogs_24m", "ThreatIntelFeeds", "CVEDatabase", "AssetInventory"],
        model_parameters={
            "seasonality_mode": "multiplicative",
            "changepoint_prior_scale": 0.05,
            "seasonality_prior_scale": 10.0,
            "holidays_prior_scale": 10.0,
            "yearly_seasonality": 15,
            "weekly_seasonality": 5,
        },
        training_duration_seconds=342.0,
        test_set_size=180,
        validation_accuracy=0.908,
    ),
    "model-002": MLModelDetail(
        id="model-002",
        name="Anomaly Detection Ensemble",
        model_type="Isolation Forest + Autoencoder",
        status=ModelStatusEnum.DEPLOYED,
        accuracy=0.887,
        last_trained_at=datetime.now() - timedelta(days=5),
        version="2.1.0",
        description="Ensemble of unsupervised learners detecting outliers in network, authentication, and process telemetry with real-time scoring pipeline",
        created_at=datetime.now() - timedelta(days=150),
        predictions_count=89200,
        feature_importance=[
            FeatureImportance(feature="connection_count_per_min", importance=0.25, category="Network"),
            FeatureImportance(feature="bytes_transferred", importance=0.21, category="Network"),
            FeatureImportance(feature="login_frequency", importance=0.18, category="Authentication"),
            FeatureImportance(feature="process_spawn_rate", importance=0.15, category="Endpoint"),
            FeatureImportance(feature="dns_query_entropy", importance=0.12, category="Network"),
            FeatureImportance(feature="geolocation_velocity", importance=0.09, category="Authentication"),
        ],
        training_metrics={
            "precision": 0.912,
            "recall": 0.864,
            "f1_score": 0.887,
            "auc_roc": 0.941,
            "false_positive_rate": 0.036,
        },
        data_sources=["NetFlow_90d", "AuthLogs_90d", "ProcessEvents_90d", "DNSLogs_90d"],
        model_parameters={
            "isolation_forest_estimators": 200,
            "isolation_forest_contamination": 0.05,
            "autoencoder_layers": [64, 32, 16, 8, 16, 32, 64],
            "autoencoder_epochs": 150,
            "ensemble_weight_if": 0.55,
            "ensemble_weight_ae": 0.45,
        },
        training_duration_seconds=1860.0,
        test_set_size=50000,
        validation_accuracy=0.879,
    ),
}


@router.get("/threat-forecast", response_model=List[ThreatForecast])
def get_threat_forecast(days: int = 7, current_user: dict = Depends(get_current_user)):
    if days not in (7, 14, 30):
        raise HTTPException(status_code=400, detail="Days must be 7, 14, or 30")
    if days <= 7:
        return MOCK_FORECAST
    result = []
    for i in range(days):
        base = MOCK_FORECAST[i % 7]
        import copy
        item = copy.deepcopy(base)
        item.date = (datetime.now() + timedelta(days=i)).strftime("%Y-%m-%d")
        item.predicted_incidents = max(0, int(base.predicted_incidents + (i // 7) * 5 - (i % 3) * 2))
        item.confidence = max(50.0, base.confidence - (i // 7) * 8.0)
        result.append(item)
    return result


@router.get("/risk-trends", response_model=List[RiskTrend])
def get_risk_trends(days: int = 30, current_user: dict = Depends(get_current_user)):
    if days not in (7, 14, 30):
        raise HTTPException(status_code=400, detail="Days must be 7, 14, or 30")
    return MOCK_RISK_TRENDS[-days:]


@router.get("/anomaly-scores", response_model=List[AnomalyScore])
def get_anomaly_scores(source: str = None, current_user: dict = Depends(get_current_user)):
    if source:
        return [a for a in MOCK_ANOMALIES if a.source.lower() == source.lower()]
    return MOCK_ANOMALIES


@router.get("/attack-pathways", response_model=List[AttackPathway])
def get_attack_pathways(current_user: dict = Depends(get_current_user)):
    return MOCK_ATTACK_PATHWAYS


@router.post("/models/train", status_code=202)
def train_models(background_tasks: BackgroundTasks, model_type: str = None, current_user: dict = Depends(get_current_user)):
    from uuid import uuid4
    task_id = uuid4().hex[:12]
    return {
        "message": "Model training initiated",
        "task_id": task_id,
        "model_type": model_type or "all",
        "status": "queued"
    }


@router.get("/models", response_model=List[MLModel])
def list_models(status: str = None, current_user: dict = Depends(get_current_user)):
    if status:
        return [m for m in MOCK_MODELS if m.status.value == status]
    return MOCK_MODELS


@router.get("/models/{model_id}", response_model=MLModelDetail)
def get_model_detail(model_id: str, current_user: dict = Depends(get_current_user)):
    if model_id in MOCK_MODEL_DETAILS:
        return MOCK_MODEL_DETAILS[model_id]
    for m in MOCK_MODELS:
        if m.id == model_id:
            return MLModelDetail(**m.model_dump())
    raise HTTPException(status_code=404, detail="Model not found")


@router.get("/stats", response_model=PredictiveStats)
def get_stats(current_user: dict = Depends(get_current_user)):
    deployed = [m for m in MOCK_MODELS if m.status == ModelStatusEnum.DEPLOYED]
    training = [m for m in MOCK_MODELS if m.status == ModelStatusEnum.TRAINING]
    accuracies = [m.accuracy for m in deployed]
    overall_acc = sum(accuracies) / len(accuracies) if accuracies else 0.0
    high_conf = sum(m.predictions_count for m in deployed if m.accuracy >= 0.85)
    avg_risk = sum(m.risk_score for m in MOCK_FORECAST) / len(MOCK_FORECAST)
    top_types = {}
    for f in MOCK_FORECAST:
        for t in f.top_threat_types:
            top_types[t] = top_types.get(t, 0) + 1
    top_threat = max(top_types, key=top_types.get) if top_types else "Unknown"
    last_trained = None
    for m in MOCK_MODELS:
        if m.last_trained_at:
            if last_trained is None or m.last_trained_at > last_trained:
                last_trained = m.last_trained_at
    last_trained_str = last_trained.isoformat() if last_trained else None
    now = datetime.now()
    last_24h = [a for a in MOCK_ANOMALIES if a.timestamp >= now - timedelta(hours=24)]
    return PredictiveStats(
        predictions_today=sum(m.predictions_count for m in deployed) // 30,
        overall_accuracy=round(overall_acc * 100, 2),
        active_models=len(deployed),
        total_models=len(MOCK_MODELS),
        high_confidence_predictions=high_conf,
        avg_risk_score=round(avg_risk, 2),
        top_threat_type=top_threat,
        last_model_trained=last_trained_str,
        anomalies_detected_24h=len(last_24h),
        attack_pathways_active=len(MOCK_ATTACK_PATHWAYS),
        models_in_training=len(training),
        data_sources_monitored=12,
    )
