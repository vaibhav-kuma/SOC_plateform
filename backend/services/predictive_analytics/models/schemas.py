from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ModelStatusEnum(str, Enum):
    ACTIVE = "active"
    TRAINING = "training"
    DEPLOYED = "deployed"
    FAILED = "failed"
    ARCHIVED = "archived"


class ThreatForecast(BaseModel):
    date: str
    threat_level: str
    predicted_incidents: int
    top_threat_types: List[str]
    confidence: float
    risk_score: float
    affected_assets: int
    recommended_actions: List[str]


class RiskTrend(BaseModel):
    date: str
    risk_score: float
    total_risks: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    mitigated_count: int


class AnomalyScore(BaseModel):
    id: str
    source: str
    score: float
    severity: SeverityEnum
    timestamp: datetime
    description: str
    feature_name: str
    baseline_value: float
    observed_value: float
    deviation_percent: float


class AttackPathway(BaseModel):
    id: str
    name: str
    description: str
    mitre_techniques: List[str]
    mitre_tactics: List[str]
    probability: float
    impact: str
    affected_assets: List[str]
    recommended_controls: List[str]
    entry_points: List[str]


class MLModel(BaseModel):
    id: str
    name: str
    model_type: str
    status: ModelStatusEnum
    accuracy: float
    last_trained_at: Optional[datetime] = None
    version: str
    description: str
    created_at: datetime
    predictions_count: int


class FeatureImportance(BaseModel):
    feature: str
    importance: float
    category: str


class MLModelDetail(MLModel):
    feature_importance: List[FeatureImportance] = []
    training_metrics: Dict[str, Any] = {}
    data_sources: List[str] = []
    model_parameters: Dict[str, Any] = {}
    training_duration_seconds: Optional[float] = None
    test_set_size: int = 0
    validation_accuracy: Optional[float] = None


class PredictiveStats(BaseModel):
    predictions_today: int
    overall_accuracy: float
    active_models: int
    total_models: int
    high_confidence_predictions: int
    avg_risk_score: float
    top_threat_type: str
    last_model_trained: Optional[str] = None
    anomalies_detected_24h: int
    attack_pathways_active: int
    models_in_training: int
    data_sources_monitored: int
