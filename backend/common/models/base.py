import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, String, Boolean, JSON, Float, ForeignKey, Text, ARRAY, BigInteger, Index
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class TimestampMixin:
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), index=True)


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    settings = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True, index=True)

    __table_args__ = (
        Index("ix_organizations_slug_active", "slug", "is_active"),
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), nullable=False, default="analyst", index=True)
    permissions = Column(JSON, default=list)
    mfa_enabled = Column(Boolean, default=False, index=True)
    mfa_secret = Column(String(255))
    is_active = Column(Boolean, default=True, index=True)
    last_login = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_users_org_role", "org_id", "role"),
        Index("ix_users_org_active", "org_id", "is_active"),
    )


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True)
    hostname = Column(String(255))
    ip_address = Column(INET, index=True)
    mac_address = Column(String(17))
    os = Column(String(100))
    os_version = Column(String(100))
    asset_type = Column(String(50), index=True)
    risk_score = Column(Float, default=0.0, index=True)
    tags = Column(JSON, default=list)
    attributes = Column(JSON, default=dict)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_assets_org_type", "org_id", "asset_type"),
        Index("ix_assets_org_risk", "org_id", "risk_score"),
    )


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), index=True)
    cve_id = Column(String(20), index=True)
    cvss_score = Column(Float, index=True)
    severity = Column(String(20), index=True)
    description = Column(Text)
    exploit_available = Column(Boolean, default=False, index=True)
    remediation = Column(Text)
    status = Column(String(50), default="open", index=True)
    discovered_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)
    fixed_at = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_vulns_org_severity", "org_id", "severity"),
        Index("ix_vulns_org_status", "org_id", "status"),
        Index("ix_vulns_cvss_severity", "cvss_score", "severity"),
    )


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True)
    source = Column(String(50), index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)
    status = Column(String(50), default="new", index=True)
    mitre_techniques = Column(ARRAY(String))
    asset_ids = Column(ARRAY(UUID(as_uuid=True)))
    raw_data = Column(JSON)
    ai_summary = Column(Text)
    ai_recommendation = Column(Text)
    risk_score = Column(Float, default=0.0, index=True)
    resolved_at = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_alerts_org_severity", "org_id", "severity"),
        Index("ix_alerts_org_status", "org_id", "status"),
        Index("ix_alerts_org_created", "org_id", "created_at"),
    )


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)
    status = Column(String(50), default="open", index=True)
    alert_ids = Column(ARRAY(UUID(as_uuid=True)))
    assignee_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    playbook_id = Column(UUID(as_uuid=True))
    timeline = Column(JSON, default=list)
    ai_narrative = Column(Text)
    resolved_at = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_incidents_org_severity", "org_id", "severity"),
        Index("ix_incidents_org_status", "org_id", "status"),
        Index("ix_incidents_org_created", "org_id", "created_at"),
    )


class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True)
    ioc_type = Column(String(50), index=True)
    ioc_value = Column(Text, nullable=False, index=True)
    threat_score = Column(Float, default=0.0, index=True)
    source = Column(String(100))
    tags = Column(JSON, default=list)
    is_active = Column(Boolean, default=True, index=True)
    first_seen = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime(timezone=True))

    __table_args__ = (
        Index("ix_iocs_org_type_active", "org_id", "ioc_type", "is_active"),
        Index("ix_iocs_value_type", "ioc_value", "ioc_type"),
    )


class Playbook(Base, TimestampMixin):
    __tablename__ = "playbooks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    trigger_type = Column(String(100))
    trigger_config = Column(JSON)
    steps = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=True, index=True)

    __table_args__ = (
        Index("ix_playbooks_org_active", "org_id", "is_active"),
    )


class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(100), index=True)
    resource_id = Column(String(100), index=True)
    details = Column(JSON)
    ip_address = Column(INET)

    __table_args__ = (
        Index("ix_audit_org_action", "org_id", "action"),
        Index("ix_audit_org_resource", "org_id", "resource_type", "resource_id"),
        Index("ix_audit_created", "created_at"),
    )
