# SOC Platform Architecture

## Overview

AI-Driven Unified Security Operations Platform (Next-Generation SOC). A microservices-based platform with 15 backend services, React frontend, and full observability stack.

## System Architecture

```
┌──────────┐     ┌──────────────┐     ┌──────────────────┐
│  Client   │────▶│ API Gateway  │────▶│   Microservices  │
│ (React)   │     │  (port 8000) │     │  (ports 8010-16) │
└──────────┘     └──────┬───────┘     └──────────────────┘
                        │
                        ▼
              ┌──────────────────┐
              │  Authentication  │
              │   (port 8010)    │
              │  JWT + RBAC+MFA  │
              └──────────────────┘
```

## Data Layer

- **PostgreSQL** (port 5434): Primary data store for all services
- **Redis** (port 6379): Caching, rate limiting, session management
- **Elasticsearch** (port 9200): Search, logging, threat intelligence indexing
- **Kafka** (port 9092): Async event bus between services

## Service Ports

| Service | Port | Module |
|---------|------|--------|
| API Gateway | 8000 | core |
| Asset Discovery | 8002 | services/asset_discovery |
| Vulnerability Scanner | 8003 | services/vuln_scanner |
| Threat Intelligence | 8004 | services/threat_intel |
| Incident Response | 8005 | services/incident_response |
| AI Copilot | 8006 | services/ai_copilot |
| EDR | 8007 | services/edr_service |
| NDR | 8008 | services/ndr_service |
| MITRE Mapper | 8009 | services/mitre_mapper |
| Auth Service | 8010 | services/auth_service |
| Cloud Security | 8011 | services/cloud_security |
| Hunting Service | 8012 | services/hunting_service |
| Identity Security | 8013 | services/identity_security |
| Email Security | 8014 | services/email_security |
| Autonomous SOC | 8015 | services/autonomous_soc |
| Predictive Analytics | 8016 | services/predictive_analytics |

## Security

- JWT-based authentication with access + refresh tokens
- Role-Based Access Control (admin, analyst, viewer)
- Multi-Factor Authentication (TOTP)
- Password hashing via passlib + bcrypt
- Rate limiting via Redis
- CORS configured per environment

## Observability

- Prometheus metrics on each service
- Grafana dashboards for monitoring
- Elasticsearch for centralized logging
- Health check endpoints on all services
