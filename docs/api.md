# API Reference

## Authentication (port 8010)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login with email + password |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Invalidate refresh token |
| GET | `/api/v1/auth/me` | Get current user info |
| PUT | `/api/v1/auth/password` | Change password |
| POST | `/api/v1/auth/mfa/setup` | Setup MFA |
| POST | `/api/v1/auth/mfa/verify` | Verify MFA code |

## Asset Discovery (port 8002)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/assets` | List assets |
| POST | `/api/v1/assets/scan` | Trigger asset scan |
| GET | `/api/v1/assets/stats` | Asset discovery stats |
| GET | `/api/v1/assets/{asset_id}` | Get asset details |

## Vulnerability Scanner (port 8003)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/vulnerabilities` | List vulnerabilities |
| GET | `/api/v1/vulnerabilities/stats` | Vulnerability stats |
| GET | `/api/v1/vulnerabilities/{vuln_id}` | Get vulnerability details |
| POST | `/api/v1/vulnerabilities/{vuln_id}/remediate` | Trigger remediation |

## Threat Intelligence (port 8004)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/intel/feeds` | List threat intel feeds |
| GET | `/api/v1/intel/actors` | List threat actors |
| POST | `/api/v1/intel/iocs/lookup` | Lookup IOCs |
| GET | `/api/v1/intel/stats` | Threat intel stats |

## Incident Response (port 8005)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/incidents` | List incidents |
| POST | `/api/v1/incidents` | Create incident |
| GET | `/api/v1/incidents/{incident_id}` | Get incident details |
| PUT | `/api/v1/incidents/{incident_id}` | Update incident |
| POST | `/api/v1/incidents/{incident_id}/respond` | Execute response action |
| GET | `/api/v1/incidents/{incident_id}/timeline` | Get incident timeline |

## AI Copilot (port 8006)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/copilot/chat` | Send message to AI |
| POST | `/api/v1/copilot/investigate` | Investigate endpoint |
| POST | `/api/v1/copilot/summarize` | Summarize incident |

## EDR (port 8007)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/endpoints` | List endpoints |
| POST | `/api/v1/endpoints/{endpoint_id}/isolate` | Isolate endpoint |
| POST | `/api/v1/endpoints/kill-process` | Kill process on endpoint |
| POST | `/api/v1/endpoints/block-ioc` | Block IOC across endpoints |

## NDR (port 8008)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/network/flows` | List network flows |
| GET | `/api/v1/network/alerts` | List network alerts |
| GET | `/api/v1/network/stats` | Network traffic stats |

## MITRE Mapper (port 8009)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/mitre/coverage` | Get MITRE coverage map |
| GET | `/api/v1/mitre/heatmap` | Get coverage heatmap |

## Cloud Security (port 8011)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/cloud/accounts` | List cloud accounts |
| POST | `/api/v1/cloud/scan` | Trigger cloud scan |
| GET | `/api/v1/cloud/findings` | List cloud findings |

## Hunting Service (port 8012)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/hunting/queries` | List hunting queries |
| POST | `/api/v1/hunting/queries` | Create hunting query |
| POST | `/api/v1/hunting/queries/{query_id}/execute` | Execute query |
| GET | `/api/v1/hunting/hypotheses` | List hypotheses |
| POST | `/api/v1/hunting/hypotheses` | Create hypothesis |
| GET | `/api/v1/hunting/stats` | Hunting dashboard stats |

## Identity Security (port 8013)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/identity/users` | List monitored users |
| GET | `/api/v1/identity/users/{user_id}` | Get user details |
| POST | `/api/v1/identity/users/{user_id}/risk-score` | Recalculate risk |
| GET | `/api/v1/identity/anomalies` | List identity anomalies |
| POST | `/api/v1/identity/anomalies/{anomaly_id}/investigate` | Investigate anomaly |
| GET | `/api/v1/identity/privileged-accounts` | List privileged accounts |
| GET | `/api/v1/identity/stats` | Identity security stats |
| POST | `/api/v1/identity/policies` | Create policy |
| GET | `/api/v1/identity/policies` | List policies |

## Email Security (port 8014)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/email/analyze` | Analyze email for threats |
| GET | `/api/v1/email/messages` | List analyzed messages |
| GET | `/api/v1/email/messages/{message_id}` | Get message analysis |
| POST | `/api/v1/email/messages/{message_id}/report` | Report false positive/miss |
| GET | `/api/v1/email/threats` | List email threats |
| GET | `/api/v1/email/stats` | Email security stats |
| POST | `/api/v1/email/policies` | Create policy |
| GET | `/api/v1/email/policies` | List policies |

## Autonomous SOC (port 8015)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/autonomous/playbooks` | List playbooks |
| POST | `/api/v1/autonomous/playbooks` | Create playbook |
| GET | `/api/v1/autonomous/playbooks/{playbook_id}` | Get playbook |
| PUT | `/api/v1/autonomous/playbooks/{playbook_id}` | Update playbook |
| DELETE | `/api/v1/autonomous/playbooks/{playbook_id}` | Delete playbook |
| POST | `/api/v1/autonomous/playbooks/{playbook_id}/execute` | Execute playbook |
| GET | `/api/v1/autonomous/executions` | List executions |
| GET | `/api/v1/autonomous/executions/{execution_id}` | Get execution details |
| GET | `/api/v1/autonomous/rules` | List correlation rules |
| POST | `/api/v1/autonomous/rules` | Create rule |
| GET | `/api/v1/autonomous/stats` | Autonomous SOC stats |

## Predictive Analytics (port 8016)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/predictive/threat-forecast` | Get threat forecast |
| GET | `/api/v1/predictive/risk-trends` | Get risk trends |
| GET | `/api/v1/predictive/anomaly-scores` | Get anomaly scores |
| GET | `/api/v1/predictive/attack-pathways` | Get attack pathways |
| POST | `/api/v1/predictive/models/train` | Train ML model |
| GET | `/api/v1/predictive/models` | List ML models |
| GET | `/api/v1/predictive/models/{model_id}` | Get model details |
| GET | `/api/v1/predictive/stats` | Predictive analytics stats |

## Common Headers

All authenticated endpoints require:
```
Authorization: Bearer <jwt_token>
```

## Response Format

Success: `200` with JSON body
Error: `4xx` or `5xx` with `{"detail": "message"}`
