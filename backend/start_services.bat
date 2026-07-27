@echo off
set VENV=%~dp0venv\Scripts\python.exe
set BASE=%~dp0

echo Starting API Gateway (8000)...
start "API-Gateway-8000" /MIN "%VENV%" -m uvicorn core.main:app --host 0.0.0.0 --port 8000

echo Starting Auth Service (8010)...
start "Auth-8010" /MIN "%VENV%" -m uvicorn services.auth_service.main:app --host 0.0.0.0 --port 8010

echo Starting Asset Discovery (8002)...
start "AssetDisc-8002" /MIN "%VENV%" -m uvicorn services.asset_discovery.main:app --host 0.0.0.0 --port 8002

echo Starting Vuln Scanner (8003)...
start "VulnScan-8003" /MIN "%VENV%" -m uvicorn services.vuln_scanner.main:app --host 0.0.0.0 --port 8003

echo Starting Threat Intel (8004)...
start "ThreatIntel-8004" /MIN "%VENV%" -m uvicorn services.threat_intel.main:app --host 0.0.0.0 --port 8004

echo Starting Incident Response (8005)...
start "IncidentResp-8005" /MIN "%VENV%" -m uvicorn services.incident_response.main:app --host 0.0.0.0 --port 8005

echo Starting AI Copilot (8006)...
start "AICopilot-8006" /MIN "%VENV%" -m uvicorn services.ai_copilot.main:app --host 0.0.0.0 --port 8006

echo Starting EDR (8007)...
start "EDR-8007" /MIN "%VENV%" -m uvicorn services.edr_service.main:app --host 0.0.0.0 --port 8007

echo Starting NDR (8008)...
start "NDR-8008" /MIN "%VENV%" -m uvicorn services.ndr_service.main:app --host 0.0.0.0 --port 8008

echo Starting MITRE Mapper (8009)...
start "MITRE-8009" /MIN "%VENV%" -m uvicorn services.mitre_mapper.main:app --host 0.0.0.0 --port 8009

echo Starting Cloud Security (8011)...
start "CloudSec-8011" /MIN "%VENV%" -m uvicorn services.cloud_security.main:app --host 0.0.0.0 --port 8011

echo Starting Hunting Service (8012)...
start "Hunting-8012" /MIN "%VENV%" -m uvicorn services.hunting_service.main:app --host 0.0.0.0 --port 8012

echo Starting Identity Security (8013)...
start "Identity-8013" /MIN "%VENV%" -m uvicorn services.identity_security.main:app --host 0.0.0.0 --port 8013

echo Starting Email Security (8014)...
start "Email-8014" /MIN cmd /k "cd /d %BASE%services\email_security && %VENV% main.py"

echo Starting Autonomous SOC (8015)...
start "AutonomSOC-8015" /MIN cmd /k "cd /d %BASE%services\autonomous_soc && %VENV% main.py"

echo Starting Predictive Analytics (8016)...
start "Predictive-8016" /MIN cmd /k "cd /d %BASE%services\predictive_analytics && %VENV% main.py"

echo.
echo All services launched. Check Task Manager or netstat to verify.
