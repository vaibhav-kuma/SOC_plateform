$base = "e:\You_tube_notes\vi\ss\Talent\backend"
$python = "$base\venv\Scripts\python.exe"
$logs = "$base\logs"

if (!(Test-Path $logs)) { New-Item -ItemType Directory -Path $logs | Out-Null }

$services = @(
    @{ name="API-Gateway";          port=8000; module="core.main:app" },
    @{ name="Auth";                 port=8010; module="services.auth_service.main:app" },
    @{ name="AssetDiscovery";       port=8002; module="services.asset_discovery.main:app" },
    @{ name="VulnScanner";          port=8003; module="services.vuln_scanner.main:app" },
    @{ name="ThreatIntel";          port=8004; module="services.threat_intel.main:app" },
    @{ name="IncidentResponse";     port=8005; module="services.incident_response.main:app" },
    @{ name="AICopilot";            port=8006; module="services.ai_copilot.main:app" },
    @{ name="EDR";                  port=8007; module="services.edr_service.main:app" },
    @{ name="NDR";                  port=8008; module="services.ndr_service.main:app" },
    @{ name="MITREMapper";          port=8009; module="services.mitre_mapper.main:app" },
    @{ name="CloudSecurity";        port=8011; module="services.cloud_security.main:app" },
    @{ name="HuntingService";       port=8012; module="services.hunting_service.main:app" },
    @{ name="IdentitySecurity";     port=8013; module="services.identity_security.main:app" },
    @{ name="EmailSecurity";        port=8014; module="services.email_security.main:app";    direct=$true; dir="services\email_security" },
    @{ name="AutonomousSOC";        port=8015; module="services.autonomous_soc.main:app";     direct=$true; dir="services\autonomous_soc" },
    @{ name="PredictiveAnalytics";  port=8016; module="services.predictive_analytics.main:app"; direct=$true; dir="services\predictive_analytics" }
)

foreach ($svc in $services) {
    $logFile = "$logs\$($svc.name).log"
    if ($svc.direct) {
        $workDir = "$base\$($svc.dir)"
        Start-Process -FilePath $python `
            -ArgumentList "main.py" `
            -WorkingDirectory $workDir `
            -RedirectStandardOutput $logFile `
            -RedirectStandardError "$logFile.err" `
            -WindowStyle Hidden
    } else {
        $uvicornArgs = "-m uvicorn $($svc.module) --host 0.0.0.0 --port $($svc.port)"
        Start-Process -FilePath $python `
            -ArgumentList $uvicornArgs `
            -WorkingDirectory $base `
            -RedirectStandardOutput $logFile `
            -RedirectStandardError "$logFile.err" `
            -WindowStyle Hidden
    }
    Write-Host "Started $($svc.name) on port $($svc.port)"
}

Write-Host "`nAll services launched. Waiting 15s for startup..."
Start-Sleep -Seconds 15

Write-Host "`n=== Port Status ==="
foreach ($svc in $services) {
    $conn = Get-NetTCPConnection -LocalPort $svc.port -State Listen -ErrorAction SilentlyContinue
    if ($conn) {
        Write-Host "PORT $($svc.port) ($($svc.name)): UP" -ForegroundColor Green
    } else {
        Write-Host "PORT $($svc.port) ($($svc.name)): DOWN" -ForegroundColor Red
    }
}
