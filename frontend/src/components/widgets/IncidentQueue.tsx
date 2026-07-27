const incidents = [
  { id: 'INC-001', title: 'Suspicious PowerShell on WKS-047', severity: 'critical', status: 'open', age: '5m' },
  { id: 'INC-002', title: 'C2 Beacon Detected - 185.234.72.18', severity: 'critical', status: 'investigating', age: '12m' },
  { id: 'INC-003', title: 'Phishing Campaign - PayPal Spoof', severity: 'high', status: 'open', age: '34m' },
  { id: 'INC-004', title: 'Lateral Movement - WKS-047 → DC-01', severity: 'high', status: 'contained', age: '1h' },
  { id: 'INC-005', title: 'MFA Failures - Admin Account', severity: 'medium', status: 'open', age: '2h' },
]

const severityClass: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
}

export default function IncidentQueue() {
  return (
    <div className="panel">
      <div className="panel-header">
        <span>Incident Queue</span>
        <span className="ml-auto text-soc-accent">{incidents.length} active</span>
      </div>
      <div className="divide-y divide-soc-border">
        {incidents.map((inc) => (
          <div key={inc.id} className="px-3 py-2 hover:bg-soc-sidebar-hover cursor-pointer transition-colors">
            <div className="flex items-center gap-2 mb-0.5">
              <span className={`badge ${severityClass[inc.severity]}`}>{inc.severity}</span>
              <span className="text-2xs font-mono text-soc-text-dim">{inc.id}</span>
              <span className="text-2xs text-soc-text-dim ml-auto">{inc.age}</span>
            </div>
            <div className="text-xs text-soc-text truncate">{inc.title}</div>
            <div className="text-2xs text-soc-text-dim mt-0.5">Status: {inc.status}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
