const recommendations = [
  { text: 'Isolate WKS-047 - Ransomware behavior detected', severity: 'critical', action: 'Isolate' },
  { text: 'Block IP 185.234.72.18 - Active C2 communication', severity: 'critical', action: 'Block' },
  { text: 'Patch CVE-2024-1234 on SRV-DC01 - Remote code execution', severity: 'high', action: 'Patch' },
  { text: 'Review 12 high severity vulnerabilities discovered', severity: 'high', action: 'Review' },
  { text: 'Enable MFA for 3 privileged accounts without 2FA', severity: 'medium', action: 'Enable' },
]

export default function AiRecommendations() {
  return (
    <div className="panel">
      <div className="panel-header">
        <span>🤖 AI Recommendations</span>
        <span className="ml-auto text-2xs text-soc-accent">Powered by AI</span>
      </div>
      <div className="divide-y divide-soc-border">
        {recommendations.map((rec, i) => (
          <div key={i} className="px-3 py-2 flex items-start gap-2 hover:bg-soc-sidebar-hover transition-colors">
            <div className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${
              rec.severity === 'critical' ? 'bg-red-500' :
              rec.severity === 'high' ? 'bg-orange-500' : 'bg-yellow-500'
            }`} />
            <div className="flex-1 min-w-0">
              <p className="text-xs text-soc-text leading-relaxed">{rec.text}</p>
              <button className="text-2xs text-soc-accent mt-1 hover:text-soc-accent-dim">{rec.action} →</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
