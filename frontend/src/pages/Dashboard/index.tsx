import { useEffect } from 'react'
import AppShell from '../../components/layout/AppShell'
import ThreatTimeline from '../../components/widgets/ThreatTimeline'
import MitreHeatmap from '../../components/widgets/MitreHeatmap'
import IncidentQueue from '../../components/widgets/IncidentQueue'
import RiskTrends from '../../components/widgets/RiskTrends'
import AiRecommendations from '../../components/widgets/AiRecommendations'
import AiCopilot from '../../components/modules/AiCopilot'
import { useAlertStore } from '../../store/alertStore'

export default function Dashboard() {
  const { stats, fetchStats } = useAlertStore()

  useEffect(() => {
    fetchStats()
  }, [])

  const statCards = [
    { label: 'Active Alerts', value: '12', change: '+3', color: 'text-red-400', bg: 'bg-red-500/10' },
    { label: 'Critical Vulns', value: '47', change: '+5', color: 'text-orange-400', bg: 'bg-orange-500/10' },
    { label: 'Open Incidents', value: '8', change: '+2', color: 'text-yellow-400', bg: 'bg-yellow-500/10' },
    { label: 'Risk Score', value: '7.2', change: '+0.3', color: 'text-soc-accent', bg: 'bg-soc-accent/10' },
  ]

  return (
    <AppShell rightPanel={<AiCopilot />}>
      <div className="p-4 space-y-4">
        {/* Top Stats */}
        <div className="grid grid-cols-4 gap-3">
          {statCards.map((card) => (
            <div key={card.label} className={`${card.bg} border border-soc-border rounded-lg p-3`}>
              <div className="text-2xs text-soc-text-dim mb-1">{card.label}</div>
              <div className="flex items-baseline gap-2">
                <span className={`text-2xl font-bold font-mono ${card.color}`}>{card.value}</span>
                <span className={`text-xs ${card.change.startsWith('+') ? 'text-red-400' : 'text-green-400'}`}>
                  {card.change}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Charts Row */}
        <div className="grid grid-cols-2 gap-3">
          <ThreatTimeline />
          <RiskTrends />
        </div>

        {/* Bottom Grid */}
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-1">
            <MitreHeatmap />
          </div>
          <div className="col-span-1">
            <IncidentQueue />
          </div>
          <div className="col-span-1">
            <AiRecommendations />
          </div>
        </div>
      </div>
    </AppShell>
  )
}
