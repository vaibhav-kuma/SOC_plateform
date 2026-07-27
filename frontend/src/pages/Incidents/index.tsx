import { useEffect, useState } from 'react'
import AppShell from '../../components/layout/AppShell'
import AiCopilot from '../../components/modules/AiCopilot'
import type { Incident } from '../../types'
import api from '../../services/api'

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([])

  useEffect(() => {
    api.get('/incidents').then(({ data }) => setIncidents(data)).catch(() => {})
  }, [])

  return (
    <AppShell rightPanel={<AiCopilot />}>
      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h1 className="text-sm font-semibold">Incident Response Center</h1>
          <div className="flex gap-2">
            <button className="btn-primary">New Incident</button>
            <button className="btn-ghost">Playbooks</button>
          </div>
        </div>

        <div className="grid grid-cols-5 gap-3">
          {[
            { label: 'Open', count: incidents.filter((i) => i.status === 'open').length, color: 'text-red-400' },
            { label: 'Investigating', count: incidents.filter((i) => i.status === 'investigating').length, color: 'text-orange-400' },
            { label: 'Contained', count: incidents.filter((i) => i.status === 'contained').length, color: 'text-yellow-400' },
            { label: 'Resolved', count: incidents.filter((i) => i.status === 'resolved').length, color: 'text-green-400' },
            { label: 'Total', count: incidents.length, color: 'text-soc-accent' },
          ].map((s) => (
            <div key={s.label} className="panel p-3">
              <div className="text-2xs text-soc-text-dim">{s.label}</div>
              <div className={`text-xl font-bold font-mono mt-1 ${s.color}`}>{s.count}</div>
            </div>
          ))}
        </div>

        <div className="panel overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-soc-bg/50 border-b border-soc-border">
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">ID</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Title</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Severity</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Status</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Assignee</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Alerts</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Created</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {incidents.map((inc) => (
                <tr key={inc.id} className="hover:bg-soc-sidebar-hover">
                  <td className="px-3 py-2 font-mono text-soc-accent text-2xs">{inc.id.slice(0, 8)}</td>
                  <td className="px-3 py-2 font-medium">{inc.title}</td>
                  <td className="px-3 py-2">
                    <span className={`badge ${inc.severity === 'critical' ? 'badge-critical' : inc.severity === 'high' ? 'badge-high' : inc.severity === 'medium' ? 'badge-medium' : 'badge-low'}`}>
                      {inc.severity}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className="badge badge-info">{inc.status}</span>
                  </td>
                  <td className="px-3 py-2 text-soc-text-dim">{inc.assignee_name || 'Unassigned'}</td>
                  <td className="px-3 py-2 font-mono text-center">{inc.alert_ids?.length || 0}</td>
                  <td className="px-3 py-2 text-2xs text-soc-text-dim">{new Date(inc.created_at).toLocaleString()}</td>
                  <td className="px-3 py-2">
                    <button className="text-2xs text-soc-accent hover:text-soc-accent-dim">Investigate</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {incidents.length === 0 && (
            <div className="p-8 text-center text-soc-text-dim text-sm">No incidents yet.</div>
          )}
        </div>
      </div>
    </AppShell>
  )
}
