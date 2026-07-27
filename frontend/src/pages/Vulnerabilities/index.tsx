import { useEffect, useState } from 'react'
import AppShell from '../../components/layout/AppShell'
import AiCopilot from '../../components/modules/AiCopilot'
import type { Vulnerability } from '../../types'
import api from '../../services/api'

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [filter, setFilter] = useState('')

  useEffect(() => {
    api.get('/vulnerabilities', { params: { page_size: 100 } }).then(({ data }) => setVulns(data)).catch(() => {})
  }, [])

  const filtered = vulns.filter((v) => !filter || v.severity === filter || v.status === filter)

  return (
    <AppShell rightPanel={<AiCopilot />}>
      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h1 className="text-sm font-semibold">Vulnerabilities</h1>
          <div className="flex gap-2">
            <select className="input text-xs" value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="open">Open</option>
              <option value="fixed">Fixed</option>
            </select>
            <button className="btn-primary">New Scan</button>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-3">
          <div className="panel p-3">
            <div className="text-2xs text-soc-text-dim">Total</div>
            <div className="text-xl font-bold font-mono mt-1">{vulns.length}</div>
          </div>
          <div className="panel p-3">
            <div className="text-2xs text-soc-text-dim">Critical</div>
            <div className="text-xl font-bold font-mono text-red-400 mt-1">{vulns.filter((v) => v.severity === 'critical').length}</div>
          </div>
          <div className="panel p-3">
            <div className="text-2xs text-soc-text-dim">High</div>
            <div className="text-xl font-bold font-mono text-orange-400 mt-1">{vulns.filter((v) => v.severity === 'high').length}</div>
          </div>
          <div className="panel p-3">
            <div className="text-2xs text-soc-text-dim">Exploitable</div>
            <div className="text-xl font-bold font-mono text-red-400 mt-1">{vulns.filter((v) => v.exploit_available).length}</div>
          </div>
        </div>

        <div className="panel overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-soc-bg/50 border-b border-soc-border">
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">CVE</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Severity</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">CVSS</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Description</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Asset</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Exploit</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {filtered.map((v) => (
                <tr key={v.id} className="hover:bg-soc-sidebar-hover cursor-pointer">
                  <td className="px-3 py-2 font-mono text-soc-accent">{v.cve_id || 'N/A'}</td>
                  <td className="px-3 py-2">
                    <span className={`badge ${v.severity === 'critical' ? 'badge-critical' : v.severity === 'high' ? 'badge-high' : v.severity === 'medium' ? 'badge-medium' : 'badge-low'}`}>
                      {v.severity}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono">{v.cvss_score?.toFixed(1) || '—'}</td>
                  <td className="px-3 py-2 text-soc-text-dim max-w-xs truncate">{v.description}</td>
                  <td className="px-3 py-2">{v.asset_hostname || '—'}</td>
                  <td className="px-3 py-2">{v.exploit_available ? <span className="text-red-400">Yes</span> : <span className="text-soc-text-dim">No</span>}</td>
                  <td className="px-3 py-2"><span className="badge badge-info">{v.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  )
}
