import { useEffect, useState } from 'react'
import AppShell from '../../components/layout/AppShell'
import AiCopilot from '../../components/modules/AiCopilot'
import type { Asset } from '../../types'
import api from '../../services/api'

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([])
  const [search, setSearch] = useState('')

  useEffect(() => {
    api.get('/assets').then(({ data }) => setAssets(data)).catch(() => {})
  }, [])

  return (
    <AppShell rightPanel={<AiCopilot />}>
      <div className="p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h1 className="text-sm font-semibold">Asset Inventory</h1>
          <div className="flex gap-2">
            <input className="input w-64" placeholder="Search hosts, IPs..." value={search} onChange={(e) => setSearch(e.target.value)} />
            <button className="btn-primary">New Scan</button>
          </div>
        </div>

        <div className="panel overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-soc-bg/50 border-b border-soc-border">
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Hostname</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">IP Address</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">OS</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Type</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Open Ports</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Risk</th>
                <th className="text-left px-3 py-2 text-2xs text-soc-text-dim font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-soc-border">
              {assets.filter((a) => !search || a.hostname?.toLowerCase().includes(search.toLowerCase()) || a.ip_address?.includes(search)).map((asset) => (
                <tr key={asset.id} className="hover:bg-soc-sidebar-hover cursor-pointer">
                  <td className="px-3 py-2 font-medium">{asset.hostname || 'Unknown'}</td>
                  <td className="px-3 py-2 font-mono text-soc-text-dim">{asset.ip_address}</td>
                  <td className="px-3 py-2 text-soc-text-dim">{asset.os || '—'}</td>
                  <td className="px-3 py-2">
                    <span className="badge badge-info">{asset.asset_type}</span>
                  </td>
                  <td className="px-3 py-2 font-mono">{asset.open_ports?.slice(0, 5).join(', ') || '—'}</td>
                  <td className="px-3 py-2">
                    <span className={`badge ${asset.risk_score >= 7 ? 'badge-critical' : asset.risk_score >= 4 ? 'badge-high' : 'badge-low'}`}>
                      {asset.risk_score?.toFixed(1)}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-2xs text-soc-text-dim">{asset.last_seen ? new Date(asset.last_seen).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {assets.length === 0 && (
            <div className="p-8 text-center text-soc-text-dim text-sm">
              No assets found. Run a discovery scan to get started.
            </div>
          )}
        </div>
      </div>
    </AppShell>
  )
}
