import { useState } from 'react'
import AppShell from '../../components/layout/AppShell'
import AiCopilot from '../../components/modules/AiCopilot'

const EXAMPLE_QUERIES = [
  'Show all suspicious PowerShell executions in the last 24 hours',
  'Find hosts communicating with known malicious IPs',
  'Identify systems showing lateral movement behavior',
  'Show all failed logins from unusual geographic locations',
  'Find processes with encoded command line arguments',
  'Detect anomalous outbound DNS queries',
]

export default function HuntingPage() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<any[] | null>(null)
  const [loading, setLoading] = useState(false)

  const runQuery = async (q: string) => {
    setQuery(q)
    setLoading(true)
    try {
      const token = localStorage.getItem('access_token')
      const res = await fetch('/api/v1/hunting/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ query: q }),
      })
      const data = await res.json()
      setResults(data.results || [])
    } catch {
      setResults([])
    }
    setLoading(false)
  }

  return (
    <AppShell rightPanel={<AiCopilot />}>
      <div className="p-4 space-y-3">
        <div>
          <h1 className="text-sm font-semibold mb-1">AI Threat Hunting</h1>
          <p className="text-2xs text-soc-text-dim">Describe what you're looking for in natural language. AI converts your query into search parameters.</p>
        </div>

        <div className="flex gap-2">
          <input
            className="input flex-1"
            placeholder='e.g., "Find all suspicious PowerShell executions..."'
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runQuery(query)}
          />
          <button className="btn-primary" onClick={() => runQuery(query)} disabled={loading || !query.trim()}>
            {loading ? 'Hunting...' : 'Hunt'}
          </button>
        </div>

        <div>
          <p className="text-2xs text-soc-text-dim mb-2">Example queries:</p>
          <div className="flex flex-wrap gap-1.5">
            {EXAMPLE_QUERIES.map((q, i) => (
              <button
                key={i}
                onClick={() => runQuery(q)}
                className="text-2xs text-soc-accent bg-soc-accent/5 border border-soc-accent/20 rounded px-2 py-1 hover:bg-soc-accent/10"
              >
                {q.length > 60 ? q.slice(0, 60) + '...' : q}
              </button>
            ))}
          </div>
        </div>

        {loading && (
          <div className="panel p-8 text-center text-soc-text-dim text-sm">
            AI is translating your query and searching across data sources...
          </div>
        )}

        {results !== null && !loading && (
          <div className="panel overflow-hidden">
            <div className="panel-header">Results ({results.length})</div>
            {results.length === 0 ? (
              <div className="p-4 text-center text-soc-text-dim text-xs">No matching events found.</div>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-soc-bg/50 border-b border-soc-border">
                    <th className="text-left px-3 py-2 text-2xs text-soc-text-dim">Timestamp</th>
                    <th className="text-left px-3 py-2 text-2xs text-soc-text-dim">Source</th>
                    <th className="text-left px-3 py-2 text-2xs text-soc-text-dim">Host</th>
                    <th className="text-left px-3 py-2 text-2xs text-soc-text-dim">Event</th>
                    <th className="text-left px-3 py-2 text-2xs text-soc-text-dim">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-soc-border">
                  {results.map((r, i) => (
                    <tr key={i} className="hover:bg-soc-sidebar-hover">
                      <td className="px-3 py-2 text-2xs text-soc-text-dim">{r.timestamp}</td>
                      <td className="px-3 py-2"><span className="badge badge-info">{r.source}</span></td>
                      <td className="px-3 py-2 font-mono">{r.host}</td>
                      <td className="px-3 py-2">{r.event}</td>
                      <td className="px-3 py-2 text-soc-text-dim max-w-xs truncate">{r.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {results === null && !loading && (
          <div className="panel p-8 text-center text-soc-text-dim text-sm">
            Enter a query or select an example to start hunting for threats.
          </div>
        )}
      </div>
    </AppShell>
  )
}
