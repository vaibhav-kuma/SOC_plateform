import { useNavigate, useLocation } from 'react-router-dom'
import { cn } from '../../utils/cn'

const SIDEBAR_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: '📊', path: '/' },
  { id: 'assets', label: 'Assets', icon: '🖥', path: '/assets' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '🔍', path: '/vulnerabilities' },
  { id: 'edr', label: 'Endpoint Detection', icon: '⚡', path: '/threats' },
  { id: 'ndr', label: 'Network Detection', icon: '🌐', path: '/threats' },
  { id: 'intel', label: 'Threat Intelligence', icon: '🧠', path: '/intelligence' },
  { id: 'hunting', label: 'Threat Hunting', icon: '🎯', path: '/hunting' },
  { id: 'incidents', label: 'Incident Response', icon: '🚨', path: '/incidents' },
  { id: 'cloud', label: 'Cloud Security', icon: '☁️', path: '/cloud' },
  { id: 'identity', label: 'Identity Security', icon: '🔑', path: '/settings' },
  { id: 'email', label: 'Email Security', icon: '📧', path: '/settings' },
  { id: 'autosoc', label: 'Autonomous SOC', icon: '🤖', path: '/settings' },
  { id: 'reports', label: 'Reports', icon: '📄', path: '/reports' },
  { id: 'settings', label: 'Settings', icon: '⚙️', path: '/settings' },
]

export default function Sidebar() {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <aside className="w-48 bg-soc-sidebar border-r border-soc-border flex flex-col shrink-0 overflow-y-auto">
      <div className="p-2 border-b border-soc-border">
        <div className="relative">
          <svg className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-soc-text-dim" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            className="w-full bg-soc-bg border border-soc-border rounded pl-7 pr-2 py-1 text-2xs text-soc-text placeholder-soc-text-dim/40 focus:outline-none focus:border-soc-accent"
            placeholder="Search modules..."
          />
        </div>
      </div>

      <nav className="flex-1 py-1">
        {SIDEBAR_ITEMS.map((item) => (
          <button
            key={item.id}
            onClick={() => navigate(item.path)}
            className={cn(
              'w-full flex items-center gap-2 px-3 py-1.5 text-xs transition-colors',
              location.pathname === item.path
                ? 'bg-soc-accent/10 text-soc-accent border-l-2 border-soc-accent'
                : 'text-soc-text-dim hover:text-soc-text hover:bg-soc-sidebar-hover',
            )}
          >
            <span className="text-sm">{item.icon}</span>
            <span>{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="p-3 border-t border-soc-border">
        <div className="text-2xs text-soc-text-dim space-y-1">
          <div className="flex justify-between">
            <span>Events/s</span>
            <span className="font-mono text-soc-accent">1,234</span>
          </div>
          <div className="flex justify-between">
            <span>Alerts</span>
            <span className="font-mono text-red-400">12</span>
          </div>
          <div className="flex justify-between">
            <span>Risk Score</span>
            <span className="font-mono text-orange-400">7.2</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
