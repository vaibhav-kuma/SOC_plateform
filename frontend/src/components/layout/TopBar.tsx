import { useNavigate, useLocation } from 'react-router-dom'
import { cn } from '../../utils/cn'

const NAV_ITEMS = [
  { label: 'Dashboard', path: '/' },
  { label: 'Assets', path: '/assets' },
  { label: 'Vulnerabilities', path: '/vulnerabilities' },
  { label: 'Threats', path: '/threats' },
  { label: 'Hunting', path: '/hunting' },
  { label: 'Incidents', path: '/incidents' },
  { label: 'Cloud', path: '/cloud' },
  { label: 'Intelligence', path: '/intelligence' },
  { label: 'Reports', path: '/reports' },
  { label: 'Settings', path: '/settings' },
]

export default function TopBar() {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <header className="h-9 bg-soc-topbar border-b border-soc-border flex items-center px-2 gap-1 shrink-0">
      <div className="flex items-center gap-2 mr-4 px-2">
        <svg className="w-4 h-4 text-soc-accent" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
        <span className="text-xs font-bold text-soc-accent tracking-wider">SOC PLATFORM</span>
      </div>

      <nav className="flex items-center gap-0.5">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.path}
            onClick={() => navigate(item.path)}
            className={cn(
              'px-3 py-1 text-2xs font-medium rounded transition-colors',
              location.pathname === item.path
                ? 'bg-soc-accent/10 text-soc-accent'
                : 'text-soc-text-dim hover:text-soc-text hover:bg-soc-sidebar-hover',
            )}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <div className="ml-auto flex items-center gap-3">
        <span className="text-2xs text-soc-text-dim">🔴 Active: 12</span>
        <span className="text-2xs text-soc-text-dim">🟡 Warning: 34</span>
        <span className="text-2xs text-soc-text-dim">🟢 Info: 156</span>
        <div className="w-px h-4 bg-soc-border" />
        <span className="text-xs font-mono text-soc-text-dim">jdoe</span>
      </div>
    </header>
  )
}
