export default function StatusBar() {
  return (
    <div className="status-bar">
      <span className="text-green-400">● Online</span>
      <span className="w-px h-3 bg-soc-border" />
      <span>SOC Analyst: jdoe</span>
      <span className="w-px h-3 bg-soc-border" />
      <span>RBAC: Responder</span>
      <span className="w-px h-3 bg-soc-border" />
      <span className="font-mono">1,234 evt/s</span>
      <span className="w-px h-3 bg-soc-border" />
      <span>Session: 02:34:15</span>
      <span className="ml-auto text-2xs text-soc-text-dim">
        Connected to: api/v1 | ES: healthy | Kafka: healthy
      </span>
    </div>
  )
}
