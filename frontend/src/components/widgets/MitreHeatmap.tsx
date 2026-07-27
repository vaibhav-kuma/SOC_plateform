const techniques = [
  { tactic: 'Reconnaissance', score: 3, max: 10 },
  { tactic: 'Resource Development', score: 2, max: 8 },
  { tactic: 'Initial Access', score: 8, max: 9 },
  { tactic: 'Execution', score: 9, max: 10 },
  { tactic: 'Persistence', score: 6, max: 12 },
  { tactic: 'Privilege Escalation', score: 7, max: 9 },
  { tactic: 'Defense Evasion', score: 8, max: 12 },
  { tactic: 'Credential Access', score: 7, max: 8 },
  { tactic: 'Discovery', score: 5, max: 8 },
  { tactic: 'Lateral Movement', score: 6, max: 7 },
  { tactic: 'Collection', score: 4, max: 6 },
  { tactic: 'C2', score: 8, max: 9 },
  { tactic: 'Exfiltration', score: 3, max: 5 },
  { tactic: 'Impact', score: 2, max: 7 },
]

function getColor(score: number, max: number) {
  const pct = score / max
  if (pct >= 0.8) return 'bg-red-500/30 text-red-300'
  if (pct >= 0.5) return 'bg-orange-500/20 text-orange-300'
  if (pct >= 0.3) return 'bg-yellow-500/20 text-yellow-300'
  return 'bg-green-500/10 text-green-300'
}

export default function MitreHeatmap() {
  return (
    <div className="panel">
      <div className="panel-header">MITRE ATT&CK Coverage</div>
      <div className="p-2 grid grid-cols-2 gap-1">
        {techniques.map((t) => (
          <div
            key={t.tactic}
            className={`px-2 py-1 rounded text-2xs font-medium flex justify-between items-center ${getColor(t.score, t.max)}`}
          >
            <span className="truncate">{t.tactic}</span>
            <span className="font-mono ml-2">{t.score}/{t.max}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
