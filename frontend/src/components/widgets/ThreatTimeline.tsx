import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts'

const data = [
  { time: '00:00', threats: 4, alerts: 12 },
  { time: '04:00', threats: 7, alerts: 18 },
  { time: '08:00', threats: 15, alerts: 34 },
  { time: '12:00', threats: 22, alerts: 45 },
  { time: '16:00', threats: 18, alerts: 38 },
  { time: '20:00', threats: 9, alerts: 22 },
  { time: 'Now', threats: 12, alerts: 28 },
]

export default function ThreatTimeline() {
  return (
    <div className="panel">
      <div className="panel-header">Threat Timeline (24h)</div>
      <div className="p-3 h-40">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data}>
            <defs>
              <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 10 }} />
            <YAxis stroke="#475569" tick={{ fontSize: 10 }} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#111827',
                border: '1px solid #1e293b',
                borderRadius: '6px',
                fontSize: '12px',
              }}
            />
            <Area type="monotone" dataKey="threats" stroke="#ef4444" fill="url(#threatGrad)" strokeWidth={2} />
            <Line type="monotone" dataKey="alerts" stroke="#f97316" strokeWidth={2} dot={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
