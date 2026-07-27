import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

const data = [
  { day: 'Mon', critical: 5, high: 12, medium: 20 },
  { day: 'Tue', critical: 3, high: 15, medium: 18 },
  { day: 'Wed', critical: 7, high: 8, medium: 22 },
  { day: 'Thu', critical: 4, high: 10, medium: 15 },
  { day: 'Fri', critical: 6, high: 14, medium: 19 },
  { day: 'Sat', critical: 2, high: 6, medium: 10 },
  { day: 'Sun', critical: 1, high: 4, medium: 8 },
]

export default function RiskTrends() {
  return (
    <div className="panel">
      <div className="panel-header">Risk Trends (7 Days)</div>
      <div className="p-3 h-40">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="day" stroke="#475569" tick={{ fontSize: 10 }} />
            <YAxis stroke="#475569" tick={{ fontSize: 10 }} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#111827',
                border: '1px solid #1e293b',
                borderRadius: '6px',
                fontSize: '12px',
              }}
            />
            <Bar dataKey="critical" fill="#ef4444" radius={[2, 2, 0, 0]} stackId="a" />
            <Bar dataKey="high" fill="#f97316" radius={[2, 2, 0, 0]} stackId="a" />
            <Bar dataKey="medium" fill="#eab308" radius={[2, 2, 0, 0]} stackId="a" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
