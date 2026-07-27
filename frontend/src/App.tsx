import { Routes, Route, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import AssetsPage from './pages/Assets'
import VulnerabilitiesPage from './pages/Vulnerabilities'
import IncidentsPage from './pages/Incidents'
import HuntingPage from './pages/Hunting'
import LoginPage from './pages/Login'
import { useState, useEffect } from 'react'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('access_token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  const [ready, setReady] = useState(false)

  useEffect(() => {
    // Check auth on mount
    const token = localStorage.getItem('access_token')
    if (token) {
      setReady(true)
    } else {
      setReady(true)
    }
  }, [])

  if (!ready) return null

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
      <Route path="/assets" element={<PrivateRoute><AssetsPage /></PrivateRoute>} />
      <Route path="/vulnerabilities" element={<PrivateRoute><VulnerabilitiesPage /></PrivateRoute>} />
      <Route path="/incidents" element={<PrivateRoute><IncidentsPage /></PrivateRoute>} />
      <Route path="/hunting" element={<PrivateRoute><HuntingPage /></PrivateRoute>} />
      <Route path="/threats" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
      <Route path="/intelligence" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
      <Route path="/cloud" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
      <Route path="/reports" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
      <Route path="/settings" element={<PrivateRoute><Dashboard /></PrivateRoute>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
