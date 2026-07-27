import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../../services/api'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [mfaSession, setMfaSession] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const { data } = await api.post('/auth/login', { email, password })

      if (data.mfa_required) {
        setMfaSession(data.mfa_session_id)
        return
      }

      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)
      navigate('/')
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed')
    }
    setLoading(false)
  }

  const handleMFA = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')

    try {
      const { data } = await api.post('/auth/mfa/verify', {
        mfa_session_id: mfaSession,
        code: mfaCode,
      })
      localStorage.setItem('access_token', data.access_token)
      localStorage.setItem('refresh_token', data.refresh_token)
      navigate('/')
    } catch (err: any) {
      setError(err.response?.data?.detail || 'MFA verification failed')
    }
    setLoading(false)
  }

  return (
    <div className="h-screen flex items-center justify-center bg-soc-bg">
      <div className="w-96 panel p-6">
        <div className="text-center mb-6">
          <svg className="w-10 h-10 text-soc-accent mx-auto mb-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
          <h1 className="text-lg font-bold text-soc-text">SOC Platform</h1>
          <p className="text-xs text-soc-text-dim mt-1">Unified Security Operations</p>
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded px-3 py-2 mb-4 text-xs text-red-400">{error}</div>
        )}

        {!mfaSession ? (
          <form onSubmit={handleLogin} className="space-y-3">
            <div>
              <label className="text-2xs text-soc-text-dim block mb-1">Email</label>
              <input className="input w-full" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="analyst@soc.local" required />
            </div>
            <div>
              <label className="text-2xs text-soc-text-dim block mb-1">Password</label>
              <input className="input w-full" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" required />
            </div>
            <button className="btn-primary w-full py-2" disabled={loading}>
              {loading ? 'Authenticating...' : 'Sign In'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleMFA} className="space-y-3">
            <p className="text-xs text-soc-text-dim text-center">Enter the code from your authenticator app</p>
            <div>
              <label className="text-2xs text-soc-text-dim block mb-1">MFA Code</label>
              <input className="input w-full text-center text-lg tracking-widest" type="text" value={mfaCode} onChange={(e) => setMfaCode(e.target.value)} placeholder="000000" maxLength={6} required />
            </div>
            <button className="btn-primary w-full py-2" disabled={loading}>
              {loading ? 'Verifying...' : 'Verify'}
            </button>
          </form>
        )}

        <div className="mt-4 pt-4 border-t border-soc-border">
          <p className="text-2xs text-soc-text-dim text-center">Secured with JWT + MFA · RBAC Enabled</p>
        </div>
      </div>
    </div>
  )
}
