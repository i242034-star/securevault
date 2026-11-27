import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { Alert, Spinner } from '../components/ui'

export default function Login() {
  const { login } = useAuth()
  const navigate  = useNavigate()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!username.trim() || !password) {
      setError('Username and password are required.')
      return
    }
    setLoading(true)
    try {
      await login(username.trim(), password)
      navigate('/dashboard')
    } catch (err) {
      const msg = err.response?.data?.message ?? 'Login failed. Please try again.'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center px-4">
      {/* Decorative background blobs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
        <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative w-full max-w-sm">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/20 mb-4">
            <span className="text-white font-bold text-xl">SV</span>
          </div>
          <h1 className="text-2xl font-bold text-white">SecureVault</h1>
          <p className="text-slate-400 text-sm mt-1">CP-ABE Secure Document Locker</p>
        </div>

        {/* Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 shadow-2xl">
          <h2 className="text-lg font-semibold text-white mb-1">Sign in</h2>
          <p className="text-slate-500 text-sm mb-6">Your credentials authenticate your CP-ABE private key.</p>

          {error && (
            <div className="mb-4">
              <Alert type="error">{error}</Alert>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">Username</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="alice"
                autoComplete="username"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:border-cyan-500 transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-400 mb-1.5">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                autoComplete="current-password"
                className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:border-cyan-500 transition-colors"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-slate-900 font-semibold py-2.5 rounded-lg text-sm transition-all duration-150 flex items-center justify-center gap-2 mt-2"
            >
              {loading ? <><Spinner size="sm" /> Authenticating…</> : '🔐 Sign In'}
            </button>
          </form>
        </div>

        {/* Info footnote */}
        <div className="mt-6 p-4 bg-slate-900/50 border border-slate-800 rounded-xl">
          <p className="text-xs text-slate-500 text-center leading-relaxed">
            Your password unlocks your CP-ABE private key in backend memory.<br />
            <span className="text-cyan-600">Passwords are never stored in the browser.</span>
          </p>
        </div>

        {/* Demo credentials */}
        <div className="mt-4 p-4 bg-slate-900/50 border border-slate-800 rounded-xl">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2 text-center">Demo Users</p>
          <div className="grid grid-cols-2 gap-1.5 text-xs text-slate-600">
            {[
              ['alice',   'Alice@2026!',   '✓ Engineer L3'],
              ['charlie', 'Charlie@2026!', '✓ Manager L3'],
              ['bob',     'Bob@2026!',     '✗ Student L3'],
              ['david',   'David@2026!',   '✗ Engineer L2'],
              ['admin',   'Admin@2026!',   '★ Admin'],
            ].map(([u, p, note]) => (
              <button
                key={u}
                type="button"
                onClick={() => { setUsername(u); setPassword(p) }}
                className="text-left p-2 rounded bg-slate-800/50 hover:bg-slate-800 transition-colors"
              >
                <span className="text-slate-300 font-medium">{u}</span>
                <span className="block text-slate-600">{note}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
