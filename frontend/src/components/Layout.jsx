import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { authAPI } from '../api'
import { Alert, Spinner } from './ui'

const NAV = [
  { to: '/dashboard', label: 'Dashboard',      icon: '⊞' },
  { to: '/documents', label: 'Document Locker', icon: '🔒' },
  { to: '/attacks',   label: 'Attack Lab',      icon: '🧪' },
]
const ADMIN_NAV = [
  { to: '/admin',     label: 'Admin Panel',    icon: '⚙' },
  { to: '/audit',     label: 'Audit Logs',     icon: '📋' },
]

function NavItem({ to, label, icon }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-150 ${
          isActive
            ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/30'
            : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
        }`
      }
    >
      <span className="text-base w-5 text-center">{icon}</span>
      {label}
    </NavLink>
  )
}

export default function Layout() {
  const { user, activeKey, logout, isAdmin, refreshMe } = useAuth()
  const navigate = useNavigate()

  // Key claim modal state
  const [showClaimModal, setShowClaimModal] = useState(false)
  const [claimPassword, setClaimPassword]   = useState('')
  const [claiming, setClaiming]             = useState(false)
  const [claimError, setClaimError]         = useState('')
  const [claimSuccess, setClaimSuccess]     = useState('')

  function handleLogout() {
    logout()
    navigate('/login')
  }

  async function handleClaimKey(e) {
    e.preventDefault()
    if (!claimPassword) {
      setClaimError('Password is required to unlock and re-encrypt your key.')
      return
    }
    setClaiming(true)
    setClaimError('')
    setClaimSuccess('')
    try {
      const { data } = await authAPI.claimKey(claimPassword)
      setClaimSuccess(`Successfully activated Key v${data.key_info.version}!`)
      await refreshMe()
      setTimeout(() => {
        setShowClaimModal(false)
        setClaimPassword('')
        setClaimSuccess('')
      }, 1200)
    } catch (err) {
      setClaimError(err.response?.data?.message ?? 'Failed to claim key. Check password.')
    } finally {
      setClaiming(false)
    }
  }

  return (
    <div className="flex min-h-screen bg-slate-950">
      {/* ── Sidebar ───────────────────────────────────────────────── */}
      <aside className="w-64 flex-shrink-0 bg-slate-900 border-r border-slate-800 flex flex-col">
        {/* Logo */}
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white font-bold text-sm">SV</div>
            <div>
              <p className="text-sm font-bold text-white leading-none">SecureVault</p>
              <p className="text-xs text-slate-500 mt-0.5">CP-ABE Document Locker</p>
            </div>
          </div>
        </div>

        {/* User card */}
        <div className="p-4 border-b border-slate-800">
          <div className="bg-slate-800/60 rounded-lg p-3">
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Logged in as</p>
            <p className="text-sm font-semibold text-white">{user?.username}</p>
            <div className="mt-2 flex flex-wrap gap-1">
              <span className="text-xs bg-blue-500/15 text-blue-400 border border-blue-500/25 px-2 py-0.5 rounded-full">
                {user?.role_attr}
              </span>
              <span className="text-xs bg-cyan-500/15 text-cyan-400 border border-cyan-500/25 px-2 py-0.5 rounded-full">
                {user?.clearance_attr}
              </span>
              {isAdmin && (
                <span className="text-xs bg-purple-500/15 text-purple-400 border border-purple-500/25 px-2 py-0.5 rounded-full">
                  admin
                </span>
              )}
            </div>
            {activeKey && (
              <p className="text-xs text-slate-500 mt-2">
                🔑 Key v{activeKey.key_version} · active
              </p>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1">
          {NAV.map(n => <NavItem key={n.to} {...n} />)}
          {isAdmin && (
            <>
              <div className="pt-3 pb-1">
                <p className="text-xs text-slate-600 uppercase tracking-wider px-4">Administration</p>
              </div>
              {ADMIN_NAV.map(n => <NavItem key={n.to} {...n} />)}
            </>
          )}
        </nav>

        {/* Logout */}
        <div className="p-4 border-t border-slate-800">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm text-slate-400 hover:bg-red-500/10 hover:text-red-400 transition-all duration-150"
          >
            <span className="text-base w-5 text-center">⏻</span>
            Sign Out
          </button>
        </div>
      </aside>

      {/* ── Main content ──────────────────────────────────────────── */}
      <main className="flex-1 overflow-auto">
        {/* Top bar */}
        <header className="bg-slate-900/60 border-b border-slate-800 px-8 py-4 flex items-center justify-between backdrop-blur-sm sticky top-0 z-10">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-xs text-slate-500">System operational</span>
          </div>
          <div className="text-xs text-slate-500 font-mono">
            BSW07 CP-ABE · AES-256-GCM · Flask 3 · SQLite
          </div>
        </header>

        {/* Pending Key Claim Banner (Phase 4 Asynchronous Key Reissuance) */}
        {user?.pending_key_reissue && (
          <div className="bg-gradient-to-r from-amber-500/20 via-orange-500/20 to-amber-500/20 border-b border-amber-500/30 px-8 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3 text-amber-300 text-xs sm:text-sm">
              <span className="text-base">⚠️</span>
              <span>
                <strong>Key Rotation Pending:</strong> Your cryptographic attributes or epoch have been updated.
                Activate your newly generated private key to maintain document access.
              </span>
            </div>
            <button
              onClick={() => { setClaimError(''); setClaimSuccess(''); setClaimPassword(''); setShowClaimModal(true) }}
              className="ml-4 px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors whitespace-nowrap shadow-md shadow-amber-500/20"
            >
              🔑 Claim Updated Key
            </button>
          </div>
        )}

        <div className="p-8">
          <Outlet />
        </div>
      </main>

      {/* Claim Key Modal */}
      {showClaimModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
            <h2 className="text-lg font-semibold text-white mb-1">Claim Updated CP-ABE Private Key</h2>
            <p className="text-sm text-slate-400 mb-4">
              Enter your password to unlock and envelope-encrypt your new private key.
            </p>

            <div className="bg-slate-800 rounded-lg p-3 mb-4 text-xs text-slate-400 leading-relaxed">
              In SecureVault&apos;s zero-knowledge architecture, administrators never know or handle user passwords.
              The Trusted Authority generates your key and securely encrypts it using your password in transient memory.
            </div>

            {claimError && <div className="mb-4"><Alert type="error">{claimError}</Alert></div>}
            {claimSuccess && <div className="mb-4"><Alert type="success">{claimSuccess}</Alert></div>}

            <form onSubmit={handleClaimKey} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">Your Password</label>
                <input
                  type="password"
                  value={claimPassword}
                  onChange={e => setClaimPassword(e.target.value)}
                  placeholder="Enter your account password"
                  autoFocus
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:border-cyan-500 transition-colors"
                />
              </div>
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setShowClaimModal(false)}
                  className="flex-1 px-4 py-2 text-sm text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  Later
                </button>
                <button
                  type="submit"
                  disabled={claiming}
                  className="flex-1 px-4 py-2 text-sm font-semibold bg-amber-500 hover:bg-amber-400 disabled:opacity-50 text-slate-950 rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  {claiming ? <><Spinner size="sm" />Issuing…</> : 'Activate Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
