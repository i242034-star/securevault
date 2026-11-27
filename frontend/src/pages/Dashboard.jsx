import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { documentsAPI, auditAPI } from '../api'
import { PageHeader, StatCard, StatusBadge, Spinner, EmptyState } from '../components/ui'

export default function Dashboard() {
  const { user, activeKey, isAdmin } = useAuth()
  const [docs,    setDocs]    = useState([])
  const [logs,    setLogs]    = useState([])
  const [loading, setLoading] = useState(true)
  const [showGuide, setShowGuide] = useState(false)

  useEffect(() => {
    async function load() {
      try {
        const [dRes, lRes] = await Promise.allSettled([
          documentsAPI.list(),
          isAdmin ? auditAPI.logs({ per_page: 5 }) : Promise.resolve(null),
        ])
        if (dRes.status === 'fulfilled') setDocs(dRes.value.data.documents ?? [])
        if (lRes.status === 'fulfilled' && lRes.value) setLogs(lRes.value.data.logs ?? [])
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [isAdmin])

  const keyAttrs = activeKey?.bound_attributes
    ? (typeof activeKey.bound_attributes === 'string'
        ? JSON.parse(activeKey.bound_attributes)
        : activeKey.bound_attributes)
    : [user?.role_attr, user?.clearance_attr].filter(Boolean)

  return (
    <div>
      <PageHeader
        title={`Welcome, ${user?.username}`}
        subtitle="SecureVault — CP-ABE Secure Document Locker"
      />

      {/* Interactive System Guidance & Evaluation Guide (Requirement C13) */}
      <div className="mb-6 bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border border-cyan-500/30 rounded-xl p-4 shadow-lg">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-xl">📘</span>
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                SecureVault Evaluation Guide & Cryptographic Walkthrough
                <span className="text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 px-2 py-0.5 rounded-full">
                  CP-ABE BSW07 + AES-256-GCM
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                First-time user? Explore the 4-persona test matrix and mathematical access workflow.
              </p>
            </div>
          </div>
          <button
            onClick={() => setShowGuide(!showGuide)}
            className="px-3 py-1 bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 rounded text-xs font-semibold transition-colors whitespace-nowrap"
          >
            {showGuide ? 'Hide Walkthrough ▲' : 'Show Walkthrough ▼'}
          </button>
        </div>

        {showGuide && (
          <div className="mt-4 pt-4 border-t border-slate-800 grid md:grid-cols-3 gap-4 text-xs">
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
              <h4 className="font-bold text-cyan-400 mb-1">1. Cryptographic Model</h4>
              <p className="text-slate-400 leading-relaxed">
                Documents are locked with a boolean policy tree (e.g. <code>(Role:Engineer OR Role:Manager) AND Clearance:Level-3</code>).
                Keys embed user attributes. Access is verified mathematically by bilinear pairings over the BN254 curve, not by database checks.
              </p>
            </div>
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
              <h4 className="font-bold text-blue-400 mb-1">2. Persona Test Matrix</h4>
              <ul className="text-slate-400 space-y-1 font-mono">
                <li>• <strong className="text-white">Alice</strong>: Engineer + L3 → <span className="text-green-400 font-bold">Access GRANTED</span></li>
                <li>• <strong className="text-white">Charlie</strong>: Manager + L3 → <span className="text-green-400 font-bold">Access GRANTED</span></li>
                <li>• <strong className="text-white">Bob</strong>: Student + L3 → <span className="text-red-400 font-bold">Role DENIED</span></li>
                <li>• <strong className="text-white">David</strong>: Engineer + L2 → <span className="text-red-400 font-bold">Clearance DENIED</span></li>
              </ul>
            </div>
            <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
              <h4 className="font-bold text-purple-400 mb-1">3. Epoch Revocation</h4>
              <p className="text-slate-400 leading-relaxed">
                When an employee leaves or changes role, the Admin advances the Epoch (e.g. <code>Epoch 1 → 2</code>).
                Re-encrypted documents immediately reject old keys at the pairing layer without re-generating the master authority key.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard label="Encrypted Documents" value={loading ? '—' : docs.length} icon="🔒" accent="cyan" />
        <StatCard label="CP-ABE Key Version"  value={activeKey ? `v${activeKey.key_version}` : '—'} icon="🔑" accent="blue" />
        <StatCard label="System Role"         value={user?.system_role ?? '—'} icon="👤" accent="purple" />
        <StatCard label="Access Status"       value={activeKey ? 'Active' : 'No Key'} icon="✓" accent="green" />
      </div>

      <div className="grid lg:grid-cols-2 gap-6">
        {/* Identity card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
            Cryptographic Identity
          </h2>
          <div className="space-y-4">
            <Row label="Username"    value={user?.username} />
            <Row label="System Role" value={user?.system_role} />
            <div>
              <p className="text-xs text-slate-500 mb-2">Bound Attributes (embedded in private key)</p>
              <div className="flex flex-wrap gap-2">
                {keyAttrs.map(a => (
                  <span key={a} className="text-xs bg-cyan-500/15 text-cyan-400 border border-cyan-500/25 px-3 py-1 rounded-full font-mono">
                    {a}
                  </span>
                ))}
              </div>
            </div>
            {activeKey && (
              <div className="pt-2 border-t border-slate-800">
                <Row label="Key Version" value={`v${activeKey.key_version}`} />
                <Row label="Key Issued"  value={new Date(activeKey.issued_at).toLocaleDateString()} />
              </div>
            )}
          </div>
        </div>

        {/* Access policy card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
            Active Access Policy
          </h2>
          <div className="font-mono text-sm text-cyan-300 bg-slate-800 rounded-lg p-4 leading-relaxed">
            <span className="text-slate-500">( </span>
            <span className="text-blue-300">Role:Engineer</span>
            <span className="text-yellow-400"> OR </span>
            <span className="text-blue-300">Role:Manager</span>
            <span className="text-slate-500"> )</span>
            <span className="text-yellow-400"> AND </span>
            <span className="text-cyan-300">Clearance:Level-3</span>
          </div>
          <p className="text-xs text-slate-500 mt-3 leading-relaxed">
            Documents encrypted under this policy. The BSW07 bilinear pairing equation
            mathematically enforces access — a user without matching attributes cannot
            reconstruct the AES decryption key, regardless of application logic.
          </p>

          {/* Access matrix */}
          <div className="mt-4 space-y-2">
            {[
              { name: 'Alice',   attrs: 'Engineer + L3',  ok: true  },
              { name: 'Charlie', attrs: 'Manager + L3',   ok: true  },
              { name: 'Bob',     attrs: 'Student + L3',   ok: false },
              { name: 'David',   attrs: 'Engineer + L2',  ok: false },
            ].map(r => (
              <div key={r.name} className="flex items-center justify-between text-xs py-1.5 px-3 rounded-lg bg-slate-800/50">
                <span className="text-slate-300 font-medium">{r.name}</span>
                <span className="text-slate-500">{r.attrs}</span>
                <span className={r.ok ? 'text-green-400 font-semibold' : 'text-red-400 font-semibold'}>
                  {r.ok ? '✓ GRANTED' : '✕ DENIED'}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent documents */}
      <div className="mt-6 bg-slate-900 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            Recent Documents
          </h2>
          <Link to="/documents" className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
            View all →
          </Link>
        </div>
        {loading ? (
          <div className="flex justify-center py-8"><Spinner /></div>
        ) : docs.length === 0 ? (
          <EmptyState icon="📄" title="No documents yet" description="Upload a PDF from the Document Locker." />
        ) : (
          <div className="space-y-2">
            {docs.slice(0, 5).map(doc => (
              <div key={doc.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <span className="text-lg">📄</span>
                  <div>
                    <p className="text-sm text-white font-medium">{doc.original_filename}</p>
                    <p className="text-xs text-slate-500">
                      {(doc.file_size / 1024).toFixed(1)} KB · {doc.uploader_username} · {new Date(doc.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <Link to="/documents" className="text-xs text-cyan-400 hover:underline">Decrypt</Link>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent audit events (admin only) */}
      {isAdmin && logs.length > 0 && (
        <div className="mt-6 bg-slate-900 border border-slate-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
              Recent Security Events
            </h2>
            <Link to="/audit" className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors">
              Full audit log →
            </Link>
          </div>
          <div className="space-y-2">
            {logs.map(log => (
              <div key={log.id} className="flex items-center gap-3 p-3 bg-slate-800/50 rounded-lg text-xs">
                <StatusBadge value={log.action} />
                <StatusBadge value={log.status} />
                <span className="text-slate-300 font-medium">{log.username}</span>
                <span className="text-slate-500 truncate">{log.details}</span>
                <span className="text-slate-600 ml-auto whitespace-nowrap">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div className="flex items-center justify-between py-1.5">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="text-sm text-slate-200 font-medium">{value}</span>
    </div>
  )
}
