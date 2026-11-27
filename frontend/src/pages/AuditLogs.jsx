import { useEffect, useState, useCallback } from 'react'
import { auditAPI } from '../api'
import { PageHeader, Spinner, Alert, EmptyState, StatusBadge } from '../components/ui'

const ACTION_COLORS = {
  AUTH_LOGIN:       'text-blue-400',
  KEY_ISSUANCE:     'text-purple-400',
  DOC_UPLOAD:       'text-teal-400',
  DECRYPT_SUCCESS:  'text-green-400',
  DECRYPT_DENIED:   'text-red-400',
  DECRYPT_FAILED:   'text-orange-400',
  ATTRIBUTE_CHANGE: 'text-yellow-400',
}

export default function AuditLogs() {
  const [logs,    setLogs]    = useState([])
  const [total,   setTotal]   = useState(0)
  const [page,    setPage]    = useState(1)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState('')

  // Filters
  const [filterAction,   setFilterAction]   = useState('')
  const [filterStatus,   setFilterStatus]   = useState('')
  const [filterUsername, setFilterUsername] = useState('')
  const [actions,        setActions]        = useState([])
  const [chainStatus,    setChainStatus]    = useState(null) // null | { loading, valid, verified_records, total_records, errors }

  const PER_PAGE = 20

  const handleVerifyChain = async () => {
    setChainStatus({ loading: true })
    try {
      const { data } = await auditAPI.verifyChain()
      setChainStatus({ loading: false, ...data })
    } catch (err) {
      const data = err.response?.data
      if (data && data.valid === false) {
        setChainStatus({ loading: false, ...data })
      } else {
        setChainStatus({ loading: false, valid: false, errors: ['Failed to reach verification endpoint.'] })
      }
    }
  }

  const fetchLogs = useCallback(async (p = 1) => {
    setLoading(true)
    setError('')
    try {
      const params = { page: p, per_page: PER_PAGE }
      if (filterAction)   params.action   = filterAction
      if (filterStatus)   params.status   = filterStatus
      if (filterUsername) params.username = filterUsername
      const { data } = await auditAPI.logs(params)
      setLogs(data.logs ?? [])
      setTotal(data.pagination?.total ?? 0)
      setPage(p)
    } catch (err) {
      if (err.response?.status === 403) {
        setError('Access denied — Audit logs are restricted to administrators.')
      } else {
        setError('Failed to load audit logs.')
      }
    } finally {
      setLoading(false)
    }
  }, [filterAction, filterStatus, filterUsername])

  useEffect(() => {
    auditAPI.actions()
      .then(r => setActions(r.data.actions ?? []))
      .catch(() => {})
    fetchLogs(1)
  }, [fetchLogs])

  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE))

  function handleFilter(e) {
    e.preventDefault()
    fetchLogs(1)
  }

  return (
    <div>
      <PageHeader
        title="Audit Logs"
        subtitle={`${total} security events recorded — admin access only`}
      >
        <div className="flex gap-2">
          <button
            onClick={handleVerifyChain}
            disabled={chainStatus?.loading}
            className="px-4 py-2 text-sm bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 rounded-lg transition-colors font-medium flex items-center gap-1.5"
          >
            {chainStatus?.loading ? 'Verifying Chain...' : '🛡️ Verify Chain Integrity'}
          </button>
          <button
            onClick={() => fetchLogs(page)}
            className="px-4 py-2 text-sm bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg transition-colors"
          >
            ↻ Refresh
          </button>
        </div>
      </PageHeader>

      {/* Cryptographic Chain Integrity Banner */}
      {chainStatus && !chainStatus.loading && (
        <div className={`p-4 mb-6 rounded-xl border ${
          chainStatus.valid
            ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
            : 'bg-rose-950/40 border-rose-500/40 text-rose-300'
        }`}>
          <div className="flex items-start justify-between">
            <div>
              <div className="font-semibold text-sm flex items-center gap-2">
                {chainStatus.valid ? (
                  <>
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    Cryptographic Hash Chain Verified (HMAC-SHA256)
                  </>
                ) : (
                  <>
                    <span className="w-2.5 h-2.5 rounded-full bg-rose-400"></span>
                    Audit Log Tampering / Broken Chain Detected!
                  </>
                )}
              </div>
              <p className="text-xs mt-1 text-slate-300">
                {chainStatus.valid
                  ? `All ${chainStatus.verified_records} audit events verified consecutively from Genesis block. Monotonic sequence, previous hash linkages, and HMAC signatures match.`
                  : `Integrity check failed: ${chainStatus.errors?.length} violation(s) identified.`}
              </p>
              {chainStatus.errors && chainStatus.errors.length > 0 && (
                <ul className="mt-2 text-xs list-disc list-inside font-mono bg-black/40 p-2.5 rounded text-rose-200">
                  {chainStatus.errors.map((err, idx) => (
                    <li key={idx}>{err}</li>
                  ))}
                </ul>
              )}
            </div>
            <button
              onClick={() => setChainStatus(null)}
              className="text-xs text-slate-400 hover:text-white ml-4"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Filter bar */}
      <form onSubmit={handleFilter} className="bg-slate-900 border border-slate-800 rounded-xl p-4 mb-6 flex flex-wrap gap-3 items-end">
        <div className="flex-1 min-w-36">
          <label className="block text-xs text-slate-500 mb-1">Action</label>
          <select
            value={filterAction}
            onChange={e => setFilterAction(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-cyan-500 transition-colors"
          >
            <option value="">All actions</option>
            {actions.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>
        <div className="flex-1 min-w-36">
          <label className="block text-xs text-slate-500 mb-1">Status</label>
          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-cyan-500 transition-colors"
          >
            <option value="">All statuses</option>
            {['SUCCESS', 'DENIED', 'FAILED'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="flex-1 min-w-36">
          <label className="block text-xs text-slate-500 mb-1">Username</label>
          <input
            type="text"
            value={filterUsername}
            onChange={e => setFilterUsername(e.target.value)}
            placeholder="Filter by user"
            className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:border-cyan-500 transition-colors"
          />
        </div>
        <button
          type="submit"
          className="px-5 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold text-sm rounded-lg transition-colors"
        >
          Apply
        </button>
        <button
          type="button"
          onClick={() => { setFilterAction(''); setFilterStatus(''); setFilterUsername(''); }}
          className="px-4 py-2 text-sm text-slate-500 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
        >
          Clear
        </button>
      </form>

      {error && <div className="mb-4"><Alert type="error">{error}</Alert></div>}

      {loading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : logs.length === 0 ? (
        <EmptyState icon="📋" title="No log entries" description="Security events will appear here as users interact with the system." />
      ) : (
        <>
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-slate-800">
                  {['Seq #', 'Timestamp', 'User', 'Action', 'Status', 'Details', 'IP', 'HMAC Hash'].map(h => (
                    <th key={h} className="text-left font-semibold text-slate-500 uppercase tracking-wider px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {logs.map((log, i) => (
                  <tr key={log.id} className={`border-b border-slate-800/40 hover:bg-slate-800/30 transition-colors ${i % 2 ? 'bg-slate-900/30' : ''}`}>
                    <td className="px-4 py-3 text-cyan-400 font-mono font-semibold">#{log.sequence_number ?? log.id}</td>
                    <td className="px-4 py-3 text-slate-500 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-white font-medium">{log.username}</td>
                    <td className="px-4 py-3">
                      <span className={`font-mono font-semibold ${ACTION_COLORS[log.action] ?? 'text-slate-400'}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge value={log.status} />
                    </td>
                    <td className="px-4 py-3 text-slate-400 max-w-xs truncate" title={log.details}>
                      {log.details}
                    </td>
                    <td className="px-4 py-3 text-slate-600 font-mono">{log.ip_address}</td>
                    <td className="px-4 py-3 text-slate-500 font-mono text-[10px] truncate max-w-[100px]" title={`Record Hash: ${log.record_hash}\nPrevious Hash: ${log.previous_hash}`}>
                      {log.record_hash ? `${log.record_hash.slice(0, 8)}...` : 'legacy'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 text-sm text-slate-500">
              <span>Page {page} of {totalPages} · {total} total events</span>
              <div className="flex gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => fetchLogs(page - 1)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded-lg transition-colors"
                >
                  ← Prev
                </button>
                <button
                  disabled={page >= totalPages}
                  onClick={() => fetchLogs(page + 1)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded-lg transition-colors"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
