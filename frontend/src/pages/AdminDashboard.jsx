import { useEffect, useState, useCallback } from 'react'
import { adminAPI, documentsAPI } from '../api'
import { PageHeader, Spinner, Alert, EmptyState, StatusBadge } from '../components/ui'

const ROLE_OPTIONS = ['Role:Engineer', 'Role:Manager', 'Role:Student', 'Role:Analyst']
const CLR_OPTIONS  = ['Clearance:Level-1', 'Clearance:Level-2', 'Clearance:Level-3']

export default function AdminDashboard() {
  const [activeTab, setActiveTab] = useState('attributes') // 'attributes' | 'revocation'

  // Users state
  const [users, setUsers]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')

  // Documents & Epoch state
  const [docs, setDocs]           = useState([])
  const [epochInfo, setEpochInfo] = useState(null)

  // Edit attributes modal
  const [editTarget, setEditTarget]   = useState(null)
  const [editRole, setEditRole]       = useState('')
  const [editClear, setEditClear]     = useState('')
  const [customTags, setCustomTags]   = useState([])
  const [newTagInput, setNewTagInput] = useState('')
  const [savingAttr, setSavingAttr]   = useState(false)
  const [saveMsg, setSaveMsg]         = useState(null)

  // Advance Epoch modal
  const [showAdvanceModal, setShowAdvanceModal] = useState(false)
  const [advanceReason, setAdvanceReason]       = useState('')
  const [advancing, setAdvancing]               = useState(false)
  const [advanceMsg, setAdvanceMsg]             = useState(null)

  // Re-encryption modal
  const [reencryptTarget, setReencryptTarget] = useState(null) // null for all, doc object for single
  const [reencryptPwd, setReencryptPwd]       = useState('')
  const [reencrypting, setReencrypting]       = useState(false)
  const [reencryptResult, setReencryptResult] = useState(null)

  // Live Verification state
  const [verifyDocId, setVerifyDocId]       = useState('')
  const [verifyUserId, setVerifyUserId]     = useState('')
  const [verifyUserPwd, setVerifyUserPwd]   = useState('')
  const [verifyOldVer, setVerifyOldVer]     = useState('1')
  const [verifyNewVer, setVerifyNewVer]     = useState('3')
  const [verifyUserKeys, setVerifyUserKeys] = useState([])
  const [verifying, setVerifying]           = useState(false)
  const [verifyResult, setVerifyResult]     = useState(null)
  const [verifyError, setVerifyError]       = useState('')

  // Key history drawer
  const [historyUser, setHistoryUser] = useState(null)
  const [history, setHistory]         = useState([])
  const [historyLoad, setHistoryLoad] = useState(false)

  const loadUserKeyVersions = useCallback(async (userId, userList = users) => {
    if (!userId) {
      setVerifyUserKeys([])
      return
    }
    try {
      const { data } = await adminAPI.getKeyHistory(userId)
      const keys = data.key_history ?? []
      setVerifyUserKeys(keys)
      if (keys.length > 0) {
        const activeKey = keys.find(k => k.is_active) || keys[0]
        const oldKey = keys.filter(k => k.version !== activeKey.version).slice(-1)[0] || keys[0]
        setVerifyNewVer(String(activeKey.version))
        setVerifyOldVer(String(oldKey.version))
      }
    } catch {
      const userObj = userList.find(u => String(u.id) === String(userId))
      if (userObj?.active_key?.version) {
        setVerifyNewVer(String(userObj.active_key.version))
        setVerifyOldVer('1')
      }
    }
  }, [users])

  const fetchData = useCallback(async () => {
    try {
      const [uRes, dRes, eRes] = await Promise.all([
        adminAPI.listUsers(),
        documentsAPI.list(),
        adminAPI.getEpoch(),
      ])
      const userList = uRes.data.users ?? []
      setUsers(userList)
      setDocs(dRes.data.documents ?? [])
      setEpochInfo(eRes.data ?? null)
      if (dRes.data.documents?.length > 0 && !verifyDocId) {
        setVerifyDocId(String(dRes.data.documents[0].id))
      }
      if (userList.length > 0 && !verifyUserId) {
        const defaultUser = userList.find(u => u.username === 'alice') || userList[0]
        if (defaultUser) {
          setVerifyUserId(String(defaultUser.id))
          loadUserKeyVersions(defaultUser.id, userList)
        }
      }
    } catch {
      setError('Failed to load administrative telemetry. Verify admin authorization.')
    } finally {
      setLoading(false)
    }
  }, [verifyDocId, verifyUserId, loadUserKeyVersions])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  /* ── Attribute Management ─────────────────────────────────────────── */
  function openEdit(u) {
    setEditTarget(u)
    setEditRole(u.role_attr)
    setEditClear(u.clearance_attr)
    setCustomTags(u.custom_attributes ? [...u.custom_attributes] : [])
    setNewTagInput('')
    setSaveMsg(null)
  }

  function addCustomTag() {
    const trimmed = newTagInput.trim()
    if (!trimmed) return
    if (!customTags.includes(trimmed)) {
      setCustomTags([...customTags, trimmed])
    }
    setNewTagInput('')
  }

  function removeCustomTag(tag) {
    setCustomTags(customTags.filter(t => t !== tag))
  }

  async function handleSaveAttributes(e) {
    e.preventDefault()
    setSavingAttr(true)
    setSaveMsg(null)
    try {
      const { data } = await adminAPI.updateAttributes(editTarget.id, {
        role_attr: editRole,
        clearance_attr: editClear,
        custom_attributes: customTags
      })
      setSaveMsg({
        type: 'success',
        text: `Attributes updated for ${editTarget.username}. User flagged to claim key with updated attributes.`
      })
      await fetchData()
    } catch (err) {
      setSaveMsg({ type: 'error', text: err.response?.data?.message ?? 'Attribute update failed.' })
    } finally {
      setSavingAttr(false)
    }
  }

  /* ── Advance Epoch ────────────────────────────────────────────────── */
  async function handleAdvanceEpoch(e) {
    e.preventDefault()
    if (!advanceReason.trim()) {
      setAdvanceMsg({ type: 'error', text: 'Administrative justification reason is required.' })
      return
    }
    setAdvancing(true)
    setAdvanceMsg(null)
    try {
      const { data } = await adminAPI.advanceEpoch(advanceReason.trim())
      setAdvanceMsg({ type: 'success', text: `System advanced to Epoch ${data.new_epoch}. Documents ready for re-encryption.` })
      setAdvanceReason('')
      await fetchData()
      setTimeout(() => setShowAdvanceModal(false), 1200)
    } catch (err) {
      setAdvanceMsg({ type: 'error', text: err.response?.data?.message ?? 'Epoch advance failed.' })
    } finally {
      setAdvancing(false)
    }
  }

  /* ── Re-encrypt Document ─────────────────────────────────────────── */
  async function handleReencrypt(e) {
    e.preventDefault()
    if (!reencryptPwd) {
      setReencryptResult({ type: 'error', text: 'Password required to unlock authorized key for CP-ABE recovery.' })
      return
    }
    setReencrypting(true)
    setReencryptResult(null)
    try {
      if (reencryptTarget === 'ALL') {
        const { data } = await adminAPI.reencryptAll(reencryptPwd)
        if (data.status === 'COMPLETED') {
          setReencryptResult({
            type: 'success',
            text: `Successfully re-encrypted ${data.reencrypted_count} of ${data.total_documents} documents under Epoch ${data.epoch}.`
          })
        } else {
          setReencryptResult({
            type: 'warning',
            text: `PARTIAL FAILURE: Re-encrypted ${data.reencrypted_count} documents, but ${data.failed_count} document(s) failed.`
          })
        }
      } else {
        const { data } = await adminAPI.reencryptDocument(reencryptTarget.id, reencryptPwd)
        setReencryptResult({
          type: 'success',
          text: `Document '${data.document.original_filename}' re-encrypted successfully to Epoch ${data.document.epoch}.`
        })
      }
      setReencryptPwd('')
      await fetchData()
    } catch (err) {
      setReencryptResult({
        type: 'error',
        text: err.response?.data?.message ?? 'Re-encryption aborted. Policy authorization failed.'
      })
    } finally {
      setReencrypting(false)
    }
  }

  /* ── Live Revocation Verification ─────────────────────────────────── */
  async function handleVerifyRevocation(e) {
    e.preventDefault()
    if (!verifyDocId || !verifyUserId || !verifyUserPwd) {
      setVerifyError('Please specify document, test user, and password.')
      return
    }
    setVerifying(true)
    setVerifyError('')
    setVerifyResult(null)
    try {
      const { data } = await adminAPI.verifyRevocation({
        doc_id: parseInt(verifyDocId),
        test_user_id: parseInt(verifyUserId),
        test_user_password: verifyUserPwd,
        old_key_version: parseInt(verifyOldVer),
        new_key_version: parseInt(verifyNewVer),
      })
      setVerifyResult(data)
    } catch (err) {
      setVerifyError(err.response?.data?.message ?? 'Verification failed.')
    } finally {
      setVerifying(false)
    }
  }

  /* ── Key History Drawer ───────────────────────────────────────────── */
  async function openHistory(u) {
    setHistoryUser(u)
    setHistoryLoad(true)
    try {
      const { data } = await adminAPI.getKeyHistory(u.id)
      setHistory(data.key_history ?? [])
    } finally {
      setHistoryLoad(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Admin Panel"
        subtitle="Dynamic Attribute Management & Epoch-Based Cryptographic Revocation"
      />

      {error && <div className="mb-6"><Alert type="error">{error}</Alert></div>}

      {/* Tabs */}
      <div className="flex border-b border-slate-800 mb-6 gap-2">
        <button
          onClick={() => setActiveTab('attributes')}
          className={`px-5 py-3 text-sm font-semibold border-b-2 transition-all duration-150 flex items-center gap-2 ${
            activeTab === 'attributes'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          <span>👥</span> Dynamic Attributes & Users
        </button>
        <button
          onClick={() => setActiveTab('revocation')}
          className={`px-5 py-3 text-sm font-semibold border-b-2 transition-all duration-150 flex items-center gap-2 ${
            activeTab === 'revocation'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
          }`}
        >
          <span>🔄</span> Revocation & Epoch Management
          {epochInfo && (
            <span className="ml-1 text-xs bg-cyan-500/20 text-cyan-300 px-2 py-0.5 rounded-full border border-cyan-500/30">
              Epoch {epochInfo.current_epoch}
            </span>
          )}
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : activeTab === 'attributes' ? (
        /* ══════════════════════════════════════════════════════════════ */
        /* TAB 1: DYNAMIC ATTRIBUTES & USERS                              */
        /* ══════════════════════════════════════════════════════════════ */
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-white">Attribute Authority Governance</h3>
              <p className="text-xs text-slate-400 mt-1">
                Administrators can dynamically assign roles, clearances, and custom attribute tags.
                In SecureVault&apos;s zero-knowledge model, administrators do not handle user passwords; users claim updated keys upon login.
              </p>
            </div>
            <div className="text-right">
              <span className="text-xs text-slate-500 block">Total Registered Users</span>
              <span className="text-xl font-bold text-cyan-400">{users.length}</span>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800">
                  {['User', 'Role & Clearance', 'Custom Attribute Tags', 'CP-ABE Key State', 'Actions'].map(h => (
                    <th key={h} className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-5 py-3">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.map((u, i) => (
                  <tr key={u.id} className={`border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors ${i % 2 ? 'bg-slate-900/30' : ''}`}>
                    <td className="px-5 py-4">
                      <p className="text-white font-medium">{u.username}</p>
                      <p className="text-xs text-slate-500">#{u.id} · {u.system_role}</p>
                    </td>
                    <td className="px-5 py-4">
                      <div className="space-y-1">
                        <span className="block text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded-full w-fit">{u.role_attr}</span>
                        <span className="block text-xs bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded-full w-fit">{u.clearance_attr}</span>
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {u.custom_attributes && u.custom_attributes.length > 0 ? (
                          u.custom_attributes.map(tag => (
                            <span key={tag} className="text-xs bg-purple-500/15 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded-full">
                              {tag}
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-slate-600 italic">None</span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-4">
                      {u.pending_key_reissue ? (
                        <span className="text-xs bg-amber-500/15 text-amber-300 border border-amber-500/30 px-2 py-1 rounded-full font-medium flex items-center gap-1 w-fit">
                          <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                          Claim Pending
                        </span>
                      ) : u.active_key ? (
                        <button onClick={() => openHistory(u)} className="text-left hover:opacity-80 transition-opacity">
                          <p className="text-xs text-green-400">v{u.active_key.version} · Active</p>
                          <p className="text-xs text-slate-500 mt-0.5 truncate max-w-[140px]">
                            {u.active_key.bound_attributes?.join(' · ')}
                          </p>
                        </button>
                      ) : (
                        <span className="text-xs text-red-400">No active key</span>
                      )}
                    </td>
                    <td className="px-5 py-4">
                      <button
                        onClick={() => openEdit(u)}
                        className="px-3 py-1.5 bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-400 border border-cyan-500/30 rounded text-xs font-semibold transition-colors"
                      >
                        ✏️ Edit Attributes
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        /* ══════════════════════════════════════════════════════════════ */
        /* TAB 2: REVOCATION & EPOCH MANAGEMENT                          */
        /* ══════════════════════════════════════════════════════════════ */
        <div className="space-y-8">
          {/* Epoch Telemetry Card */}
          <div className="bg-gradient-to-br from-slate-900 to-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-3">
                  <span className="text-2xl">⏳</span>
                  <div>
                    <h3 className="text-lg font-bold text-white flex items-center gap-2">
                      System Epoch {epochInfo?.current_epoch}
                      <StatusBadge value={epochInfo?.status ?? 'COMPLETED'} />
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Last advanced: {epochInfo?.created_at ? new Date(epochInfo.created_at).toLocaleString() : 'System initialization'} · by {epochInfo?.initiated_by}
                    </p>
                  </div>
                </div>
                <p className="text-xs text-slate-500 mt-2 font-mono">
                  Active Justification: {epochInfo?.reason}
                </p>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => setShowAdvanceModal(true)}
                  className="px-4 py-2 bg-gradient-to-r from-red-500 to-orange-600 hover:from-red-400 hover:to-orange-500 text-white font-semibold text-xs rounded-lg transition-colors shadow-lg shadow-red-500/20 flex items-center gap-2"
                >
                  ⚡ Advance System Epoch
                </button>
                <button
                  onClick={() => { setReencryptTarget('ALL'); setReencryptResult(null); setReencryptPwd('') }}
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors flex items-center gap-2"
                >
                  🔄 Re-encrypt All Documents
                </button>
              </div>
            </div>

            {/* Document distribution telemetry */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-6">
              <div className="p-3 bg-slate-800/40 rounded-lg">
                <span className="text-xs text-slate-500">Total Documents</span>
                <p className="text-xl font-bold text-white mt-1">{epochInfo?.document_stats?.total_documents ?? 0}</p>
              </div>
              <div className="p-3 bg-slate-800/40 rounded-lg border-l-2 border-green-500">
                <span className="text-xs text-green-400 font-medium">Current Epoch ({epochInfo?.current_epoch})</span>
                <p className="text-xl font-bold text-white mt-1">{epochInfo?.document_stats?.current_epoch_documents ?? 0}</p>
              </div>
              <div className="p-3 bg-slate-800/40 rounded-lg border-l-2 border-amber-500">
                <span className="text-xs text-amber-400 font-medium">Pending Re-encryption</span>
                <p className="text-xl font-bold text-white mt-1">
                  {(epochInfo?.document_stats?.legacy_documents ?? 0) + (epochInfo?.document_stats?.prior_epoch_documents ?? 0)}
                </p>
              </div>
              <div className="p-3 bg-slate-800/40 rounded-lg border-l-2 border-purple-500">
                <span className="text-xs text-purple-400 font-medium">Users Pending Key Claim</span>
                <p className="text-xl font-bold text-white mt-1">{epochInfo?.user_key_stats?.users_with_pending_keys ?? 0}</p>
              </div>
            </div>
          </div>

          {/* Re-encryption Status Banner */}
          {reencryptResult && (
            <Alert type={reencryptResult.type}>{reencryptResult.text}</Alert>
          )}

          {/* Documents Epoch Table */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h4 className="text-sm font-bold text-white">Vault Documents & Epoch Encapsulation</h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Documents bound to older epochs can be re-encrypted under Epoch {epochInfo?.current_epoch}.
                  Original ciphertexts are preserved safely until fresh encryption succeeds.
                </p>
              </div>
            </div>

            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800">
                  {['Document', 'Size', 'Uploader', 'Epoch', 'Access Policy', 'Re-encrypt'].map(h => (
                    <th key={h} className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-5 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {docs.map((doc, i) => {
                  const isCurrent = doc.epoch === epochInfo?.current_epoch
                  return (
                    <tr key={doc.id} className={`border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors ${i % 2 ? 'bg-slate-900/30' : ''}`}>
                      <td className="px-5 py-3">
                        <p className="text-white font-medium">{doc.original_filename}</p>
                        <p className="text-xs text-slate-500">ID #{doc.id}</p>
                      </td>
                      <td className="px-5 py-3 text-slate-400">{(doc.file_size / 1024).toFixed(1)} KB</td>
                      <td className="px-5 py-3 text-slate-400">{doc.uploader_username}</td>
                      <td className="px-5 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full border font-mono ${
                          isCurrent
                            ? 'bg-green-500/15 text-green-400 border-green-500/30'
                            : 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                        }`}>
                          {doc.epoch > 0 ? `Epoch ${doc.epoch}` : 'Legacy (Epoch 0)'}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        <span className="text-xs font-mono text-cyan-400 bg-cyan-500/5 border border-cyan-500/20 px-2 py-0.5 rounded">
                          {doc.access_policy?.length > 40 ? doc.access_policy.slice(0, 40) + '…' : doc.access_policy}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        <button
                          onClick={() => { setReencryptTarget(doc); setReencryptResult(null); setReencryptPwd('') }}
                          className="px-3 py-1 bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 rounded text-xs transition-colors"
                        >
                          Re-encrypt
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* ══════════════════════════════════════════════════════════ */}
          {/* LIVE CRYPTOGRAPHIC REVOCATION VERIFICATION DEMO WIDGET     */}
          {/* ══════════════════════════════════════════════════════════ */}
          <div className="bg-slate-900 border border-cyan-500/30 rounded-xl p-6 shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

            <div className="flex items-center gap-3 mb-4">
              <span className="text-2xl">🔬</span>
              <div>
                <h3 className="text-base font-bold text-white">Live Cryptographic Revocation Verification</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Demonstrates genuine BSW07 bilinear pairing evaluation: proves mathematically that an old key fails against re-encrypted ciphertext while an updated key succeeds.
                </p>
              </div>
            </div>

            {verifyError && <div className="mb-4"><Alert type="error">{verifyError}</Alert></div>}

            <form onSubmit={handleVerifyRevocation} className="grid grid-cols-1 md:grid-cols-5 gap-3 items-end mb-6 bg-slate-800/40 p-4 rounded-lg border border-slate-700/50">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Target Document</label>
                <select
                  value={verifyDocId}
                  onChange={e => setVerifyDocId(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"
                >
                  {docs.map(d => (
                    <option key={d.id} value={d.id}>#{d.id} - {d.original_filename} (Epoch {d.epoch})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Test User</label>
                <select
                  value={verifyUserId}
                  onChange={e => {
                    const uid = e.target.value
                    setVerifyUserId(uid)
                    loadUserKeyVersions(uid)
                  }}
                  className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"
                >
                  <option value="">Select test user...</option>
                  {users.map(u => (
                    <option key={u.id} value={u.id}>{u.username} ({u.role_attr})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">Old Key Version</label>
                {verifyUserKeys.length > 0 ? (
                  <select
                    value={verifyOldVer}
                    onChange={e => setVerifyOldVer(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"
                  >
                    {verifyUserKeys.map(k => (
                      <option key={k.version} value={k.version}>
                        v{k.version} {k.is_active ? '(Active)' : '(Superseded)'}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="number"
                    min="1"
                    value={verifyOldVer}
                    onChange={e => setVerifyOldVer(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"
                  />
                )}
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">New Key Version</label>
                {verifyUserKeys.length > 0 ? (
                  <select
                    value={verifyNewVer}
                    onChange={e => setVerifyNewVer(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"
                  >
                    {verifyUserKeys.map(k => (
                      <option key={k.version} value={k.version}>
                        v{k.version} {k.is_active ? '(Active)' : '(Superseded)'}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="number"
                    min="1"
                    value={verifyNewVer}
                    onChange={e => setVerifyNewVer(e.target.value)}
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"
                  />
                )}
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1">User Password</label>
                <div className="flex gap-2">
                  <input
                    type="password"
                    value={verifyUserPwd}
                    onChange={e => setVerifyUserPwd(e.target.value)}
                    placeholder="User password"
                    className="w-full bg-slate-800 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"
                  />
                  <button
                    type="submit"
                    disabled={verifying}
                    className="px-4 py-1.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs rounded transition-colors whitespace-nowrap"
                  >
                    {verifying ? <Spinner size="sm" /> : 'Run Proof'}
                  </button>
                </div>
              </div>
            </form>

            {/* Verification Result Card */}
            {verifyResult && (
              <div className="bg-slate-950 border border-slate-800 rounded-lg p-5">
                <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-4">
                  <span className="text-xs font-mono text-cyan-300">
                    Testing on: <strong>{verifyResult.original_filename}</strong> (Document Epoch: {verifyResult.document_epoch})
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Cryptographic Revocation Effective:</span>
                    <span className={`text-xs px-2.5 py-0.5 rounded-full font-bold border ${
                      verifyResult.cryptographic_revocation_effective
                        ? 'bg-green-500/15 text-green-400 border-green-500/30'
                        : 'bg-red-500/15 text-red-400 border-red-500/30'
                    }`}>
                      {verifyResult.cryptographic_revocation_effective ? '✓ VERIFIED' : 'FAILED'}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Old Key Evaluation */}
                  <div className={`p-4 bg-slate-900 border rounded-lg ${
                    !verifyResult.old_key_test.decryption_succeeded
                      ? 'border-red-500/30 bg-red-950/10'
                      : 'border-green-500/30 bg-green-950/10'
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <h5 className="text-xs font-bold text-white">Old Key (Version {verifyResult.old_key_test.version})</h5>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-bold border ${
                        !verifyResult.old_key_test.decryption_succeeded
                          ? 'bg-red-500/15 text-red-400 border-red-500/30'
                          : 'bg-green-500/15 text-green-400 border-green-500/30'
                      }`}>
                        {verifyResult.old_key_test.pairing_status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-2 font-mono">
                      Attributes: {verifyResult.old_key_test.bound_attributes?.join(' · ')}
                    </p>
                    <p className={`text-xs p-2 rounded border font-mono ${
                      !verifyResult.old_key_test.decryption_succeeded
                        ? 'text-red-300/90 bg-red-500/10 border-red-500/20'
                        : 'text-green-300/90 bg-green-500/10 border-green-500/20'
                    }`}>
                      {!verifyResult.old_key_test.decryption_succeeded
                        ? 'Mathematical result: Bilinear pairing failed to satisfy the policy tree. Access denied (Revocation verified).'
                        : 'Mathematical result: Bilinear pairing satisfied. Document decrypted.'}
                    </p>
                  </div>

                  {/* New Key Evaluation */}
                  <div className={`p-4 bg-slate-900 border rounded-lg ${
                    verifyResult.new_key_test.decryption_succeeded
                      ? 'border-green-500/30 bg-green-950/10'
                      : 'border-red-500/30 bg-red-950/10'
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <h5 className="text-xs font-bold text-white">New Key (Version {verifyResult.new_key_test.version})</h5>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-bold border ${
                        verifyResult.new_key_test.decryption_succeeded
                          ? 'bg-green-500/15 text-green-400 border-green-500/30'
                          : 'bg-red-500/15 text-red-400 border-red-500/30'
                      }`}>
                        {verifyResult.new_key_test.pairing_status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mb-2 font-mono">
                      Attributes: {verifyResult.new_key_test.bound_attributes?.join(' · ')}
                    </p>
                    <p className={`text-xs p-2 rounded border font-mono ${
                      verifyResult.new_key_test.decryption_succeeded
                        ? 'text-green-300/90 bg-green-500/10 border-green-500/20'
                        : 'text-red-300/90 bg-red-500/10 border-red-500/20'
                    }`}>
                      {verifyResult.new_key_test.decryption_succeeded
                        ? 'Mathematical result: Bilinear pairing satisfied. AES-256 key recovered and document decrypted.'
                        : `Mathematical result: Bilinear pairing failed to satisfy the policy tree. Reason: ${verifyResult.new_key_test.reason || 'Attributes do not satisfy policy'}.`}
                    </p>
                  </div>
                </div>

                <p className="text-xs text-slate-500 mt-4 text-center font-mono">
                  🔒 Audited Cryptographic Verification: Pairing evaluated in transient server memory. Zero private key bytes or decrypted payloads exposed to client.
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Edit Attributes Modal ─────────────────────────────────────── */}
      {editTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-lg mx-4 p-6">
            <h2 className="text-lg font-semibold text-white mb-1">Dynamic Attribute Management</h2>
            <p className="text-sm text-slate-400 mb-4">User: <span className="text-white font-bold">{editTarget.username}</span></p>

            <div className="bg-slate-800 rounded-lg p-3 mb-4 text-xs text-slate-400">
              In this zero-knowledge administration model, the administrator does not enter or need the user&apos;s password.
              Saving attribute changes will update the database and mark the user to claim their new key.
            </div>

            {saveMsg && <div className="mb-3"><Alert type={saveMsg.type}>{saveMsg.text}</Alert></div>}

            <form onSubmit={handleSaveAttributes} className="space-y-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1 font-medium">Role Attribute</label>
                <select
                  value={editRole}
                  onChange={e => setEditRole(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-cyan-500 transition-colors"
                >
                  {ROLE_OPTIONS.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>

              <div>
                <label className="block text-xs text-slate-400 mb-1 font-medium">Clearance Level Attribute</label>
                <select
                  value={editClear}
                  onChange={e => setEditClear(e.target.value)}
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:border-cyan-500 transition-colors"
                >
                  {CLR_OPTIONS.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              </div>

              {/* Dynamic Custom Tags Editor */}
              <div>
                <label className="block text-xs text-slate-400 mb-1 font-medium">Custom Attribute Tags (Add / Remove)</label>
                <div className="flex gap-2 mb-2">
                  <input
                    type="text"
                    value={newTagInput}
                    onChange={e => setNewTagInput(e.target.value)}
                    placeholder="e.g. Dept:Security or Project:Titan"
                    className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white"
                  />
                  <button
                    type="button"
                    onClick={addCustomTag}
                    className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white rounded-lg text-xs font-semibold"
                  >
                    + Add Tag
                  </button>
                </div>

                <div className="flex flex-wrap gap-1.5 p-2 bg-slate-800/40 border border-slate-700/50 rounded-lg min-h-[42px]">
                  {customTags.length > 0 ? (
                    customTags.map(tag => (
                      <span key={tag} className="inline-flex items-center gap-1.5 text-xs bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2.5 py-0.5 rounded-full">
                        {tag}
                        <button
                          type="button"
                          onClick={() => removeCustomTag(tag)}
                          className="hover:text-red-400 text-purple-300 font-bold"
                        >
                          ×
                        </button>
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500 italic">No custom tags assigned yet.</span>
                  )}
                </div>
              </div>

              <div className="flex gap-3 pt-3">
                <button
                  type="button"
                  onClick={() => setEditTarget(null)}
                  className="flex-1 py-2 text-sm text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={savingAttr}
                  className="flex-1 py-2 text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 rounded-lg flex items-center justify-center gap-2 transition-colors"
                >
                  {savingAttr ? <><Spinner size="sm" />Saving…</> : '✓ Update Attributes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Advance Epoch Modal ───────────────────────────────────────── */}
      {showAdvanceModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
            <h2 className="text-lg font-semibold text-white mb-1">Advance System Epoch</h2>
            <p className="text-sm text-slate-400 mb-4">
              Transition from Epoch {epochInfo?.current_epoch} to Epoch {(epochInfo?.current_epoch ?? 1) + 1}.
            </p>

            <div className="bg-slate-800 rounded-lg p-3 mb-4 text-xs text-slate-400 leading-relaxed">
              Advancing the epoch initiates Stage 1 of the revocation pipeline. Documents will subsequently be re-encrypted under the new epoch, and authorized users will receive updated keys. Revoked users will be excluded.
            </div>

            {advanceMsg && <div className="mb-4"><Alert type={advanceMsg.type}>{advanceMsg.text}</Alert></div>}

            <form onSubmit={handleAdvanceEpoch} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">Administrative Justification / Reason</label>
                <textarea
                  rows="3"
                  value={advanceReason}
                  onChange={e => setAdvanceReason(e.target.value)}
                  placeholder="e.g. Personnel departure: revoking Alice's Level-3 clearance"
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg p-2.5 text-xs text-white placeholder-slate-600 focus:border-cyan-500 transition-colors"
                />
              </div>

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setShowAdvanceModal(false)}
                  className="flex-1 px-4 py-2 text-sm text-slate-400 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={advancing}
                  className="flex-1 px-4 py-2 text-sm font-semibold bg-red-500 hover:bg-red-400 text-white rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  {advancing ? <Spinner size="sm" /> : 'Confirm Epoch Advance'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Re-encrypt Document Modal ─────────────────────────────────── */}
      {reencryptTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
            <h2 className="text-lg font-semibold text-white mb-1">
              {reencryptTarget === 'ALL' ? 'Re-encrypt All Vault Documents' : 'Re-encrypt Document'}
            </h2>
            <p className="text-sm text-slate-400 mb-4">
              Target Epoch: <span className="text-cyan-400 font-bold">Epoch {epochInfo?.current_epoch}</span>
            </p>

            <div className="bg-slate-800 rounded-lg p-3 mb-4 text-xs text-slate-400 leading-relaxed">
              Enter your administrator password to unlock your authorized private key.
              The backend will verify CP-ABE policy authorization, decrypt the document, generate a fresh AES-256 key, and encapsulate it under Epoch {epochInfo?.current_epoch}.
            </div>

            <form onSubmit={handleReencrypt} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">Your Password (Authorized Key Unlock)</label>
                <input
                  type="password"
                  value={reencryptPwd}
                  onChange={e => setReencryptPwd(e.target.value)}
                  placeholder="Enter administrator password"
                  autoFocus
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2 text-sm text-white focus:border-cyan-500 transition-colors"
                />
              </div>

              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setReencryptTarget(null)}
                  className="flex-1 px-4 py-2 text-sm text-slate-400 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={reencrypting}
                  className="flex-1 px-4 py-2 text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  {reencrypting ? <Spinner size="sm" /> : 'Start Re-encryption'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── Key History Drawer ────────────────────────────────────────── */}
      {historyUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-lg mx-4 p-6">
            <h2 className="text-lg font-semibold text-white mb-1">Key History</h2>
            <p className="text-sm text-slate-400 mb-4">{historyUser.username}</p>
            {historyLoad ? (
              <div className="flex justify-center py-8"><Spinner /></div>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {history.map(k => (
                  <div key={k.id} className={`p-3 rounded-lg border ${k.is_active ? 'border-green-500/30 bg-green-500/5' : 'border-slate-700 bg-slate-800/40'}`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-white">Version {k.version}</span>
                      <StatusBadge value={k.is_active ? 'ACTIVE' : 'DENIED'} />
                    </div>
                    <p className="text-xs text-slate-500">{new Date(k.issued_at).toLocaleString()}</p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      {(typeof k.bound_attributes === 'string'
                        ? JSON.parse(k.bound_attributes)
                        : k.bound_attributes
                      ).map(a => (
                        <span key={a} className="text-xs font-mono bg-slate-700 text-slate-300 px-2 py-0.5 rounded">{a}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
            <button onClick={() => setHistoryUser(null)}
              className="mt-4 w-full py-2 text-sm text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors">
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
