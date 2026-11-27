import { useEffect, useState, useRef } from 'react'
import { documentsAPI } from '../api'
import { PageHeader, Spinner, Alert, EmptyState, Modal } from '../components/ui'

export default function Documents() {
  const [docs,       setDocs]       = useState([])
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState('')
  // Upload state
  const [uploading,  setUploading]  = useState(false)
  const [uploadMsg,  setUploadMsg]  = useState(null)  // { type, text }
  const fileRef = useRef(null)
  // Decrypt modal
  const [decryptTarget, setDecryptTarget] = useState(null)  // doc object
  const [decryptPwd,    setDecryptPwd]    = useState('')
  const [decrypting,    setDecrypting]    = useState(false)
  const [decryptError,  setDecryptError]  = useState('')

  async function fetchDocs() {
    try {
      const { data } = await documentsAPI.list()
      setDocs(data.documents ?? [])
    } catch {
      setError('Failed to load documents.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchDocs() }, [])

  /* ── Upload ──────────────────────────────────────────────────────── */
  async function handleUpload(e) {
    e.preventDefault()
    const file = fileRef.current?.files?.[0]
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.pdf')) {
      setUploadMsg({ type: 'error', text: 'Only PDF files are accepted.' })
      return
    }
    const form = new FormData()
    form.append('file', file)
    // Use default policy from backend
    setUploading(true)
    setUploadMsg(null)
    try {
      await documentsAPI.upload(form)
      setUploadMsg({ type: 'success', text: `"${file.name}" encrypted and stored successfully.` })
      fileRef.current.value = ''
      await fetchDocs()
    } catch (err) {
      const msg = err.response?.data?.message ?? 'Upload failed.'
      setUploadMsg({ type: 'error', text: msg })
    } finally {
      setUploading(false)
    }
  }

  /* ── Decrypt ─────────────────────────────────────────────────────── */
  async function handleDecrypt(e) {
    e.preventDefault()
    if (!decryptPwd) { setDecryptError('Password required to unlock your private key.'); return }
    setDecrypting(true)
    setDecryptError('')
    try {
      const { data } = await documentsAPI.decrypt(decryptTarget.id, decryptPwd)
      // Decode base64 PDF and trigger browser download
      const bytes   = Uint8Array.from(atob(data.content_base64), c => c.charCodeAt(0))
      const blob    = new Blob([bytes], { type: 'application/pdf' })
      const url     = URL.createObjectURL(blob)
      const anchor  = document.createElement('a')
      anchor.href   = url
      anchor.download = data.filename ?? decryptTarget.original_filename
      anchor.click()
      URL.revokeObjectURL(url)
      setDecryptTarget(null)
      setDecryptPwd('')
    } catch (err) {
      const status = err.response?.status
      const body   = err.response?.data
      if (status === 403) {
        setDecryptError(
          `CP-ABE ACCESS DENIED — ${body?.message ?? 'Your attributes do not satisfy the access policy.'}`
        )
      } else if (status === 422) {
        setDecryptError('Integrity failure: ciphertext has been tampered with.')
      } else if (status === 401) {
        setDecryptError('Wrong password — could not unlock your private key.')
      } else {
        setDecryptError(body?.message ?? 'Decryption failed.')
      }
    } finally {
      setDecrypting(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Document Locker"
        subtitle="All PDFs are encrypted at rest using AES-256-GCM. The AES key is protected by CP-ABE."
      />

      {/* Upload panel */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 mb-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
          Upload Confidential Document
        </h2>
        <form onSubmit={handleUpload} className="flex flex-col sm:flex-row gap-3">
          <input
            ref={fileRef}
            type="file"
            accept=".pdf"
            className="flex-1 text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-slate-700 file:text-slate-200 file:cursor-pointer hover:file:bg-slate-600 bg-slate-800 border border-slate-700 rounded-lg p-2 cursor-pointer"
          />
          <button
            type="submit"
            disabled={uploading}
            className="px-6 py-2.5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-900 font-semibold text-sm rounded-lg transition-colors flex items-center gap-2 whitespace-nowrap"
          >
            {uploading ? <><Spinner size="sm" />Encrypting…</> : '🔒 Encrypt & Upload'}
          </button>
        </form>
        {uploadMsg && (
          <div className="mt-3">
            <Alert type={uploadMsg.type}>{uploadMsg.text}</Alert>
          </div>
        )}
        <p className="text-xs text-slate-600 mt-3">
          Policy applied: <span className="text-cyan-700 font-mono">(Role:Engineer OR Role:Manager) AND Clearance:Level-3</span>
        </p>
      </div>

      {/* Document list */}
      {error && <Alert type="error">{error}</Alert>}

      {loading ? (
        <div className="flex justify-center py-16"><Spinner /></div>
      ) : docs.length === 0 ? (
        <EmptyState
          icon="🔒"
          title="No documents in vault"
          description="Upload a confidential PDF to get started. It will be encrypted immediately."
        />
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-6 py-3">Document</th>
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 py-3 hidden md:table-cell">Size</th>
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 py-3 hidden lg:table-cell">Uploader</th>
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 py-3 hidden lg:table-cell">Uploaded</th>
                <th className="text-left text-xs font-semibold text-slate-500 uppercase tracking-wider px-4 py-3">Policy</th>
                <th className="px-6 py-3" />
              </tr>
            </thead>
            <tbody>
              {docs.map((doc, i) => (
                <tr key={doc.id} className={`border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors ${i % 2 === 0 ? '' : 'bg-slate-900/50'}`}>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <span className="text-xl">📄</span>
                      <div>
                        <p className="text-white font-medium">{doc.original_filename}</p>
                        <p className="text-xs text-slate-500">ID #{doc.id}</p>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-4 text-slate-400 hidden md:table-cell">
                    {(doc.file_size / 1024).toFixed(1)} KB
                  </td>
                  <td className="px-4 py-4 text-slate-400 hidden lg:table-cell">
                    {doc.uploader_username}
                  </td>
                  <td className="px-4 py-4 text-slate-400 hidden lg:table-cell text-xs">
                    {new Date(doc.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-4">
                    <span className="text-xs font-mono text-cyan-600 bg-cyan-500/5 border border-cyan-500/15 px-2 py-1 rounded">
                      {doc.access_policy?.length > 35
                        ? doc.access_policy.slice(0, 35) + '…'
                        : doc.access_policy}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-right">
                    <button
                      onClick={() => { setDecryptTarget(doc); setDecryptError(''); setDecryptPwd('') }}
                      className="px-4 py-1.5 bg-blue-500/15 hover:bg-blue-500/25 text-blue-400 border border-blue-500/25 rounded-lg text-xs font-medium transition-colors"
                    >
                      🔓 Decrypt
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Decrypt modal */}
      {decryptTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
            <h2 className="text-lg font-semibold text-white mb-1">Decrypt Document</h2>
            <p className="text-sm text-slate-400 mb-4">
              <span className="text-white font-medium">{decryptTarget.original_filename}</span>
            </p>

            <div className="bg-slate-800 rounded-lg p-3 mb-4 text-xs text-slate-400 leading-relaxed">
              Your password will unlock your CP-ABE private key in backend memory.
              The backend will perform BSW07 decryption. If your attributes satisfy the policy,
              the AES key is recovered and the PDF is decrypted and returned to your browser.
              <span className="block mt-1 text-slate-600">Password is not stored or transmitted beyond this request.</span>
            </div>

            {decryptError && (
              <div className="mb-4">
                <Alert type={decryptError.startsWith('CP-ABE') ? 'warning' : 'error'}>
                  {decryptError}
                </Alert>
              </div>
            )}

            <form onSubmit={handleDecrypt} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5">Your Password</label>
                <input
                  type="password"
                  value={decryptPwd}
                  onChange={e => setDecryptPwd(e.target.value)}
                  placeholder="Unlocks your CP-ABE private key"
                  autoFocus
                  className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-600 focus:border-cyan-500 transition-colors"
                />
              </div>
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => { setDecryptTarget(null); setDecryptPwd(''); setDecryptError('') }}
                  className="flex-1 px-4 py-2.5 text-sm text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={decrypting}
                  className="flex-1 px-4 py-2.5 text-sm font-semibold bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-900 rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  {decrypting ? <><Spinner size="sm" />Decrypting…</> : '🔓 Decrypt & Download'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
