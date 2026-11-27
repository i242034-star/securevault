/**
 * api.js — Centralised Axios instance for SecureVault
 * All requests are routed through the Vite dev-server proxy to http://127.0.0.1:5000
 */
import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT token from sessionStorage on every request
api.interceptors.request.use((config) => {
  const token = sessionStorage.getItem('sv_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Global response error handler — redirect to login on 401
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      sessionStorage.removeItem('sv_token')
      sessionStorage.removeItem('sv_user')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

export default api

// ── Auth ─────────────────────────────────────────────────────────────────────
export const authAPI = {
  login:    (username, password)      => api.post('/auth/login', { username, password }),
  me:       ()                        => api.get('/auth/me'),
  claimKey: (password)                => api.post('/auth/claim-key', { password }),
}

// ── Admin ────────────────────────────────────────────────────────────────────
export const adminAPI = {
  listUsers:        ()                                           => api.get('/admin/users'),
  updateAttributes: (userId, payload) =>
    api.put(`/admin/users/${userId}/attributes`, payload),
  reissueKey:       (userId, user_passphrase)                   =>
    api.post(`/admin/users/${userId}/reissue-key`, { user_passphrase }),
  getKeyHistory:    (userId)                                    => api.get(`/admin/users/${userId}/keys`),

  // Phase 4: Epoch & Revocation
  getEpoch:          ()                                         => api.get('/admin/epoch'),
  advanceEpoch:      (reason)                                   => api.post('/admin/epoch/advance', { reason }),
  reencryptDocument: (docId, password)                          => api.post(`/admin/epoch/reencrypt/${docId}`, { password }),
  reencryptAll:      (password)                                 => api.post('/admin/epoch/reencrypt-all', { password }),
  verifyRevocation:  (payload)                                  => api.post('/admin/revocation/verify', payload),
}

// ── Documents ─────────────────────────────────────────────────────────────────
export const documentsAPI = {
  list:    ()                        => api.get('/documents'),
  get:     (id)                      => api.get(`/documents/${id}`),
  upload:  (formData)                => api.post('/documents/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
  decrypt: (id, password)            => api.post(
    `/documents/${id}/decrypt?as_base64=true`,
    { password },
  ),
}

// ── Attack Lab ────────────────────────────────────────────────────────────────
export const attacksAPI = {
  list: ()   => api.get('/attacks'),
  run:  (id) => api.post(`/attacks/${id}/run`),
}

// ── Audit ─────────────────────────────────────────────────────────────────────
export const auditAPI = {
  logs:        (params = {})         => api.get('/audit/logs', { params }),
  actions:     ()                    => api.get('/audit/logs/actions'),
  userLogs:    (userId, params = {}) => api.get(`/audit/logs/user/${userId}`, { params }),
  verifyChain: ()                    => api.get('/audit/verify'),
}
