/** Spinner — small inline loading indicator */
export function Spinner({ size = 'md' }) {
  const cls = size === 'sm' ? 'h-4 w-4 border' : 'h-6 w-6 border-2'
  return (
    <div className={`${cls} animate-spin rounded-full border-t-cyan-400 border-slate-700`} />
  )
}

/** StatusBadge — coloured pill for action/status values */
export function StatusBadge({ value }) {
  const map = {
    SUCCESS:         'bg-green-500/15 text-green-400 border-green-500/30',
    DENIED:          'bg-red-500/15 text-red-400 border-red-500/30',
    FAILED:          'bg-orange-500/15 text-orange-400 border-orange-500/30',
    ACTIVE:          'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
    AUTH_LOGIN:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
    KEY_ISSUANCE:    'bg-purple-500/15 text-purple-400 border-purple-500/30',
    DOC_UPLOAD:      'bg-teal-500/15 text-teal-400 border-teal-500/30',
    DECRYPT_SUCCESS: 'bg-green-500/15 text-green-400 border-green-500/30',
    DECRYPT_DENIED:  'bg-red-500/15 text-red-400 border-red-500/30',
    DECRYPT_FAILED:  'bg-orange-500/15 text-orange-400 border-orange-500/30',
    ATTRIBUTE_CHANGE:'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
    ATTACK_SIMULATION:'bg-red-500/15 text-red-300 border-red-500/30',
    AUTH_LOCKOUT:    'bg-red-500/15 text-red-400 border-red-500/30',
  }
  const cls = map[value] ?? 'bg-slate-700 text-slate-400 border-slate-600'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${cls}`}>
      {value}
    </span>
  )
}

/** Alert — inline coloured message box */
export function Alert({ type = 'error', children }) {
  const styles = {
    error:   'bg-red-500/10 border-red-500/30 text-red-300',
    success: 'bg-green-500/10 border-green-500/30 text-green-300',
    info:    'bg-blue-500/10 border-blue-500/30 text-blue-300',
    warning: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-300',
  }
  const icons = { error: '✕', success: '✓', info: 'ℹ', warning: '⚠' }
  return (
    <div className={`flex items-start gap-2 p-3 rounded-lg border text-sm ${styles[type]}`}>
      <span className="mt-0.5 font-bold">{icons[type]}</span>
      <span>{children}</span>
    </div>
  )
}

/** Modal — confirmation dialog */
export function Modal({ title, children, onConfirm, onCancel, confirmLabel = 'Confirm', danger = false }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-6">
        <h2 className="text-lg font-semibold text-white mb-3">{title}</h2>
        <div className="text-sm text-slate-400 mb-6">{children}</div>
        <div className="flex justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
              danger
                ? 'bg-red-500 hover:bg-red-600 text-white'
                : 'bg-cyan-500 hover:bg-cyan-600 text-slate-900 font-semibold'
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

/** PageHeader — consistent page title section */
export function PageHeader({ title, subtitle, children }) {
  return (
    <div className="flex items-start justify-between mb-8">
      <div>
        <h1 className="text-2xl font-bold text-white">{title}</h1>
        {subtitle && <p className="text-slate-400 text-sm mt-1">{subtitle}</p>}
      </div>
      {children && <div className="flex items-center gap-3">{children}</div>}
    </div>
  )
}

/** StatCard — metric tile used on Dashboard */
export function StatCard({ label, value, icon, accent = 'cyan' }) {
  const accents = {
    cyan:   'from-cyan-500/20 to-cyan-500/5 border-cyan-500/20 text-cyan-400',
    blue:   'from-blue-500/20 to-blue-500/5 border-blue-500/20 text-blue-400',
    purple: 'from-purple-500/20 to-purple-500/5 border-purple-500/20 text-purple-400',
    green:  'from-green-500/20 to-green-500/5 border-green-500/20 text-green-400',
  }
  return (
    <div className={`bg-gradient-to-br ${accents[accent]} border rounded-xl p-5`}>
      <div className="text-2xl mb-2">{icon}</div>
      <p className="text-3xl font-bold text-white">{value}</p>
      <p className="text-sm text-slate-400 mt-1">{label}</p>
    </div>
  )
}

/** EmptyState — placeholder when a list is empty */
export function EmptyState({ icon = '📭', title, description }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="text-5xl mb-4">{icon}</div>
      <h3 className="text-lg font-semibold text-slate-300 mb-1">{title}</h3>
      {description && <p className="text-sm text-slate-500 max-w-xs">{description}</p>}
    </div>
  )
}
