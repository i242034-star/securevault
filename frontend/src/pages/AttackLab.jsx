import { useEffect, useState } from 'react'
import { attacksAPI } from '../api'
import { PageHeader, Spinner, Alert } from '../components/ui'

const CATEGORY_STYLE = {
  'CP-ABE core':   'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  'Integrity':     'bg-teal-500/15 text-teal-300 border-teal-500/30',
  'Key lifecycle': 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  'Authentication':'bg-blue-500/15 text-blue-300 border-blue-500/30',
  'Side channel':  'bg-amber-500/15 text-amber-300 border-amber-500/30',
}

const BLURBS = {
  collusion:         'Bob (Student, L3) + David (Engineer, L2) merge key parts to fake {Engineer, L3}.',
  policy_tampering:  'Rewrite the stored ciphertext so the policy says Role:Student.',
  ciphertext_tamper: 'Flip single bits in the AES-256-GCM payload and tag.',
  revoked_key:       'Replay an Epoch:1 key after the system rotated to Epoch 2.',
  brute_force:       'Dictionary attack on login + offline PBKDF2 cracking cost.',
  timing_leak:       'Detect which usernames exist from login response time.',
}

function OutcomeBadge({ outcome }) {
  const blocked = outcome === 'BLOCKED'
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-bold border ${
      blocked
        ? 'bg-green-500/15 text-green-300 border-green-500/40'
        : 'bg-red-500/15 text-red-300 border-red-500/40'
    }`}>
      {blocked ? '🛡 ATTACK BLOCKED' : '⚠ ATTACK SUCCEEDED'}
    </span>
  )
}

function AttackCard({ attack, result, running, onRun }) {
  return (
    <div className="min-w-0 bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col">
      <div className="flex items-start justify-between gap-3 mb-2">
        <div>
          <span className={`text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full border ${CATEGORY_STYLE[attack.category] ?? 'bg-slate-700 text-slate-300 border-slate-600'}`}>
            {attack.category}
          </span>
          <h3 className="text-white font-semibold mt-2">{attack.name}</h3>
          <p className="text-xs text-slate-400 mt-1">{BLURBS[attack.id]}</p>
        </div>
        <button
          onClick={onRun}
          disabled={running}
          title="Runs the attack against an isolated sandbox authority (no real keys are touched)"
          className="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 disabled:opacity-50 flex items-center gap-2"
        >
          {running ? <><Spinner size="sm" />Running…</> : '▶ Launch'}
        </button>
      </div>

      {result && (
        <div className="mt-3 pt-3 border-t border-slate-800 space-y-3 text-xs">
          <div className="flex items-center justify-between">
            <OutcomeBadge outcome={result.outcome} />
            <span className="text-slate-500 font-mono">{result.duration_ms} ms</span>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider text-[10px] mb-1">Attacker goal</p>
            <p className="text-slate-300 leading-relaxed">{result.attacker_goal}</p>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider text-[10px] mb-1">What happened</p>
            <ol className="space-y-1 font-mono text-[11px] text-slate-300 bg-slate-950/70 rounded-lg p-3 border border-slate-800">
              {result.steps.map((s, i) => (
                <li key={i} className="flex gap-2">
                  <span className="text-slate-600">{i + 1}.</span>
                  <span className="min-w-0 [overflow-wrap:anywhere]">{s}</span>
                </li>
              ))}
            </ol>
          </div>
          <div>
            <p className="text-slate-500 uppercase tracking-wider text-[10px] mb-1">Why it failed — countermeasure</p>
            <p className="text-green-200/90 leading-relaxed bg-green-500/5 border border-green-500/20 rounded-lg p-3">
              {result.countermeasure}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}

export default function AttackLab() {
  const [attacks, setAttacks] = useState([])
  const [results, setResults] = useState({})
  const [running, setRunning] = useState({})
  const [error, setError]     = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    attacksAPI.list()
      .then(({ data }) => setAttacks(data.attacks))
      .catch(() => setError('Could not load the attack catalogue.'))
      .finally(() => setLoading(false))
  }, [])

  async function run(id) {
    setRunning(r => ({ ...r, [id]: true }))
    setError('')
    try {
      const { data } = await attacksAPI.run(id)
      setResults(r => ({ ...r, [id]: data }))
    } catch (err) {
      setError(err.response?.data?.message ?? `Attack '${id}' failed to run.`)
    } finally {
      setRunning(r => ({ ...r, [id]: false }))
    }
  }

  async function runAll() {
    for (const a of attacks) {
      // sequential on purpose: keeps timing measurements clean
      await run(a.id)
    }
  }

  const done = Object.values(results)
  const blocked = done.filter(r => r.outcome === 'BLOCKED').length
  const anyRunning = Object.values(running).some(Boolean)

  return (
    <div>
      <PageHeader
        title="Attack Lab"
        subtitle="Launch real attacks against the cryptography and watch the countermeasures hold"
      >
        <button
          onClick={runAll}
          disabled={loading || anyRunning}
          className="px-4 py-2 text-sm font-semibold rounded-lg bg-red-500 hover:bg-red-400 text-white disabled:opacity-50"
        >
          {anyRunning ? 'Running…' : '▶ Run all attacks'}
        </button>
      </PageHeader>

      <div className="mb-6 bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs text-slate-400 leading-relaxed flex gap-3">
        <span className="text-lg">🧪</span>
        <p>
          Each attack runs against a <strong className="text-slate-200">fresh sandbox Trusted Authority</strong> (its own
          BSW07 master key) with genuine Charm-Crypto pairings, AES-256-GCM and PBKDF2. Nothing touches your real keys or
          documents, and no key material is returned — only the verdict, the steps and the timings.
          Every run is written to the tamper-evident audit log as <code className="text-cyan-300">ATTACK_SIMULATION</code>.
        </p>
      </div>

      {done.length > 0 && (
        <div className="mb-6 flex items-center gap-3 text-sm">
          <span className="text-slate-400">Scoreboard:</span>
          <span className="font-bold text-green-300">{blocked} blocked</span>
          <span className="text-slate-600">/</span>
          <span className="text-slate-300">{done.length} launched</span>
          {done.length - blocked > 0 && (
            <span className="font-bold text-red-300">· {done.length - blocked} succeeded</span>
          )}
        </div>
      )}

      {error && <div className="mb-4"><Alert type="error">{error}</Alert></div>}

      {loading ? (
        <div className="flex justify-center py-20"><Spinner /></div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 items-start">
          {attacks.map(a => (
            <AttackCard
              key={a.id}
              attack={a}
              result={results[a.id]}
              running={!!running[a.id]}
              onRun={() => run(a.id)}
            />
          ))}
        </div>
      )}
    </div>
  )
}
