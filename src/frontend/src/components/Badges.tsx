import { clsx } from 'clsx'

// --- Severity Badge ---
const sevColors: Record<string, string> = {
  CRITICAL: 'bg-red-900/40 text-red-400 border border-red-700',
  HIGH:     'bg-orange-900/40 text-orange-400 border border-orange-700',
  MEDIUM:   'bg-yellow-900/40 text-yellow-400 border border-yellow-700',
  LOW:      'bg-slate-800 text-slate-400 border border-slate-600',
}
export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded font-mono', sevColors[severity] ?? sevColors.LOW)}>
      {severity}
    </span>
  )
}

// --- Source Type Badge ---
const srcColors: Record<string, string> = {
  SIEM:         'bg-purple-900/40 text-purple-300 border border-purple-700',
  CYBER_SENSOR: 'bg-cyan-900/40 text-cyan-300 border border-cyan-700',
  SATELLITE:    'bg-green-900/40 text-green-300 border border-green-700',
  INTEL_REPORT: 'bg-amber-900/40 text-amber-300 border border-amber-700',
}
export function SourceBadge({ sourceType }: { sourceType: string }) {
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded font-mono', srcColors[sourceType] ?? 'bg-slate-800 text-slate-300')}>
      {sourceType.replace('_', ' ')}
    </span>
  )
}

// --- Classification Badge ---
const classColors: Record<string, string> = {
  GENUINE_THREAT: 'bg-red-900/50 text-red-300 border border-red-600',
  FALSE_POSITIVE: 'bg-emerald-900/50 text-emerald-300 border border-emerald-600',
  UNCLASSIFIED:   'bg-slate-800 text-slate-400 border border-slate-600',
}
export function ClassificationBadge({ classification }: { classification: string }) {
  const labels: Record<string, string> = {
    GENUINE_THREAT: '⚠ GENUINE THREAT',
    FALSE_POSITIVE: '✓ FALSE POSITIVE',
    UNCLASSIFIED:   '? UNCLASSIFIED',
  }
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded font-semibold tracking-wide', classColors[classification] ?? classColors.UNCLASSIFIED)}>
      {labels[classification] ?? classification}
    </span>
  )
}

// --- Agreement Badge ---
const agreeColors: Record<string, string> = {
  AGREES:    'bg-emerald-900/50 text-emerald-300 border border-emerald-600',
  DISAGREES: 'bg-red-900/50 text-red-300 border border-red-600',
  PARTIAL:   'bg-amber-900/50 text-amber-300 border border-amber-600',
  NOT_ANALYSED: 'bg-slate-800 text-slate-500 border border-slate-700',
}
export function AgreementBadge({ status }: { status: string }) {
  const icons: Record<string, string> = { AGREES: '✓', DISAGREES: '✗', PARTIAL: '~' }
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded font-semibold', agreeColors[status] ?? agreeColors.NOT_ANALYSED)}>
      {icons[status] ?? '?'} {status.replace('_', ' ')}
    </span>
  )
}

// --- Risk Score Gauge ---
export function RiskScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? 'text-red-400' : score >= 60 ? 'text-orange-400' : score >= 40 ? 'text-yellow-400' : 'text-green-400'
  return (
    <span className={clsx('text-2xl font-bold tabular-nums', color)}>
      {score.toFixed(1)}
      <span className="text-sm text-slate-500 ml-0.5">/100</span>
    </span>
  )
}

// --- Fired Rule Chip ---
export function FiredRuleChip({ rule }: { rule: string | null | undefined }) {
  if (!rule) return null
  return (
    <span className="text-xs px-2 py-0.5 rounded bg-blue-900/40 text-blue-300 border border-blue-700 font-mono">
      Rule {rule}
    </span>
  )
}

// --- Loading ---
export function Loading() {
  return <div className="text-slate-400 text-sm animate-pulse">Loading…</div>
}

// --- Error ---
export function ErrorMsg({ msg }: { msg: string }) {
  return <div className="text-red-400 text-sm">Error: {msg}</div>
}

// --- Card ---
export function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={clsx('bg-[#1a2035] border border-[#2e3a4e] rounded-lg p-4', className)}>
      {children}
    </div>
  )
}

// --- Section heading ---
export function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h2 className="text-slate-300 text-sm font-semibold uppercase tracking-widest mb-3">{children}</h2>
}
