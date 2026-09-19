import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getDashboardStats, triggerFeedIngest } from '../api'
import { Card, SectionHeading, ClassificationBadge, Loading, ErrorMsg } from '../components/Badges'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'
import { Link } from 'react-router-dom'
import { Zap } from 'lucide-react'
import { getIncidents } from '../api'
import { SeverityBadge, AgreementBadge } from '../components/Badges'

const PIE_COLORS = { GENUINE_THREAT: '#f87171', FALSE_POSITIVE: '#34d399', UNCLASSIFIED: '#64748b' }

export default function Dashboard() {
  const qc = useQueryClient()
  const { data: stats, isLoading, error } = useQuery({
    queryKey: ['stats'],
    queryFn: getDashboardStats,
    refetchInterval: 30_000,
  })
  const { data: incData } = useQuery({
    queryKey: ['incidents', { page: 1, page_size: 5 }],
    queryFn: () => getIncidents({ page: 1, page_size: 5 }),
    refetchInterval: 30_000,
  })
  const ingest = useMutation({
    mutationFn: () => triggerFeedIngest('random'),
    onSuccess: () => setTimeout(() => qc.invalidateQueries(), 3000),
  })

  if (isLoading) return <Loading />
  if (error) return <ErrorMsg msg="Could not load dashboard stats" />

  const s = stats!
  const pieData = [
    { name: 'Genuine Threat', value: s.genuine_threat_count, key: 'GENUINE_THREAT' },
    { name: 'False Positive', value: s.false_positive_count, key: 'FALSE_POSITIVE' },
    { name: 'Unclassified', value: s.unclassified_count, key: 'UNCLASSIFIED' },
  ]
  const barData = [
    { name: 'Total Alerts', value: s.total_alerts },
    { name: 'Open Incidents', value: s.open_incidents },
    { name: 'P1 Incidents', value: s.p1_incidents },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-white">Threat Dashboard</h1>
        <button
          onClick={() => ingest.mutate()}
          disabled={ingest.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm disabled:opacity-50"
        >
          <Zap size={14} />
          {ingest.isPending ? 'Ingesting…' : 'Ingest Feed'}
        </button>
      </div>

      {/* Commander alert banner — shown when P1 incidents exist */}
      {s.p1_incidents > 0 && (
        <div className="flex items-center gap-3 bg-amber-900/20 border border-amber-600/50 rounded-lg px-4 py-3">
          <span className="text-amber-400 text-lg">⚠</span>
          <div className="flex-1">
            <span className="text-amber-300 font-semibold text-sm">COMMAND ALERT — </span>
            <span className="text-amber-200 text-sm">{s.p1_incidents} high-priority incident{s.p1_incidents !== 1 ? 's' : ''} require immediate attention.</span>
          </div>
          <Link to="/incidents?severity=CRITICAL" className="text-xs text-amber-400 border border-amber-600/50 rounded px-2 py-1 hover:bg-amber-900/30">
            View →
          </Link>
        </div>
      )}

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {[
          { label: 'Total Alerts', value: s.total_alerts, color: 'text-blue-400' },
          { label: 'Open Incidents', value: s.open_incidents, color: 'text-orange-400' },
          { label: 'P1 Incidents', value: s.p1_incidents, color: 'text-red-400' },
          { label: 'FP Rate', value: `${(s.false_positive_rate * 100).toFixed(1)}%`, color: 'text-emerald-400' },
          { label: 'False Positives', value: s.false_positive_count, color: 'text-emerald-400' },
          { label: 'Genuine Threats', value: s.genuine_threat_count, color: 'text-red-400' },
        ].map(({ label, value, color }) => (
          <Card key={label}>
            <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">{label}</div>
            <div className={`text-2xl font-bold tabular-nums ${color}`}>{value}</div>
          </Card>
        ))}
      </div>

      {/* FP Masking warning — ONLY shown when C6 rule specifically detected masking */}
      {(s.fp_masking_alerts ?? 0) > 0 && (
        <div className="flex items-start gap-3 bg-red-900/20 border border-red-600/60 rounded-lg px-4 py-4">
          <span className="text-red-400 text-2xl">🎭</span>
          <div className="flex-1">
            <div className="text-red-300 font-bold text-sm mb-1">
              FP MASKING ATTACK DETECTED — Rule C6
            </div>
            <p className="text-red-200 text-sm leading-relaxed">
              {s.fp_masking_alerts} alert{s.fp_masking_alerts !== 1 ? 's' : ''} were deliberately crafted
              to appear as false positives — but their cumulative pattern on the same asset/IP reveals
              a genuine intrusion attempt. The attacker knew the detection thresholds and deliberately
              stayed below them.
            </p>
            <p className="text-red-300/70 text-xs mt-1">
              Correlation Rule C6 fired — each alert alone = false positive, together = genuine threat.
            </p>
          </div>
          <Link to="/incidents" className="text-xs text-red-400 border border-red-600/50 rounded px-2 py-1 hover:bg-red-900/30 shrink-0 mt-1">
            Investigate →
          </Link>
        </div>
      )}

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <SectionHeading>Classification Breakdown</SectionHeading>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={70} label={({ name, value }) => `${name}: ${value}`}>
                {pieData.map(d => <Cell key={d.key} fill={PIE_COLORS[d.key as keyof typeof PIE_COLORS]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Card>
        <Card>
          <SectionHeading>Volume Summary</SectionHeading>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={barData}>
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#1a2035', border: '1px solid #2e3a4e' }} />
              <Bar dataKey="value" fill="#3b82d4" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Recent incidents — Signal vs Noise context */}
      <Card>
        <SectionHeading>Recent Incidents</SectionHeading>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-slate-500 text-xs border-b border-[#2e3a4e]">
              <th className="text-left py-2">Title</th>
              <th className="text-left py-2">Severity</th>
              <th className="text-left py-2">Classification</th>
              <th className="text-left py-2">Agreement</th>
              <th className="text-left py-2">Score</th>
            </tr>
          </thead>
          <tbody>
            {(incData?.items ?? []).map((inc: any) => (
              <tr key={inc.id} className="border-b border-[#2e3a4e]/50 hover:bg-white/5">
                <td className="py-2 pr-4">
                  <Link to={`/incidents/${inc.id}`} className="text-blue-400 hover:underline truncate block max-w-xs">
                    {inc.title}
                  </Link>
                </td>
                <td className="py-2 pr-4"><SeverityBadge severity={inc.overall_severity} /></td>
                <td className="py-2 pr-4"><ClassificationBadge classification={inc.auto_classification} /></td>
                <td className="py-2 pr-4">
                  <AgreementBadge status={inc.bob_analysis?.agreement_status ?? 'NOT_ANALYSED'} />
                </td>
                <td className="py-2 tabular-nums text-slate-300">
                  {inc.risk_score ? `${inc.risk_score.total_score.toFixed(1)}` : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <Link to="/incidents" className="text-blue-400 text-xs hover:underline mt-2 block">View all incidents →</Link>
      </Card>

      {/* Source Pipeline Strip — Point 14 */}
      <Card>
        <SectionHeading>Infinity Intelligence Pipeline</SectionHeading>
        <div className="flex flex-wrap items-center gap-1 text-xs">
          {[
            { label: 'SIEM', color: 'bg-purple-900/40 text-purple-300 border-purple-700' },
            { label: 'CYBER SENSOR', color: 'bg-cyan-900/40 text-cyan-300 border-cyan-700' },
            { label: 'SATELLITE', color: 'bg-green-900/40 text-green-300 border-green-700' },
            { label: 'INTEL REPORT', color: 'bg-amber-900/40 text-amber-300 border-amber-700' },
            { label: 'INFINITY', color: 'bg-blue-900/40 text-blue-300 border-blue-700', accent: true },
            { label: 'CORRELATION', color: 'bg-slate-800 text-slate-300 border-slate-600' },
            { label: 'FP FILTER', color: 'bg-emerald-900/40 text-emerald-300 border-emerald-700' },
            { label: 'RISK SCORE', color: 'bg-orange-900/40 text-orange-300 border-orange-700' },
            { label: 'MITRE ATT&CK', color: 'bg-purple-900/40 text-purple-300 border-purple-700' },
            { label: 'IBM BOB', color: 'bg-blue-900/40 text-blue-300 border-blue-700' },
            { label: 'BLUF', color: 'bg-red-900/40 text-red-300 border-red-700' },
          ].map((stage, i, arr) => (
            <span key={stage.label} className="flex items-center gap-1">
              <span className={`px-2 py-0.5 rounded border font-mono ${stage.color}`}>{stage.label}</span>
              {i < arr.length - 1 && <span className="text-slate-600">→</span>}
            </span>
          ))}
        </div>
      </Card>

      {/* About Infinity — Points 5, 17, 18 */}
      <Card>
        <SectionHeading>About Infinity</SectionHeading>
        <p className="text-slate-400 text-sm leading-relaxed">
          Infinity sits between raw sensor alerts and the analyst. Like a doctor combining vital signs,
          it correlates events from <span className="text-purple-300">SIEM</span>,{' '}
          <span className="text-cyan-300">Cyber Sensors</span>,{' '}
          <span className="text-green-300">Satellites</span> and{' '}
          <span className="text-amber-300">Intel Reports</span> — filtering noise, scoring risk,
          mapping MITRE ATT&amp;CK tactics, and generating a <span className="text-blue-300">BLUF</span> for every incident.
        </p>
        <p className="text-slate-500 text-xs mt-2 leading-relaxed">
          Infinity doesn't detect the original event — it detects <em>meaning</em>. Individual alerts
          don't tell the complete story. Infinity reveals the relationship between them so analysts can
          focus on the signal inside the noise.
        </p>
      </Card>
    </div>
  )
}
