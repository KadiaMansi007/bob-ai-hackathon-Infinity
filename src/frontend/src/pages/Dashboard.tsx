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

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Alerts', value: s.total_alerts, color: 'text-blue-400' },
          { label: 'Open Incidents', value: s.open_incidents, color: 'text-orange-400' },
          { label: 'P1 Incidents', value: s.p1_incidents, color: 'text-red-400' },
          { label: 'FP Rate', value: `${(s.false_positive_rate * 100).toFixed(1)}%`, color: 'text-emerald-400' },
        ].map(({ label, value, color }) => (
          <Card key={label}>
            <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">{label}</div>
            <div className={`text-2xl font-bold tabular-nums ${color}`}>{value}</div>
          </Card>
        ))}
      </div>

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

      {/* Recent incidents */}
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
    </div>
  )
}
