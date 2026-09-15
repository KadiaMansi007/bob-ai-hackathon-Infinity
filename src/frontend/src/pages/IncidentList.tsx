import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getIncidents } from '../api'
import { SeverityBadge, ClassificationBadge, AgreementBadge, Card, Loading, ErrorMsg, FiredRuleChip } from '../components/Badges'
import { Link } from 'react-router-dom'

export default function IncidentList() {
  const [status, setStatus] = useState('')
  const [severity, setSeverity] = useState('')
  const [classification, setClassification] = useState('')
  const [page, setPage] = useState(1)

  const { data, isLoading, error } = useQuery({
    queryKey: ['incidents', { page, status, severity, classification }],
    queryFn: () => getIncidents({
      page, page_size: 20,
      ...(status && { status }),
      ...(severity && { severity }),
      ...(classification && { auto_classification: classification }),
    }),
    refetchInterval: 30_000,
  })

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-white">Correlated Incidents</h1>

      <div className="flex gap-3 flex-wrap">
        <select value={status} onChange={e => { setStatus(e.target.value); setPage(1) }}
          className="bg-[#1a2035] border border-[#2e3a4e] text-slate-300 text-sm rounded px-3 py-1.5">
          <option value="">All statuses</option>
          {['OPEN','INVESTIGATING','CLOSED','FALSE_POSITIVE'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1) }}
          className="bg-[#1a2035] border border-[#2e3a4e] text-slate-300 text-sm rounded px-3 py-1.5">
          <option value="">All severities</option>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={classification} onChange={e => { setClassification(e.target.value); setPage(1) }}
          className="bg-[#1a2035] border border-[#2e3a4e] text-slate-300 text-sm rounded px-3 py-1.5">
          <option value="">All classifications</option>
          {['GENUINE_THREAT','FALSE_POSITIVE','UNCLASSIFIED'].map(s => <option key={s}>{s.replace('_',' ')}</option>)}
        </select>
      </div>

      {isLoading && <Loading />}
      {error && <ErrorMsg msg="Could not load incidents" />}

      {data && (
        <>
          <div className="text-xs text-slate-500">{data.total} incidents total</div>
          <Card className="p-0 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-[#141824]">
                <tr className="text-slate-500 text-xs">
                  <th className="text-left px-4 py-3">Title</th>
                  <th className="text-left px-4 py-3">Severity</th>
                  <th className="text-left px-4 py-3">Rule</th>
                  <th className="text-left px-4 py-3">Auto Classification</th>
                  <th className="text-left px-4 py-3">Bob Agreement</th>
                  <th className="text-left px-4 py-3">Score</th>
                  <th className="text-left px-4 py-3">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((inc: any) => (
                  <tr key={inc.id} className="border-t border-[#2e3a4e]/50 hover:bg-white/5">
                    <td className="px-4 py-2 max-w-[220px]">
                      <Link to={`/incidents/${inc.id}`} className="text-blue-400 hover:underline text-xs truncate block">
                        {inc.title}
                      </Link>
                    </td>
                    <td className="px-4 py-2"><SeverityBadge severity={inc.overall_severity} /></td>
                    <td className="px-4 py-2"><FiredRuleChip rule={inc.fired_correlation_rule} /></td>
                    <td className="px-4 py-2"><ClassificationBadge classification={inc.auto_classification} /></td>
                    <td className="px-4 py-2">
                      <AgreementBadge status={inc.bob_analysis?.agreement_status ?? 'NOT_ANALYSED'} />
                    </td>
                    <td className="px-4 py-2 tabular-nums text-slate-300 text-xs">
                      {inc.risk_score ? inc.risk_score.total_score.toFixed(1) : '—'}
                    </td>
                    <td className="px-4 py-2 text-xs text-slate-500">{new Date(inc.last_seen).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <div className="flex gap-2 text-sm">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="px-3 py-1 bg-[#1a2035] border border-[#2e3a4e] rounded disabled:opacity-40">← Prev</button>
            <span className="px-3 py-1 text-slate-400">Page {page}</span>
            <button onClick={() => setPage(p => p + 1)} disabled={data.items.length < 20}
              className="px-3 py-1 bg-[#1a2035] border border-[#2e3a4e] rounded disabled:opacity-40">Next →</button>
          </div>
        </>
      )}
    </div>
  )
}
