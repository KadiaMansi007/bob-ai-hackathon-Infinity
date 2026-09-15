import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getAlerts } from '../api'
import { SeverityBadge, SourceBadge, Loading, ErrorMsg, Card } from '../components/Badges'
import { Link } from 'react-router-dom'

export default function AlertFeed() {
  const [severity, setSeverity] = useState('')
  const [sourceType, setSourceType] = useState('')
  const [showFP, setShowFP] = useState<boolean | undefined>(undefined)
  const [page, setPage] = useState(1)

  const { data, isLoading, error } = useQuery({
    queryKey: ['alerts', { page, severity, sourceType, showFP }],
    queryFn: () => getAlerts({
      page,
      page_size: 25,
      ...(severity && { severity }),
      ...(sourceType && { source_type: sourceType }),
      ...(showFP !== undefined && { is_false_positive: showFP }),
    }),
  })

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-bold text-white">Alert Feed</h1>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1) }}
          className="bg-[#1a2035] border border-[#2e3a4e] text-slate-300 text-sm rounded px-3 py-1.5">
          <option value="">All severities</option>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={sourceType} onChange={e => { setSourceType(e.target.value); setPage(1) }}
          className="bg-[#1a2035] border border-[#2e3a4e] text-slate-300 text-sm rounded px-3 py-1.5">
          <option value="">All sources</option>
          {['SIEM','CYBER_SENSOR','SATELLITE','INTEL_REPORT'].map(s => <option key={s}>{s.replace('_',' ')}</option>)}
        </select>
        <select value={showFP === undefined ? '' : String(showFP)} onChange={e => {
          setShowFP(e.target.value === '' ? undefined : e.target.value === 'true')
          setPage(1)
        }} className="bg-[#1a2035] border border-[#2e3a4e] text-slate-300 text-sm rounded px-3 py-1.5">
          <option value="">All alerts</option>
          <option value="false">Genuine only</option>
          <option value="true">False positives</option>
        </select>
      </div>

      {isLoading && <Loading />}
      {error && <ErrorMsg msg="Could not load alerts" />}

      {data && (
        <>
          <div className="text-xs text-slate-500">{data.total} alerts total</div>
          <Card className="p-0 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-[#141824]">
                <tr className="text-slate-500 text-xs">
                  <th className="text-left px-4 py-3">Type</th>
                  <th className="text-left px-4 py-3">Source</th>
                  <th className="text-left px-4 py-3">Severity</th>
                  <th className="text-left px-4 py-3">Confidence</th>
                  <th className="text-left px-4 py-3">Target Asset</th>
                  <th className="text-left px-4 py-3">Timestamp</th>
                  <th className="text-left px-4 py-3">FP?</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((a: any) => (
                  <tr key={a.id} className="border-t border-[#2e3a4e]/50 hover:bg-white/5">
                    <td className="px-4 py-2">
                      <Link to={`/alerts/${a.id}`} className="text-blue-400 hover:underline font-mono text-xs">
                        {a.alert_type}
                      </Link>
                    </td>
                    <td className="px-4 py-2"><SourceBadge sourceType={a.source_type} /></td>
                    <td className="px-4 py-2"><SeverityBadge severity={a.severity} /></td>
                    <td className="px-4 py-2 tabular-nums text-slate-300">{(a.confidence * 100).toFixed(0)}%</td>
                    <td className="px-4 py-2 font-mono text-xs text-slate-300 max-w-[140px] truncate">{a.target_asset}</td>
                    <td className="px-4 py-2 text-xs text-slate-500">{new Date(a.timestamp).toLocaleString()}</td>
                    <td className="px-4 py-2">
                      {a.is_false_positive
                        ? <span className="text-xs text-emerald-400">✓ {a.fp_reason}</span>
                        : <span className="text-xs text-slate-600">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
          <div className="flex gap-2 text-sm">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
              className="px-3 py-1 bg-[#1a2035] border border-[#2e3a4e] rounded disabled:opacity-40">← Prev</button>
            <span className="px-3 py-1 text-slate-400">Page {page}</span>
            <button onClick={() => setPage(p => p + 1)} disabled={data.items.length < 25}
              className="px-3 py-1 bg-[#1a2035] border border-[#2e3a4e] rounded disabled:opacity-40">Next →</button>
          </div>
        </>
      )}
    </div>
  )
}
