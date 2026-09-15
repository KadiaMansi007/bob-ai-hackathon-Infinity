import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getAlert } from '../api'
import { SeverityBadge, SourceBadge, Card, SectionHeading, Loading, ErrorMsg } from '../components/Badges'

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>()
  const { data, isLoading, error } = useQuery({ queryKey: ['alert', id], queryFn: () => getAlert(id!) })

  if (isLoading) return <Loading />
  if (error || !data) return <ErrorMsg msg="Alert not found" />

  return (
    <div className="space-y-4 max-w-4xl">
      <div className="flex items-center gap-3">
        <Link to="/alerts" className="text-blue-400 hover:underline text-sm">← Alerts</Link>
        <h1 className="text-lg font-bold text-white font-mono">{data.alert_type}</h1>
        <SeverityBadge severity={data.severity} />
        <SourceBadge sourceType={data.source_type} />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Card>
          <SectionHeading>Alert Details</SectionHeading>
          <dl className="space-y-2 text-sm">
            {[
              ['Target Asset', data.target_asset],
              ['Geo Location', data.geo_location ?? '—'],
              ['Confidence', `${(data.confidence * 100).toFixed(0)}%`],
              ['Source Name', data.source_name],
              ['Timestamp', new Date(data.timestamp).toLocaleString()],
              ['False Positive', data.is_false_positive ? `Yes — ${data.fp_reason}` : 'No'],
            ].map(([label, value]) => (
              <div key={label} className="flex justify-between border-b border-[#2e3a4e]/40 pb-1">
                <dt className="text-slate-500">{label}</dt>
                <dd className="text-slate-200 font-mono text-right text-xs">{value}</dd>
              </div>
            ))}
          </dl>
        </Card>
        <Card>
          <SectionHeading>Description</SectionHeading>
          <p className="text-slate-300 text-sm">{data.description}</p>
        </Card>
      </div>

      {/* MITRE mappings */}
      {data.mitre_mappings?.length > 0 && (
        <Card>
          <SectionHeading>MITRE ATT&CK Mappings</SectionHeading>
          <div className="space-y-3">
            {data.mitre_mappings.map((m: any) => (
              <div key={m.id} className="border border-[#2e3a4e] rounded p-3 text-sm space-y-1">
                <div className="flex gap-2 flex-wrap">
                  <span className="text-xs text-purple-300 bg-purple-900/30 px-2 py-0.5 rounded">{m.tactic_name} ({m.tactic_id})</span>
                  <span className="text-xs text-blue-300 bg-blue-900/30 px-2 py-0.5 rounded">{m.technique_id} — {m.technique_name}</span>
                  {m.subtechnique_id !== 'not_determined' ? (
                    <span className="text-xs text-cyan-300 bg-cyan-900/30 px-2 py-0.5 rounded">{m.subtechnique_id} — {m.subtechnique_name}</span>
                  ) : (
                    <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded">Sub-technique: Not determined</span>
                  )}
                  <span className="text-xs text-slate-400 ml-auto">Confidence: {(m.confidence * 100).toFixed(0)}%</span>
                </div>
                {m.evidence_strings?.length > 0 && (
                  <ul className="mt-1 space-y-0.5">
                    {m.evidence_strings.map((ev: string, i: number) => (
                      <li key={i} className="text-xs text-slate-400 before:content-['•'] before:mr-1">{ev}</li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Raw payload */}
      <Card>
        <SectionHeading>Raw Payload</SectionHeading>
        <pre className="text-xs text-slate-400 overflow-x-auto whitespace-pre-wrap">{JSON.stringify(data.raw_payload, null, 2)}</pre>
      </Card>
    </div>
  )
}
