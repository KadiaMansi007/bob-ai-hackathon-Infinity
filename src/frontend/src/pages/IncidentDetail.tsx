import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getIncident, analyseWithBob } from '../api'
import {
  SeverityBadge, SourceBadge, ClassificationBadge, AgreementBadge,
  RiskScoreGauge, FiredRuleChip, Card, SectionHeading, Loading, ErrorMsg
} from '../components/Badges'
import { Bot, Zap } from 'lucide-react'

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const { data: inc, isLoading, error } = useQuery({
    queryKey: ['incident', id],
    queryFn: () => getIncident(id!),
    refetchInterval: 15_000,
  })
  const analyseMut = useMutation({
    mutationFn: () => analyseWithBob(id!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['incident', id] }),
  })

  if (isLoading) return <Loading />
  if (error || !inc) return <ErrorMsg msg="Incident not found" />

  const rs = inc.risk_score
  const ba = inc.bob_analysis

  return (
    <div className="space-y-4 max-w-5xl">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link to="/incidents" className="text-blue-400 hover:underline text-sm">← Incidents</Link>
            <FiredRuleChip rule={inc.fired_correlation_rule} />
          </div>
          <h1 className="text-lg font-bold text-white">{inc.title}</h1>
          <div className="flex gap-2 mt-2 flex-wrap">
            <SeverityBadge severity={inc.overall_severity} />
            {inc.source_types_involved?.map((s: string) => <SourceBadge key={s} sourceType={s} />)}
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => analyseMut.mutate()}
            disabled={analyseMut.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm disabled:opacity-50"
          >
            <Bot size={14} />
            {analyseMut.isPending ? 'Analysing…' : 'Analyse with Bob'}
          </button>
          <Link to={`/incidents/${id}/bluf`}
            className="flex items-center gap-2 px-4 py-2 bg-[#1a2035] border border-[#2e3a4e] text-slate-300 rounded text-sm hover:border-blue-500">
            <Zap size={14} /> BLUF
          </Link>
        </div>
      </div>

      {/* === CLASSIFICATION PANEL — The central dual-layer feature === */}
      <Card>
        <SectionHeading>🔍 Threat Classification</SectionHeading>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Left — Automated */}
          <div className="bg-[#141824] rounded border border-[#2e3a4e] p-4 space-y-2">
            <div className="text-xs text-slate-500 uppercase tracking-widest mb-2">Automated Pipeline</div>
            <ClassificationBadge classification={inc.auto_classification} />
            <FiredRuleChip rule={inc.fired_correlation_rule} />
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">{inc.auto_classification_reason}</p>
          </div>

          {/* Centre — Agreement */}
          <div className="flex flex-col items-center justify-center gap-2 p-4">
            {ba ? (
              <>
                <AgreementBadge status={ba.agreement_status} />
                {(ba.agreement_status === 'DISAGREES' || ba.agreement_status === 'PARTIAL') && (
                  <p className="text-xs text-amber-400 text-center">{ba.agreement_detail}</p>
                )}
              </>
            ) : (
              <span className="text-xs text-slate-500 text-center">Click "Analyse with Bob"<br />to see Bob's assessment</span>
            )}
          </div>

          {/* Right — Bob */}
          <div className="bg-[#141824] rounded border border-[#2e3a4e] p-4 space-y-2">
            <div className="text-xs text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-1">
              <Bot size={10} /> IBM Bob Assessment
            </div>
            {ba ? (
              <>
                <ClassificationBadge classification={ba.bob_classification} />
                <div className="text-xs text-slate-400">Confidence: {(ba.bob_confidence * 100).toFixed(0)}%</div>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">{ba.bob_reasoning}</p>
              </>
            ) : (
              <span className="text-xs text-slate-600">Not yet analysed</span>
            )}
          </div>
        </div>

        {/* Bob's score + correlation explanation */}
        {ba && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
            <div className="bg-[#141824] rounded border border-[#2e3a4e] p-3">
              <div className="text-xs text-slate-500 mb-1 uppercase tracking-wide">Bob's Score Explanation</div>
              <p className="text-xs text-slate-400 leading-relaxed">{ba.score_explanation_text}</p>
            </div>
            <div className="bg-[#141824] rounded border border-[#2e3a4e] p-3">
              <div className="text-xs text-slate-500 mb-1 uppercase tracking-wide">Bob's Correlation Review</div>
              <p className="text-xs text-slate-400 leading-relaxed">{ba.correlation_review_text}</p>
            </div>
          </div>
        )}
      </Card>

      {/* Risk Score */}
      {rs && (
        <Card>
          <SectionHeading>Risk Score</SectionHeading>
          <div className="flex items-center gap-6">
            <RiskScoreGauge score={rs.total_score} />
            <span className="text-sm text-slate-400">{rs.explanation?.priority_label}</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-4">
            {Object.entries(rs.explanation?.components ?? {}).map(([key, comp]: [string, any]) => (
              <div key={key} className="bg-[#141824] border border-[#2e3a4e] rounded p-2 text-xs">
                <div className="text-slate-500 capitalize mb-1">{key.replace('_', ' ')}</div>
                <div className="text-white font-bold">{comp.value.toFixed(1)}</div>
                <div className="text-slate-600 text-xs mt-1">{comp.reason}</div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Member alerts */}
      <Card>
        <SectionHeading>Member Alerts ({inc.member_alerts?.length ?? 0})</SectionHeading>
        <div className="space-y-2">
          {(inc.member_alerts ?? []).map((a: any) => (
            <div key={a.id} className="flex items-center gap-3 border border-[#2e3a4e]/50 rounded px-3 py-2 text-xs">
              <SourceBadge sourceType={a.source_type} />
              <SeverityBadge severity={a.severity} />
              <span className="font-mono text-slate-300">{a.alert_type}</span>
              <span className="text-slate-500">{a.target_asset}</span>
              <span className="text-slate-600 ml-auto">{(a.confidence * 100).toFixed(0)}% conf</span>
              {a.is_false_positive && <span className="text-emerald-400">FP</span>}
              <Link to={`/alerts/${a.id}`} className="text-blue-400 hover:underline">→</Link>
            </div>
          ))}
        </div>
      </Card>

      {/* MITRE */}
      {inc.mitre_summary?.mappings?.length > 0 && (
        <Card>
          <SectionHeading>MITRE ATT&CK</SectionHeading>
          <div className="space-y-2">
            {inc.mitre_summary.mappings.map((m: any) => (
              <div key={m.id} className="flex flex-wrap items-center gap-2 border border-[#2e3a4e]/50 rounded px-3 py-2 text-xs">
                <span className="text-purple-300 bg-purple-900/30 px-2 py-0.5 rounded">{m.tactic_name}</span>
                <span className="text-slate-500">→</span>
                <span className="text-blue-300 bg-blue-900/30 px-2 py-0.5 rounded">{m.technique_id} {m.technique_name}</span>
                <span className="text-slate-500">→</span>
                {m.subtechnique_id !== 'not_determined'
                  ? <span className="text-cyan-300 bg-cyan-900/30 px-2 py-0.5 rounded">{m.subtechnique_id} {m.subtechnique_name}</span>
                  : <span className="text-slate-600 bg-slate-800 px-2 py-0.5 rounded">Not determined</span>
                }
                <span className="text-slate-500 ml-auto">{(m.confidence * 100).toFixed(0)}% · {m.mapping_method}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}
