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

  // ── Analyst Workflow auto-check logic (Point 11) ──
  const workflowSteps = [
    {
      label: 'Is this real?',
      done: inc.auto_classification !== 'UNCLASSIFIED',
      detail: inc.auto_classification !== 'UNCLASSIFIED' ? inc.auto_classification?.replace('_', ' ') : 'Not yet classified',
    },
    {
      label: 'What caused it?',
      done: !!inc.fired_correlation_rule,
      detail: inc.fired_correlation_rule ? `Rule ${inc.fired_correlation_rule}` : 'No rule fired',
    },
    {
      label: 'Are other alerts related?',
      done: (inc.member_alerts?.length ?? 0) > 1,
      detail: `${inc.member_alerts?.length ?? 0} alert(s) correlated`,
    },
    {
      label: 'Who / what is affected?',
      done: (inc.member_alerts ?? []).some((a: any) => a.target_asset),
      detail: [...new Set((inc.member_alerts ?? []).map((a: any) => a.target_asset).filter(Boolean))].slice(0, 3).join(', ') || '—',
    },
    {
      label: 'How serious is it?',
      done: !!rs,
      detail: rs ? `Risk ${rs.total_score.toFixed(1)} / 100` : 'Not scored',
    },
    {
      label: 'What attacker behaviour?',
      done: (inc.mitre_summary?.mappings?.length ?? 0) > 0,
      detail: [...new Set((inc.mitre_summary?.mappings ?? []).map((m: any) => m.tactic_name))].join(', ') || 'No MITRE mappings',
    },
    {
      label: 'What to investigate?',
      done: !!ba,
      detail: ba ? 'Bob analysis complete' : 'Awaiting Bob analysis',
    },
  ]

  // ── MITRE tactic → investigation step (Point 20) ──
  const tacticSteps: Record<string, string> = {
    'Credential Access': 'Examine authentication logs and verify credential activity on affected assets',
    'Privilege Escalation': 'Audit privilege changes and review elevated account activity',
    'Lateral Movement': 'Trace network connections between affected hosts for signs of internal spreading',
    'Execution': 'Inspect process execution history and command-line arguments on affected endpoints',
    'Exfiltration': 'Review outbound data transfer volumes, destinations, and timing',
    'Persistence': 'Check for new scheduled tasks, services, registry keys, or startup entries',
    'Discovery': 'Review reconnaissance activity such as port scans, directory queries, and system surveys',
    'Command and Control': 'Inspect DNS queries, unusual outbound connections, and C2 beacon patterns',
    'Initial Access': 'Investigate the initial entry point — phishing, exploit, or exposed service',
    'Defense Evasion': 'Look for log clearing, disabled security tools, or obfuscated processes',
    'Collection': 'Identify data staging activity — unusual file access or archive creation',
    'Impact': 'Assess damage to systems — ransomware, data destruction, or service disruption',
  }
  const uniqueTactics = [...new Set((inc.mitre_summary?.mappings ?? []).map((m: any) => m.tactic_name as string))]
  const affectedAssets = [...new Set((inc.member_alerts ?? []).map((a: any) => a.target_asset).filter(Boolean))] as string[]
  const investigationSteps = [
    ...uniqueTactics.map(t => tacticSteps[t] ?? `Investigate activity related to ${t} on affected assets`),
    ...(affectedAssets.length > 0 ? [`Verify and audit activity on: ${affectedAssets.slice(0, 4).join(', ')}`] : []),
    'Cross-check SIEM logs and sensor feeds for additional correlated events',
    'Review outbound connections from all affected assets',
  ].filter(Boolean)

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

      {/* ── Analyst Workflow Steps (Point 11) ── */}
      <Card>
        <SectionHeading>🔎 Analyst Workflow</SectionHeading>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {workflowSteps.map((step, i) => (
            <div key={i} className={`rounded border p-2 text-xs ${step.done ? 'border-emerald-700 bg-emerald-900/20' : 'border-[#2e3a4e] bg-[#141824]'}`}>
              <div className="flex items-center gap-1 mb-1">
                <span className={step.done ? 'text-emerald-400' : 'text-slate-600'}>
                  {step.done ? '✓' : '○'}
                </span>
                <span className={`font-semibold ${step.done ? 'text-emerald-300' : 'text-slate-500'}`}>{step.label}</span>
              </div>
              <div className="text-slate-500 text-xs">{step.detail}</div>
            </div>
          ))}
          {/* Final step: BLUF */}
          <div className="rounded border border-blue-700/50 bg-blue-900/20 p-2 text-xs">
            <div className="flex items-center gap-1 mb-1">
              <span className="text-blue-400">→</span>
              <span className="font-semibold text-blue-300">Report findings (BLUF)</span>
            </div>
            <Link to={`/incidents/${id}/bluf`} className="text-blue-400 hover:underline">Generate BLUF →</Link>
          </div>
        </div>
      </Card>

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

      {/* ── Show Me Why (Point 19) ── */}
      {ba && (
        <Card>
          <SectionHeading>🔴 Why We Flagged This Incident</SectionHeading>
          <div className="space-y-1.5">
            <div className="flex items-start gap-2 text-sm">
              <span className="text-emerald-400 mt-0.5">✓</span>
              <span className="text-slate-300">
                <span className="font-semibold text-white">{inc.member_alerts?.length ?? 0}</span> related alert{(inc.member_alerts?.length ?? 0) !== 1 ? 's' : ''} correlated into this incident
              </span>
            </div>
            {(inc.source_types_involved ?? []).length > 0 && (
              <div className="flex items-start gap-2 text-sm">
                <span className="text-emerald-400 mt-0.5">✓</span>
                <span className="text-slate-300">
                  Activity detected across <span className="font-semibold text-white">{inc.source_types_involved.length}</span> source type(s): {inc.source_types_involved.join(', ')}
                </span>
              </div>
            )}
            {(inc.member_alerts ?? []).some((a: any) => !a.is_false_positive && a.confidence >= 0.8) && (
              <div className="flex items-start gap-2 text-sm">
                <span className="text-emerald-400 mt-0.5">✓</span>
                <span className="text-slate-300">High-confidence alerts present (≥80% confidence, not false positives)</span>
              </div>
            )}
            {uniqueTactics.length > 0 && (
              <div className="flex items-start gap-2 text-sm">
                <span className="text-emerald-400 mt-0.5">✓</span>
                <span className="text-slate-300 flex flex-wrap items-center gap-1">
                  MITRE ATT&amp;CK chain observed:&nbsp;
                  {uniqueTactics.map((t, i) => (
                    <span key={t} className="flex items-center gap-1">
                      <span className="text-purple-300 bg-purple-900/30 px-1.5 py-0.5 rounded text-xs">{t}</span>
                      {i < uniqueTactics.length - 1 && <span className="text-slate-600">→</span>}
                    </span>
                  ))}
                </span>
              </div>
            )}
            {rs && (
              <div className="flex items-start gap-2 text-sm">
                <span className="text-emerald-400 mt-0.5">✓</span>
                <span className="text-slate-300">
                  Risk score: <span className={`font-bold ${rs.total_score >= 80 ? 'text-red-400' : rs.total_score >= 60 ? 'text-orange-400' : 'text-yellow-400'}`}>{rs.total_score.toFixed(1)}</span> / 100
                </span>
              </div>
            )}
            <div className="flex items-start gap-2 text-sm">
              <span className="text-emerald-400 mt-0.5">✓</span>
              <span className="text-slate-300">
                IBM Bob confidence: <span className="font-bold text-blue-300">{(ba.bob_confidence * 100).toFixed(0)}%</span>
              </span>
            </div>
          </div>
        </Card>
      )}

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

      {/* ── Investigation Checklist (Point 20) ── */}
      {ba && investigationSteps.length > 0 && (
        <Card>
          <SectionHeading>🔍 What Should I Investigate Next?</SectionHeading>
          <p className="text-xs text-slate-500 mb-3">Investigation Suggestions — analyst judgment required</p>
          <ol className="space-y-2">
            {investigationSteps.map((step, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <span className="text-blue-400 font-bold tabular-nums w-5 shrink-0">{i + 1}.</span>
                <span className="text-slate-300">{step}</span>
              </li>
            ))}
          </ol>
          <p className="text-xs text-slate-600 mt-3 border-t border-[#2e3a4e] pt-2">
            Suggestions generated by IBM Bob AI — analyst judgment required. This is not automated action.
          </p>
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

      {/* ── Attack Sequence Timeline (Point 6) ── */}
      {(inc.member_alerts?.length ?? 0) >= 2 && (
        <Card>
          <SectionHeading>⏱ Attack Sequence Timeline</SectionHeading>
          <p className="text-xs text-slate-500 mb-3">Alerts sorted by time — revealing the attack story</p>
          <div className="space-y-2">
            {[...(inc.member_alerts ?? [])]
              .sort((a: any, b: any) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
              .map((a: any, i: number, arr: any[]) => (
                <div key={a.id} className="flex items-start gap-3">
                  <div className="flex flex-col items-center">
                    <div className="w-2.5 h-2.5 rounded-full bg-blue-400 shrink-0 mt-1" />
                    {i < arr.length - 1 && <div className="w-0.5 h-6 bg-[#2e3a4e] mt-1" />}
                  </div>
                  <div className="flex-1 pb-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs text-slate-500">{new Date(a.timestamp).toLocaleTimeString()}</span>
                      <SeverityBadge severity={a.severity} />
                      <span className="font-mono text-xs text-slate-300">{a.alert_type}</span>
                      {a.target_asset && <span className="text-xs text-slate-500">on <span className="text-slate-300">{a.target_asset}</span></span>}
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </Card>
      )}

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
