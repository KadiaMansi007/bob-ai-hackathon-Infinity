import { useQuery } from '@tanstack/react-query'
import { getIncidents } from '../api'
import { ClassificationBadge, RiskScoreGauge, SeverityBadge, Card, Loading, ErrorMsg } from '../components/Badges'
import { Link } from 'react-router-dom'
import { Shield, Zap } from 'lucide-react'

/**
 * Commander Dashboard — Points 12 & 13
 * High-level, non-technical view for decision-makers.
 * Shows only CRITICAL incidents with BLUF-ready summaries.
 * No raw alerts, no packet-level detail — just: What happened? Why? What's affected? How confident?
 */
export default function CommanderDashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['incidents', { page: 1, page_size: 20, severity: 'CRITICAL' }],
    queryFn: () => getIncidents({ page: 1, page_size: 20, severity: 'CRITICAL' }),
    refetchInterval: 30_000,
  })

  if (isLoading) return <Loading />
  if (error) return <ErrorMsg msg="Could not load command-level incidents" />

  const items = data?.items ?? []

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Shield className="text-red-400" size={22} />
        <div>
          <h1 className="text-xl font-bold text-white">Commander View</h1>
          <p className="text-xs text-slate-500">High-priority incidents requiring command-level attention — non-technical summary</p>
        </div>
      </div>

      {/* Level guide */}
      <div className="flex gap-3 text-xs flex-wrap">
        {[
          { label: 'Level 1 — Raw Systems', desc: 'Sensors · SIEM · EDR', color: 'text-slate-500' },
          { label: 'Level 2 — Analyst', desc: 'Investigation · Correlation', color: 'text-blue-400' },
          { label: 'Level 3 — Commander', desc: 'Decision & Action ← You are here', color: 'text-amber-400' },
        ].map(l => (
          <div key={l.label} className="bg-[#1a2035] border border-[#2e3a4e] rounded px-3 py-2">
            <div className={`font-semibold ${l.color}`}>{l.label}</div>
            <div className="text-slate-500">{l.desc}</div>
          </div>
        ))}
      </div>

      {items.length === 0 && (
        <Card>
          <p className="text-slate-400 text-sm text-center py-4">
            ✓ No CRITICAL incidents at this time. System is monitoring.
          </p>
        </Card>
      )}

      {items.map((inc: any) => {
        const rs = inc.risk_score
        const ba = inc.bob_analysis
        const uniqueAssets = [...new Set((inc.member_alerts ?? []).map((a: any) => a.target_asset).filter(Boolean))] as string[]
        const uniqueTactics = [...new Set((inc.mitre_summary?.mappings ?? []).map((m: any) => m.tactic_name))] as string[]

        return (
          <Card key={inc.id} className="border-red-700/40">
            {/* Command header */}
            <div className="flex items-start justify-between gap-4 mb-4">
              <div>
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className="text-xs font-mono text-red-400 bg-red-900/20 border border-red-700/50 px-2 py-0.5 rounded">HIGH PRIORITY INCIDENT</span>
                  <ClassificationBadge classification={inc.auto_classification} />
                  <SeverityBadge severity={inc.overall_severity} />
                </div>
                <h2 className="text-white font-bold text-base">{inc.title}</h2>
              </div>
              {rs && <RiskScoreGauge score={rs.total_score} />}
            </div>

            {/* The 5 commander questions */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
              <div className="bg-[#141824] rounded border border-[#2e3a4e] p-3">
                <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">What happened?</div>
                <p className="text-slate-300">{inc.auto_classification_reason ?? 'Multiple correlated security alerts detected.'}</p>
              </div>
              <div className="bg-[#141824] rounded border border-[#2e3a4e] p-3">
                <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">Why does it matter?</div>
                <p className="text-slate-300">
                  {uniqueTactics.length > 0
                    ? `Adversary behaviour observed: ${uniqueTactics.join(' → ')}`
                    : 'Unusual activity across multiple systems detected.'}
                </p>
              </div>
              <div className="bg-[#141824] rounded border border-[#2e3a4e] p-3">
                <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">What is affected?</div>
                <p className="text-slate-300">
                  {uniqueAssets.length > 0
                    ? `${uniqueAssets.length} asset(s): ${uniqueAssets.slice(0, 4).join(', ')}${uniqueAssets.length > 4 ? '…' : ''}`
                    : `${inc.member_alerts?.length ?? 0} alert(s) across ${inc.source_types_involved?.length ?? 0} source type(s)`}
                </p>
              </div>
              <div className="bg-[#141824] rounded border border-[#2e3a4e] p-3">
                <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">How confident are we?</div>
                <p className="text-slate-300">
                  {ba
                    ? `IBM Bob: ${(ba.bob_confidence * 100).toFixed(0)}% — ${ba.agreement_status.replace('_', ' ')}`
                    : rs
                    ? `Risk Score: ${rs.total_score.toFixed(1)} / 100`
                    : 'Automated pipeline classification — Bob analysis pending'}
                </p>
              </div>
            </div>

            {/* What needs attention + BLUF link */}
            <div className="mt-3 flex items-center justify-between gap-3">
              <div className="text-xs text-slate-500">
                <span className="text-slate-400 font-semibold">What needs attention: </span>
                {inc.overall_severity === 'CRITICAL' || (rs && rs.total_score >= 80)
                  ? 'Immediate investigation recommended.'
                  : 'Monitor and investigate at next opportunity.'}
              </div>
              <div className="flex gap-2 shrink-0">
                <Link to={`/incidents/${inc.id}/bluf`}
                  className="flex items-center gap-1 px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-xs">
                  <Zap size={12} /> BLUF
                </Link>
                <Link to={`/incidents/${inc.id}`}
                  className="px-3 py-1.5 bg-[#1a2035] border border-[#2e3a4e] text-slate-300 rounded text-xs hover:border-blue-500">
                  Full Detail →
                </Link>
              </div>
            </div>
          </Card>
        )
      })}
    </div>
  )
}
