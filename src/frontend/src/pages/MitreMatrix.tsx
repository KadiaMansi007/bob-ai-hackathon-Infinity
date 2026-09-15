import { useQuery } from '@tanstack/react-query'
import { getMitreMatrix } from '../api'
import { Card, SectionHeading, Loading, ErrorMsg } from '../components/Badges'

export default function MitreMatrix() {
  const { data, isLoading, error } = useQuery({ queryKey: ['mitre-matrix'], queryFn: getMitreMatrix })

  if (isLoading) return <Loading />
  if (error) return <ErrorMsg msg="Could not load MITRE matrix" />

  const matrix = data?.matrix ?? {}

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold text-white">MITRE ATT&CK Matrix</h1>
      <p className="text-sm text-slate-400">
        Full hierarchy: Tactic → Technique → Sub-technique · Evidence-based sub-technique resolution
      </p>
      <div className="text-xs text-slate-500">{data?.total_mappings ?? 0} total mappings</div>

      {Object.entries(matrix).map(([tactic, techniques]: [string, any]) => (
        <Card key={tactic}>
          <SectionHeading>{tactic}</SectionHeading>
          <div className="space-y-4">
            {Object.entries(techniques).map(([techId, techData]: [string, any]) => (
              <div key={techId} className="border border-[#2e3a4e] rounded p-3">
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-blue-300 font-mono text-sm">{techId}</span>
                  <span className="text-slate-300 text-sm">{techData.technique_name}</span>
                  <span className="text-xs text-slate-500 ml-auto">{techData.count} alert(s)</span>
                </div>
                <div className="pl-4 space-y-2">
                  {Object.entries(techData.subtechniques).map(([subId, subData]: [string, any]) => (
                    <div key={subId} className="flex flex-wrap items-start gap-2 border-l-2 border-[#2e3a4e] pl-3">
                      <div className="flex-1">
                        {subId !== 'not_determined' ? (
                          <span className="text-cyan-300 font-mono text-xs bg-cyan-900/20 px-2 py-0.5 rounded">
                            {subId} — {subData.name}
                          </span>
                        ) : (
                          <span className="text-slate-600 text-xs bg-slate-800 px-2 py-0.5 rounded">
                            Sub-technique: Not determined
                          </span>
                        )}
                        <span className="text-xs text-slate-500 ml-2">
                          {subData.count}× · {(subData.confidence * 100).toFixed(0)}% conf
                        </span>
                      </div>
                      {subData.evidence_strings?.length > 0 && (
                        <ul className="w-full pl-2 mt-1 space-y-0.5">
                          {subData.evidence_strings.slice(0, 3).map((ev: string, i: number) => (
                            <li key={i} className="text-xs text-slate-500 before:content-['•'] before:mr-1">{ev}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Card>
      ))}
    </div>
  )
}
