import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getBluf, generateBluf, getIncident } from '../api'
import { Card, SectionHeading, Loading, ErrorMsg, ClassificationBadge } from '../components/Badges'
import { Zap } from 'lucide-react'

export default function BlufSummary() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const { data: inc } = useQuery({ queryKey: ['incident', id], queryFn: () => getIncident(id!) })
  const { data: bluf, isLoading } = useQuery({
    queryKey: ['bluf', id],
    queryFn: () => getBluf(id!),
    retry: false,
  })
  const genMut = useMutation({
    mutationFn: () => generateBluf(id!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['bluf', id] }),
  })

  return (
    <div className="space-y-4 max-w-3xl">
      <div className="flex items-center gap-3">
        <Link to={`/incidents/${id}`} className="text-blue-400 hover:underline text-sm">← Incident</Link>
        <h1 className="text-lg font-bold text-white">BLUF Summary</h1>
        {inc && <ClassificationBadge classification={inc.auto_classification} />}
      </div>

      <div className="flex justify-end">
        <button
          onClick={() => genMut.mutate()}
          disabled={genMut.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm disabled:opacity-50"
        >
          <Zap size={14} />
          {genMut.isPending ? 'Generating…' : bluf ? 'Regenerate BLUF' : 'Generate BLUF'}
        </button>
      </div>

      {isLoading && <Loading />}

      {!bluf && !isLoading && (
        <Card>
          <p className="text-slate-500 text-sm">No BLUF generated yet. Click "Generate BLUF" to ask IBM Bob.</p>
        </Card>
      )}

      {bluf && (
        <div className="space-y-4">
          <Card className="border-blue-700/50">
            <SectionHeading>BLUF</SectionHeading>
            <p className="text-white font-semibold text-base leading-relaxed">{bluf.bluf_line}</p>
          </Card>
          <Card>
            <SectionHeading>Situation</SectionHeading>
            <p className="text-slate-300 text-sm leading-relaxed">{bluf.situation}</p>
          </Card>
          <Card>
            <SectionHeading>Assessment</SectionHeading>
            <p className="text-slate-300 text-sm leading-relaxed">{bluf.assessment}</p>
          </Card>
          <Card>
            <SectionHeading>Recommendations</SectionHeading>
            <div className="text-slate-300 text-sm leading-relaxed whitespace-pre-line">{bluf.recommendations}</div>
          </Card>
          <div className="text-xs text-slate-600">
            Generated: {new Date(bluf.generated_at).toLocaleString()} — IBM Bob AI
          </div>
        </div>
      )}
    </div>
  )
}
