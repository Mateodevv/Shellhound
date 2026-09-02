import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CalendarClock } from 'lucide-react'
import { api, type CaseDetail, type Dashboard as DashboardData } from '../api'
import { useT } from '../i18n'
import { formatCount, formatDay, type EvidenceRoot } from '../format'
import { Card, EmptyState, Section } from '../components/ui'
import { TimelineChart } from '../components/TimelineChart'
import { LogCoverage } from '../components/LogCoverage'
import { CaseChain } from '../components/CaseChain'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import type { Navigate } from '../App'

export function Timeline({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const triage = useTriage(slug)
  const { data } = useQuery({
    queryKey: ['dashboard', slug],
    queryFn: () => api<DashboardData>(`/api/cases/${slug}/dashboard`),
    refetchInterval: 10000,
  })
  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((item) => ({
    kind: item.kind, path: item.path, label: item.label,
  }))

  if (!data) return <div className="py-16 text-center text-[var(--muted)]">{tr('common.loading')}</div>
  const sparseTimeline = data.timeline.length < 4

  return (
    <div className="flex flex-col gap-6">
      {data.logs ? <>
        <Section title={tr('timeline.title')}
          sub={tr('timeline.sub', {
            lines: formatCount(data.logs.lines),
            from: formatDay(data.logs.first_epoch),
            to: formatDay(data.logs.last_epoch),
          })}>
          <Card className={sparseTimeline ? 'max-w-4xl p-3' : 'p-4'}>
            <TimelineChart data={data.timeline} height={sparseTimeline ? 140 : 220} />
          </Card>
        </Section>
      </> : (
        <EmptyState icon={<CalendarClock size={36} />} title={tr('timeline.empty.title')}
          sub={tr('timeline.empty.sub')} />
      )}
      <CaseChain slug={slug}
        onOpen={(artifact, kind) => setSelected({
          artifact,
          artifact_kind: (kind || 'file') as ArtifactStub['artifact_kind'],
          worst: 0,
          triage: 'confirmed',
          triage_note: '',
        })}
        onTrace={(ip) => { setTraceMarks(undefined); setTraceIps([ip]) }} />
      {data.logs && <LogCoverage slug={slug} />}
      <ArtifactWindow slug={slug} artifact={selected} roots={roots}
        collected={triage.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips, marks) => { setTraceMarks(marks); setTraceIps(ips) }}
        onClose={() => { setSelected(null); triage.clearCollected() }}
        onTriage={(state, note) => {
          if (selected) triage.decide([selected.artifact], state, note)
        }} />
      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
      <FileViewer slug={slug} path={viewing?.path ?? null}
        focusLine={viewing?.line ?? null} layer={2} onClose={() => setViewing(null)} />
      <TriageFollowUp t={triage} roots={roots} onOpenIocs={() => gotoView('iocbox')} />
    </div>
  )
}
