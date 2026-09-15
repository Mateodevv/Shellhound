import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CalendarClock } from 'lucide-react'
import { api, type CaseDetail, type Dashboard as DashboardData } from '../api'
import { useT } from '../i18n'
import { type EvidenceRoot } from '../format'
import { Button, Card, EmptyState, Section, CopyButton } from '../components/ui/ui'
import { TimelineChart } from '../components/ui/TimelineChart'
import { LogCoverage } from '../components/logview/LogCoverage'
import { CaseChain } from '../components/casework/CaseChain'
import { ArtifactWindow, type ArtifactStub } from '../components/review/ArtifactWindow'
import { TraceWindow, type TraceMarks } from '../components/logview/TraceWindow'
import { FileViewer } from '../components/review/FileViewer'
import { TriageFollowUp } from '../components/review/triage'
import { useTriage } from '../components/review/useTriage'
import { CaseProfileButton } from '../components/casework/CaseProfile'
import type { Navigate } from '../App'

export function Timeline({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [focusId, setFocusId] = useState(() => new URLSearchParams(location.search).get('event') ?? '')
  useEffect(() => {
    const restore = () => setFocusId(new URLSearchParams(location.search).get('event') ?? '')
    restore()
    window.addEventListener('popstate', restore)
    return () => window.removeEventListener('popstate', restore)
  }, [slug])
  const triage = useTriage(slug)
  const { data, isError, refetch } = useQuery({
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

  if (isError) return <Card className="p-4"><p role="alert">{tr('incident.loadFailed')}</p><Button onClick={() => void refetch()}>{tr('common.retry')}</Button></Card>
  if (!data) return <div className="py-16 text-center text-[var(--muted)]">{tr('common.loading')}</div>
  const sparseTimeline = data.timeline.length < 4
  const stamp = (value?: number | null) => value == null ? null : new Date(value * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC')
  const metrics: [string, string | null][] = [
    [tr('incident.first'), stamp(data.incident_summary?.first_action)],
    [tr('incident.last'), stamp(data.incident_summary?.last_action)],
    [tr('incident.coverage'), data.logs?.first_epoch != null && data.logs?.last_epoch != null ? `${stamp(data.logs.first_epoch)} – ${stamp(data.logs.last_epoch)}` : null],
    [tr('incident.ips'), data.incident_summary ? String(data.incident_summary.attacker_ips) : null],
    [tr('incident.malware'), data.incident_summary ? String(data.incident_summary.malware_files) : null],
  ]

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">{tr('incident.title')}</h1>
        <CaseProfileButton slug={slug} />
      </div>
      <section aria-label={tr('incident.metrics')} className="grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
        {metrics.map(([label, value]) => <Card key={label} className="min-w-0 p-3">
          <div className="text-xs text-[var(--muted)]">{label}</div>
          <div className="mt-2 flex items-start justify-between gap-2"><span className="select-text break-words text-sm font-semibold tabular">{value ?? tr('incident.unavailable')}</span>
            {value != null && <CopyButton value={value} label={`${tr('common.copy')} ${label}`} />}</div>
        </Card>)}
      </section>
      {data.logs ? <>
        <Section title={tr('timeline.title')}>
          <Card className={'p-3'}>
            <TimelineChart data={data.timeline} height={sparseTimeline ? 140 : 220} />
          </Card>
        </Section>
      </> : (
        <EmptyState icon={<CalendarClock size={36} />} title={tr('timeline.empty.title')}
          sub={tr('timeline.empty.sub')} />
      )}
      <div className="scroll-mt-4">
      <CaseChain slug={slug} focusId={focusId} showSummary={false}
        onOpen={(artifact, kind) => setSelected({
          artifact,
          artifact_kind: (kind || 'file') as ArtifactStub['artifact_kind'],
          worst: 0,
          triage: 'confirmed',
          triage_note: '',
        })}
        onTrace={(ip) => { setTraceMarks(undefined); setTraceIps([ip]) }} />
      </div>
      {data.logs && <LogCoverage slug={slug} />}
      <ArtifactWindow slug={slug} artifact={selected} roots={roots}
        collected={triage.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips, marks) => { setTraceMarks(marks); setTraceIps(ips) }}
        onClose={() => { setSelected(null); triage.clearCollected() }}
        onSave={(state, note, classifications) => {
          if (!selected) return Promise.reject(new Error('No artifact selected'))
          return triage.decideAsync([selected.artifact], state, note, undefined, classifications)
        }} />
      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
      <FileViewer slug={slug} path={viewing?.path ?? null}
        focusLine={viewing?.line ?? null} layer={2} onClose={() => setViewing(null)} />
      <TriageFollowUp t={triage} roots={roots} onOpenIocs={() => gotoView('iocbox')} />
    </div>
  )
}
