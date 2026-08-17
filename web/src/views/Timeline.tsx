import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, CalendarClock, CheckCircle2, SearchCheck } from 'lucide-react'
import { api, type CaseActivity, type CaseDetail, type Dashboard as DashboardData } from '../api'
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
  const { data: activity } = useQuery({
    queryKey: ['activity', slug],
    queryFn: () => api<CaseActivity>(`/api/cases/${slug}/activity`),
    refetchInterval: 10000,
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((item) => ({
    kind: item.kind, path: item.path, label: item.label,
  }))
  const work = useMemo(() => [
    ...(activity?.decisions ?? []).map((event) => ({
      id: `decision-${event.id}`, at: event.at, icon: CheckCircle2,
      title: tr('activity.decision', {
        from: tr(`triage.${event.from_state}`), to: tr(`triage.${event.to_state}`),
      }),
      detail: event.artifact,
      sub: event.note || (event.propagated ? tr('activity.propagated') : ''),
    })),
    ...(activity?.jobs ?? []).map((job) => ({
      id: `job-${job.id}`, at: job.finished || job.started || job.created, icon: Activity,
      title: tr('activity.analysis', { kind: tr(`job.${job.kind}`) }),
      detail: job.run_id || `#${job.id}`, sub: tr(`activity.job.${job.state}`),
    })),
    ...(activity?.hunts ?? []).map((hunt) => ({
      id: `hunt-${hunt.id}`, at: hunt.ran_at, icon: SearchCheck,
      title: tr('activity.hunt'), detail: hunt.label || hunt.pattern,
      sub: tr('activity.hunt.result', { hits: hunt.hits, clients: hunt.clients }),
    })),
  ].sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 30), [activity, tr])

  if (!data) return <div className="py-16 text-center text-[var(--muted)]">{tr('common.loading')}</div>

  return (
    <div className="flex flex-col gap-6">
      <Section title={tr('activity.title')} sub={tr('activity.sub')}>
        <Card className="divide-y divide-[var(--line)] overflow-hidden">
          {work.map((item) => {
            const Icon = item.icon
            return (
              <div key={item.id} className="flex items-start gap-3 px-4 py-3">
                <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-[var(--panel-2)] text-[var(--accent)]">
                  <Icon size={14} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[12.5px] font-semibold">{item.title}</div>
                  <div className="mono truncate text-[11.5px] text-[var(--muted)]" title={item.detail}>{item.detail}</div>
                  {item.sub && <div className="text-[11px] text-[var(--muted)]">{item.sub}</div>}
                </div>
                <time className="shrink-0 text-[10.5px] text-[var(--muted)]">
                  {String(item.at || '').slice(0, 16).replace('T', ' ')}
                </time>
              </div>
            )
          })}
          {!work.length && <div className="px-4 py-6 text-center text-[12px] text-[var(--muted)]">{tr('activity.empty')}</div>}
        </Card>
      </Section>
      {data.logs ? <>
        <Section title={tr('timeline.title')}
          sub={tr('timeline.sub', {
            lines: formatCount(data.logs.lines),
            from: formatDay(data.logs.first_epoch),
            to: formatDay(data.logs.last_epoch),
          })}>
          <Card className="p-4"><TimelineChart data={data.timeline} /></Card>
        </Section>
        <LogCoverage slug={slug} />
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
