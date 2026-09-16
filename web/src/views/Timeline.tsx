import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { CalendarClock, X } from 'lucide-react'
import { api, type ArtifactContext, type CaseDetail, type ChainEvent, type Dashboard as DashboardData, type FirstSign as FirstSignData } from '../api'
import { useT } from '../i18n'
import { type EvidenceRoot } from '../format'
import { Button, Card, EmptyState, Section, CopyButton } from '../components/ui/ui'
import { TimelineChart } from '../components/ui/TimelineChart'
import { LogCoverage } from '../components/logview/LogCoverage'
import { CaseChain, type TimelineFilters } from '../components/casework/CaseChain'
import { FirstSign, FirstSignEditor } from '../components/casework/FirstSign'
import { ArtifactWindow, type ArtifactStub } from '../components/review/ArtifactWindow'
import { TraceWindow, type TraceMarks } from '../components/logview/TraceWindow'
import { FileViewer } from '../components/review/FileViewer'
import { TriageFollowUp } from '../components/review/triage'
import { useTriage } from '../components/review/useTriage'
import { CaseProfileButton } from '../components/casework/CaseProfile'
import type { Navigate } from '../App'

function filtersFromUrl(): TimelineFilters {
  const params = new URLSearchParams(location.search)
  const scope = params.get('scope')
  const source = params.get('event_source')
  const epoch = (key: string) => {
    const raw = params.get(key)
    return raw != null && raw !== '' && Number.isFinite(Number(raw)) && Math.abs(Number(raw)) < 8640000000000 ? raw : undefined
  }
  return {
    scope: scope === 'all' || scope === 'pending' ? scope : 'confirmed',
    event_source: source === 'log' || source === 'filesystem' || source === 'dump' ? source : undefined,
    from_epoch: epoch('from_epoch'), to_epoch: epoch('to_epoch'),
  }
}

const inputDate = (epoch?: string) => epoch == null ? '' : new Date(Number(epoch) * 1000).toISOString().slice(0, 19)
const inputEpoch = (value: string) => value ? String(new Date(`${value}Z`).getTime() / 1000) : undefined

export function Timeline({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const qc = useQueryClient()
  const [filters, setFilters] = useState<TimelineFilters>(filtersFromUrl)
  const [focusRequest, setFocusRequest] = useState(0)
  const [choosing, setChoosing] = useState(false)
  const [editEvent, setEditEvent] = useState<ChainEvent | null>(null)
  const chainRef = useRef<HTMLDivElement>(null)
  const openRequest = useRef(0)
  const [opening, setOpening] = useState(false)
  const [openError, setOpenError] = useState(false)
  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [focusId, setFocusId] = useState(() => new URLSearchParams(location.search).get('event') ?? '')
  useEffect(() => {
    const restore = () => {
      if (new URLSearchParams(location.search).get('view') !== 'timeline') return
      setFocusId(new URLSearchParams(location.search).get('event') ?? '')
      setFilters(filtersFromUrl())
      setChoosing(false)
    }
    restore()
    window.addEventListener('popstate', restore)
    window.addEventListener('shellhound:navigated', restore)
    return () => {
      window.removeEventListener('popstate', restore)
      window.removeEventListener('shellhound:navigated', restore)
      openRequest.current += 1
    }
  }, [slug])
  const navigate = (next: TimelineFilters, event = '') => {
    gotoView('timeline', { ...next, event })
    setFilters(next)
    setFocusId(event)
    setFocusRequest((value) => value + 1)
  }
  const openArtifact = async (artifact: string) => {
    const request = ++openRequest.current
    setOpening(true)
    setOpenError(false)
    try {
      const context = await qc.fetchQuery({ queryKey: ['artifact', slug, artifact],
        queryFn: () => api<ArtifactContext>(`/api/cases/${slug}/artifact?artifact=${encodeURIComponent(artifact)}`) })
      if (request !== openRequest.current) return
      setSelected({ artifact, artifact_kind: context.kind, worst: context.worst,
        triage: context.triage, triage_note: context.triage_note })
    } catch {
      if (request === openRequest.current) setOpenError(true)
    } finally {
      if (request === openRequest.current) setOpening(false)
    }
  }
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
  const { data: firstSign } = useQuery({ queryKey: ['first-sign', slug],
    queryFn: () => api<FirstSignData>(`/api/cases/${slug}/first-sign`) })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((item) => ({
    kind: item.kind, path: item.path, label: item.label,
  }))

  if (isError) return <Card className="p-4"><p role="alert">{tr('incident.loadFailed')}</p><Button onClick={() => void refetch()}>{tr('common.retry')}</Button></Card>
  if (!data) return <div className="py-16 text-center text-[var(--muted)]">{tr('common.loading')}</div>
  const sparseTimeline = data.timeline.length < 4
  const badRange = filters.from_epoch != null && filters.to_epoch != null && Number(filters.to_epoch) <= Number(filters.from_epoch)
  const hasRange = filters.from_epoch != null || filters.to_epoch != null
  const filterClass = 'min-w-0 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1.5 text-sm text-[var(--fg)]'
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
      <FirstSign slug={slug} data={firstSign ?? data.first_sign} editing
        onTimeline={(id) => navigate({ scope: 'confirmed' }, id)}
        onChoose={() => {
          navigate({ scope: 'confirmed' })
          setChoosing(true)
          chainRef.current?.scrollIntoView({ block: 'start', behavior: 'smooth' })
        }} />
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
      <div ref={chainRef} className="scroll-mt-4 space-y-3">
      <Card className="p-3">
        <fieldset className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <legend className="mb-2 text-sm font-semibold">{tr('timeline.filters')}</legend>
          <label className="flex min-w-0 flex-col gap-1 text-xs text-[var(--muted)]">{tr('timeline.filter.decision')}
            <select className={filterClass} value={filters.scope ?? 'confirmed'} onChange={(e) => navigate({ ...filters, scope: e.target.value as TimelineFilters['scope'] })}>
              {(['confirmed', 'pending', 'all'] as const).map((scope) => <option key={scope} value={scope}>{tr(`timeline.filter.${scope}`)}</option>)}
            </select>
          </label>
          <label className="flex min-w-0 flex-col gap-1 text-xs text-[var(--muted)]">{tr('timeline.filter.source')}
            <select className={filterClass} value={filters.event_source ?? ''} onChange={(e) => navigate({ ...filters, event_source: e.target.value as TimelineFilters['event_source'] || undefined })}>
              <option value="">{tr('timeline.filter.anySource')}</option>
              {(['filesystem', 'log', 'dump'] as const).map((source) => <option key={source} value={source}>{tr(`timeline.filter.${source}`)}</option>)}
            </select>
          </label>
          <label className="flex min-w-0 flex-col gap-1 text-xs text-[var(--muted)]">{tr('timeline.filter.from')}
            <input className={filterClass} type="datetime-local" step="1" value={inputDate(filters.from_epoch)}
              onChange={(e) => navigate({ ...filters, from_epoch: inputEpoch(e.target.value) })} />
          </label>
          <label className="flex min-w-0 flex-col gap-1 text-xs text-[var(--muted)]">{tr('timeline.filter.to')}
            <input className={filterClass} type="datetime-local" step="1" value={inputDate(filters.to_epoch)}
              onChange={(e) => navigate({ ...filters, to_epoch: inputEpoch(e.target.value) })} />
          </label>
        </fieldset>
        <div className="mt-2 flex flex-wrap gap-2">
          {filters.scope !== 'confirmed' && <Button variant="ghost" aria-label={tr('timeline.filter.remove', { filter: tr('timeline.filter.decision') })}
            onClick={() => navigate({ ...filters, scope: 'confirmed' })}>{tr(`timeline.filter.${filters.scope}`)}<X size={13} /></Button>}
          {filters.event_source && <Button variant="ghost" aria-label={tr('timeline.filter.remove', { filter: tr('timeline.filter.source') })}
            onClick={() => navigate({ ...filters, event_source: undefined })}>{tr(`timeline.filter.${filters.event_source}`)}<X size={13} /></Button>}
          {hasRange && <Button variant="ghost" aria-label={tr('timeline.filter.remove', { filter: tr('timeline.filter.range') })}
            onClick={() => navigate({ ...filters, from_epoch: undefined, to_epoch: undefined })}>{tr('timeline.filter.range')}<X size={13} /></Button>}
        </div>
        {badRange && <p role="alert" className="mt-2 text-xs text-[var(--review-text)]">{tr('timeline.filter.invalid')}</p>}
      </Card>
      {choosing && <p role="status" className="text-sm text-[var(--review-text)]">{tr('timeline.filter.selectFirst')}</p>}
      {opening && <p role="status" className="text-sm text-[var(--muted)]">{tr('common.loading')}</p>}
      {openError && <p role="alert" className="text-sm text-[var(--danger-text)]">{tr('timeline.artifact.failed')}</p>}
      {!badRange && <CaseChain slug={slug} filters={filters} focusId={focusId} focusRequest={focusRequest} showSummary={false}
        onOpen={(artifact) => void openArtifact(artifact)}
        onSelectFirstSign={(event) => setEditEvent(event)}
        onTrace={(ip) => { setTraceMarks(undefined); setTraceIps([ip]) }} />
      }
      </div>
      {editEvent && <FirstSignEditor slug={slug} event={editEvent} initialNote={(firstSign ?? data.first_sign)?.note ?? ''}
        onClose={() => setEditEvent(null)} onSaved={() => { setEditEvent(null); setChoosing(false) }} />}
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
