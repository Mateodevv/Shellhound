// Actors.tsx -- an investigation workspace over every client in the logs.
//
// The list answers "who deserves attention?"; the inspector answers "why?".
// Telemetry, automatic detections, IOC membership and analyst decisions stay
// visibly separate so that one source can never masquerade as another.
import { type ReactNode, useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Box, ChevronLeft, ChevronRight, Crosshair, Download, FileSearch,
  ListFilter, ShieldCheck, Users,
} from 'lucide-react'
import { useT, type Translate } from '../i18n'
import {
  api, downloadUrl, post, type Actor, type ActorDetail, type ActorsResponse,
  type CaseDetail,
} from '../api'
import {
  formatCount, formatDay, formatLogTime, formatSpan, relativeTime,
  type EvidenceRoot,
} from '../format'
import {
  Button, EmptyState, SearchInput, SeverityBadge, Tag, TriageBadge,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { Sparkline } from '../components/Sparkline'
import { IpFlag } from '../components/IpFlag'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import type { ViewId } from '../App'

const PAGE_SIZE = 50
const BF_FALLBACK = 30
const NO_ACTORS: Actor[] = []

type ActorView = 'relevant' | 'confirmed' | 'review' | 'notable' | 'scanner' | 'all'

const VIEWS: { id: ActorView; label: string; help: string }[] = [
  { id: 'relevant', label: 'actors.view.relevant', help: 'actors.view.relevant.help' },
  { id: 'confirmed', label: 'actors.view.confirmed', help: 'actors.view.confirmed.help' },
  { id: 'review', label: 'actors.view.review', help: 'actors.view.review.help' },
  { id: 'notable', label: 'actors.view.notable', help: 'actors.view.notable.help' },
  { id: 'scanner', label: 'actors.view.scanner', help: 'actors.view.scanner.help' },
  { id: 'all', label: 'actors.view.all', help: 'actors.view.all.help' },
]

type Signal = {
  key: string
  title: string
  detail: string
  tone?: 'danger' | 'warn' | 'accent'
}

/** The strongest statement the access log supports. This deliberately does
 * not look at triage: "measured" and "decided" are independent axes. */
function actorSignals(a: Actor | ActorDetail['actor'], tr: Translate,
                      bfThreshold = BF_FALLBACK): Signal[] {
  const signals: Signal[] = []
  if (a.upload_php_ok > 0) signals.push({
    key: 'shellAccess', title: tr('badge.shellAccess'), tone: 'danger',
    detail: tr('actors.signal.success', {
      ok: formatCount(a.upload_php_ok), attempts: formatCount(a.upload_php_attempts),
    }),
  })
  if (a.cms_dir_php_ok > 0) signals.push({
    key: 'cmsDirPhp', title: tr('badge.cmsDirPhp'), tone: 'danger',
    detail: tr('actors.signal.success', {
      ok: formatCount(a.cms_dir_php_ok), attempts: formatCount(a.cms_dir_php_attempts),
    }),
  })
  if (a.admin_ok > 0 && a.login_posts >= bfThreshold && a.login_burst >= bfThreshold) {
    signals.push({
      key: 'loginSuccess', title: tr('badge.loginSuccess'), tone: 'danger',
      detail: tr('actors.signal.login', {
        admin: formatCount(a.admin_ok), burst: formatCount(a.login_burst),
      }),
    })
  }
  if (a.sqli_ok > 0) signals.push({
    key: 'sqliOk', title: tr('badge.sqliOk', { n: a.sqli_ok }), tone: 'warn',
    detail: tr('actors.signal.success', {
      ok: formatCount(a.sqli_ok), attempts: formatCount(a.sqli_attempts),
    }),
  })
  if (a.traversal_ok > 0) signals.push({
    key: 'traversal', title: tr('badge.traversal'), tone: 'warn',
    detail: tr('actors.signal.success', {
      ok: formatCount(a.traversal_ok), attempts: formatCount(a.traversal_attempts),
    }),
  })
  if (a.login_posts >= bfThreshold) signals.push({
    key: 'bruteForce', title: tr('badge.bruteForce', { n: a.login_posts }), tone: 'warn',
    detail: tr('actors.signal.burst', { n: formatCount(a.login_burst) }),
  })
  if (a.upload_php_attempts > 0 && a.upload_php_ok === 0) signals.push({
    key: 'uploadAttempt', title: tr('actors.signal.uploadAttempt'),
    detail: tr('actors.signal.attempts', { n: formatCount(a.upload_php_attempts) }),
  })
  if (a.sqli_attempts > 0 && a.sqli_ok === 0) signals.push({
    key: 'sqliAttempts', title: tr('badge.sqliAttempts', { n: a.sqli_attempts }),
    detail: tr('actors.signal.noSuccess'),
  })
  if (a.traversal_attempts > 0 && a.traversal_ok === 0) signals.push({
    key: 'traversalAttempt', title: tr('actors.signal.traversalAttempt'),
    detail: tr('actors.signal.noSuccess'),
  })
  if (a.scanner_uas !== '[]') signals.push({
    key: 'scanner', title: tr('badge.scanner'),
    detail: tr('actors.signal.scanner'),
  })
  return signals
}

function viewCount(view: ActorView, data?: ActorsResponse) {
  const f = data?.facets
  if (!f) return undefined
  if (view === 'confirmed') return f.triage.confirmed ?? 0
  if (view === 'review') return (f.triage.new ?? 0) + (f.triage.reviewed ?? 0)
  if (view === 'notable') return f.alerted
  return f[view]
}

function queryFor(view: ActorView): Record<string, string> {
  if (view === 'relevant') return { hide: 'quiet' }
  if (view === 'confirmed') return { triage_states: 'confirmed' }
  if (view === 'review') return { triage_states: 'new,reviewed' }
  if (view === 'notable') return { flag: 'alerted' }
  if (view === 'scanner') return { flag: 'scanner' }
  return {}
}

export function Actors({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const triage = useTriage(slug)
  const [view, setView] = useState<ActorView>('relevant')
  const [search, setSearch] = useState('')
  const [sort, setSort] = useState('evidence')
  const [page, setPage] = useState(0)
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [activeIp, setActiveIp] = useState<string | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [artifact, setArtifact] = useState<ArtifactStub | null>(null)
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)

  const filters = queryFor(view)
  const query = new URLSearchParams({
    search, sort, limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE), ...filters,
  })
  const { data, isFetching } = useQuery({
    queryKey: ['actors', slug, view, search, sort, page],
    queryFn: () => api<ActorsResponse>(`/api/cases/${slug}/actors?${query}`),
  })
  const actors = data?.actors ?? NO_ACTORS

  const { data: detail, isFetching: detailLoading } = useQuery({
    queryKey: ['actor-detail', slug, activeIp],
    queryFn: () => api<ActorDetail>(
      `/api/cases/${slug}/actor?ip=${encodeURIComponent(activeIp ?? '')}`),
    enabled: Boolean(activeIp),
  })

  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))

  useEffect(() => { setPage(0) }, [view, search, sort])
  useEffect(() => {
    if (!activeIp && actors.length) setActiveIp(actors[0].ip)
  }, [activeIp, actors])

  const collect = useMutation({
    mutationFn: (ips: string[]) => post(`/api/cases/${slug}/actors/collect`, { ips }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actors'] })
      qc.invalidateQueries({ queryKey: ['actor-detail'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
      setChecked(new Set())
    },
  })

  const total = data?.total ?? 0
  const from = total ? page * PAGE_SIZE + 1 : 0
  const to = Math.min(total, (page + 1) * PAGE_SIZE)
  const pageIps = actors.map((a) => a.ip)
  const pageSelected = pageIps.length > 0 && pageIps.every((ip) => checked.has(ip))

  const toggleCurrentPage = () => {
    const next = new Set(checked)
    if (pageSelected) pageIps.forEach((ip) => next.delete(ip))
    else pageIps.forEach((ip) => next.add(ip))
    setChecked(next)
  }

  const openTrace = (ips: string[], exact: string[] = []) => {
    setTraceMarks({ exact: exact.filter(Boolean), reason: tr('marks.alertTrigger') })
    setTraceIps(ips)
  }

  const selectedActors = actors.filter((a) => checked.has(a.ip))

  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold">{tr('actors.workspace.title')}</h1>
            <InfoDot body={tr('actors.workspace.info')}
              hint={tr('actors.workspace.infoHint')} />
          </div>
          <p className="mt-0.5 max-w-3xl text-[13px] text-[var(--muted)]">
            {tr('actors.workspace.sub')}
          </p>
        </div>
        <div className="flex items-center gap-2 text-[12px] text-[var(--muted)]">
          <ListFilter size={14} />
          {tr('actors.casePopulation', { n: formatCount(data?.facets?.all ?? total) })}
        </div>
      </header>

      <nav className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6"
        aria-label={tr('actors.views')}>
        {VIEWS.map((item) => {
          const count = viewCount(item.id, data)
          return (
            <Tooltip key={item.id} hint={tr(item.help)}>
              <button type="button" aria-pressed={view === item.id}
                onClick={() => { setView(item.id); setActiveIp(null) }}
                className={clsx(
                  'flex min-w-0 cursor-pointer items-center justify-between gap-2 rounded-xl border px-3 py-2.5 text-left transition-colors',
                  view === item.id
                    ? 'border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent-text)]'
                    : 'border-[var(--line)] bg-[var(--panel)] hover:border-[var(--accent)]/50',
                )}>
                <span className="truncate text-[12px] font-semibold">{tr(item.label)}</span>
                {count != null && <span className="tabular text-[11px] opacity-75">{formatCount(count)}</span>}
              </button>
            </Tooltip>
          )
        })}
      </nav>

      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--panel)] p-2.5">
        <SearchInput value={search} onChange={setSearch} placeholder={tr('actors.searchExpanded')} />
        <select value={sort} onChange={(e) => setSort(e.target.value)}
          aria-label={tr('common.sort')}
          className="cursor-pointer rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2.5 py-1.5 text-xs outline-none">
          <option value="evidence">{tr('actors.sort.evidence')}</option>
          <option value="last">{tr('actors.sort.last')}</option>
          <option value="requests">{tr('actors.sort.requests')}</option>
          <option value="errors">{tr('actors.sort.errors')}</option>
          <option value="first">{tr('actors.sort.first')}</option>
        </select>
        <div className="ml-auto flex items-center gap-2 text-[12px] text-[var(--muted)]">
          {isFetching && <span>{tr('common.loading')} · </span>}
          <span className="tabular">{tr('actors.range', {
            from: formatCount(from), to: formatCount(to), total: formatCount(total),
          })}</span>
        </div>
      </div>

      {checked.size > 0 && (
        <div className="sticky top-2 z-20 flex flex-wrap items-center gap-2 rounded-xl border border-[var(--accent)]/50 bg-[var(--panel)] px-3 py-2 shadow-lg">
          <span className="mr-1 text-[13px] font-semibold">
            {tr('common.selected', { n: checked.size })}
          </span>
          <Button variant="primary" onClick={() => openTrace(
            [...checked], selectedActors.flatMap((a) => a.alerts.map((alert) => alert.example)),
          )}>
            <Crosshair size={14} /> {tr('actors.traceSelected')}
          </Button>
          <Tooltip hint={tr('actors.collect.hint')}>
            <Button onClick={() => collect.mutate([...checked])} disabled={collect.isPending}>
              <Box size={14} /> {tr('actors.toIocBox')}
            </Button>
          </Tooltip>
          <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] font-medium hover:border-[var(--accent)]/60"
            href={downloadUrl(`/api/cases/${slug}/trace.csv?ips=${[...checked].join(',')}`)}>
            <Download size={14} /> {tr('actors.traceCsv')}
          </a>
          <Button variant="ghost" onClick={() => setChecked(new Set())}>
            {tr('common.clearSelection')}
          </Button>
        </div>
      )}

      <div className="grid min-w-0 grid-cols-1 items-start gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(330px,0.44fr)]">
        <section className="min-w-0 overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--panel)]"
          aria-label={tr('actors.results')}>
          <div className="flex items-center gap-3 border-b border-[var(--line)] px-3 py-2 text-[12px] text-[var(--muted)]">
            <label className="inline-flex cursor-pointer items-center gap-2">
              <input type="checkbox" className="accent-[var(--accent)]"
                checked={pageSelected} onChange={toggleCurrentPage} />
              {tr('actors.selectPage')}
            </label>
            <span className="ml-auto">{tr(`actors.view.${view}`)}</span>
          </div>

          <div className="divide-y divide-[var(--line-soft)]">
            {actors.map((actor) => {
              const signals = actorSignals(actor, tr, data?.bf_threshold)
              const primary = signals[0]
              const analystOnly = actor.triage === 'confirmed' && !primary
              const errors = actor.err4 + actor.err5
              const active = actor.ip === activeIp
              return (
                <article key={actor.ip_id} role="button" tabIndex={0}
                  aria-current={active ? 'true' : undefined}
                  onClick={() => setActiveIp(actor.ip)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') setActiveIp(actor.ip)
                  }}
                  className={clsx(
                    'group cursor-pointer p-3 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--accent)]',
                    active ? 'bg-[var(--accent-soft)]' : 'hover:bg-[var(--panel-2)]',
                  )}>
                  <div className="flex min-w-0 items-start gap-3">
                    <input type="checkbox" className="mt-1 shrink-0 cursor-pointer accent-[var(--accent)]"
                      aria-label={tr('actors.selectClient', { ip: actor.ip })}
                      checked={checked.has(actor.ip)}
                      onClick={(e) => e.stopPropagation()}
                      onChange={(e) => {
                        const next = new Set(checked)
                        if (e.target.checked) next.add(actor.ip)
                        else next.delete(actor.ip)
                        setChecked(next)
                      }} />
                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
                        <IpFlag ip={actor.ip} />
                        <span className="mono font-semibold">{actor.ip}</span>
                        {actor.in_box && <Tag tone="accent" explain={tr('actors.inBox')}>IOC</Tag>}
                        {actor.triage && actor.triage !== 'new' && (
                          <TriageBadge state={actor.triage} label={tr(`triage.${actor.triage}`)} />
                        )}
                      </div>

                      <div className="mt-2 grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_170px]">
                        <div className="min-w-0">
                          <div className={clsx('text-[13px] font-semibold',
                            primary?.tone === 'danger' && 'text-[var(--danger-text)]',
                            primary?.tone === 'warn' && 'text-[var(--sev-low)]',
                            analystOnly && 'text-[var(--danger-text)]')}>
                            {primary?.title ?? (analystOnly
                              ? tr('actors.signal.analystConfirmed')
                              : tr('actors.signal.none'))}
                          </div>
                          <div className="mt-0.5 text-[12px] text-[var(--muted)]">
                            {primary?.detail ?? (analystOnly
                              ? tr('actors.signal.noAutomatic')
                              : tr('actors.signal.noneDetail'))}
                          </div>
                          {signals.length > 1 && (
                            <div className="mt-1.5 flex flex-wrap gap-1">
                              {signals.slice(1, 3).map((signal) => (
                                <Tag key={signal.key} tone={signal.tone}>{signal.title}</Tag>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="min-w-0">
                          <Sparkline data={actor.sparkline}
                            color={primary?.tone === 'danger' ? 'var(--sev-high)' : 'var(--accent)'} />
                          <div className="mt-1 truncate text-[11px] text-[var(--muted)]"
                            title={`${formatLogTime(actor.first_epoch, actor.tz)} – ${formatLogTime(actor.last_epoch, actor.tz)}`}>
                            {formatDay(actor.first_epoch, actor.tz)} → {formatDay(actor.last_epoch, actor.tz)}
                            {' · '}{formatSpan(actor.first_epoch, actor.last_epoch)}
                          </div>
                        </div>
                      </div>

                      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-[var(--muted)]">
                        <span>{tr('actors.metric.requests', { n: formatCount(actor.requests) })}</span>
                        <span className={errors ? 'text-[var(--sev-medium)]' : undefined}>
                          {tr('actors.metric.errors', { n: formatCount(errors) })}
                        </span>
                        <span>{tr('actors.lastSeen', {
                          when: relativeTime(actor.last_epoch
                            ? new Date(actor.last_epoch * 1000).toISOString() : null),
                        })}</span>
                        <Button className="ml-auto" variant="ghost"
                          onClick={() => openTrace([actor.ip], actor.alerts.map((alert) => alert.example))}>
                          <Crosshair size={13} /> Trace
                        </Button>
                      </div>
                    </div>
                  </div>
                </article>
              )
            })}
          </div>

          {!actors.length && !isFetching && (
            <EmptyState icon={<Users size={36} />} title={tr('actors.empty.filtered')}
              sub={search ? tr('actors.empty.search') : tr('actors.empty.view')} />
          )}

          {total > PAGE_SIZE && (
            <Pagination page={page} total={total} tr={tr}
              onPage={setPage} />
          )}
        </section>

        <ActorInspector detail={detail} loading={detailLoading} threshold={data?.bf_threshold}
          tr={tr}
          onTrace={() => detail && openTrace(
            [detail.actor.ip], detail.alerts.map((alert) => alert.example),
          )}
          onCollect={() => detail && collect.mutate([detail.actor.ip])}
          onArtifact={() => {
            if (!detail?.triage) return
            triage.clearCollected()
            setArtifact({
              artifact: detail.actor.ip, artifact_kind: 'client',
              worst: (detail.worst ?? 3) as 0 | 1 | 2 | 3,
              triage: detail.triage, triage_note: detail.triage_note,
            })
          }} />
      </div>

      <ArtifactWindow slug={slug} artifact={artifact} roots={roots}
        collected={triage.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips, marks) => { setTraceMarks(marks); setTraceIps(ips) }}
        onClose={() => { setArtifact(null); triage.clearCollected() }}
        onTriage={(state, note) => {
          if (artifact) triage.decide([artifact.artifact], state, note)
        }} />

      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
      <FileViewer slug={slug} path={viewing?.path ?? null} focusLine={viewing?.line}
        layer={2} onClose={() => setViewing(null)} />
      <TriageFollowUp t={triage} roots={roots} />
    </div>
  )
}

function Pagination({ page, total, tr, onPage }: {
  page: number; total: number; tr: Translate; onPage: (page: number) => void
}) {
  const pages = Math.ceil(total / PAGE_SIZE)
  return (
    <div className="flex items-center justify-between border-t border-[var(--line)] px-3 py-2">
      <span className="text-[12px] text-[var(--muted)]">
        {tr('viewer.page')} {page + 1} / {pages}
      </span>
      <div className="flex gap-1">
        <Button variant="ghost" disabled={page === 0} title={tr('actors.page.previous')}
          onClick={() => onPage(Math.max(0, page - 1))}>
          <ChevronLeft size={15} />
        </Button>
        <Button variant="ghost" disabled={page + 1 >= pages} title={tr('actors.page.next')}
          onClick={() => onPage(page + 1)}>
          <ChevronRight size={15} />
        </Button>
      </div>
    </div>
  )
}

function ActorInspector({ detail, loading, threshold, tr, onTrace, onCollect, onArtifact }: {
  detail?: ActorDetail
  loading: boolean
  threshold?: number
  tr: Translate
  onTrace: () => void
  onCollect: () => void
  onArtifact: () => void
}) {
  if (!detail) {
    return (
      <aside className="rounded-xl border border-[var(--line)] bg-[var(--panel)] p-5 text-[13px] text-[var(--muted)]">
        {loading ? tr('common.loading') : tr('actors.inspector.empty')}
      </aside>
    )
  }
  const actor = detail.actor
  const signals = actorSignals(actor, tr, threshold)
  const primary = signals[0]
  const analystOnly = detail.triage === 'confirmed' && !primary
  return (
    <aside className="min-w-0 rounded-xl border border-[var(--line)] bg-[var(--panel)] lg:sticky lg:top-3"
      aria-label={tr('actors.inspector.title')}>
      <div className="border-b border-[var(--line)] p-4">
        <div className="flex flex-wrap items-center gap-2">
          <IpFlag ip={actor.ip} />
          <h2 className="mono text-base font-bold">{actor.ip}</h2>
          {detail.in_box && <Tag tone="accent" explain={tr('actors.inBox')}>IOC</Tag>}
          {detail.triage && (
            <TriageBadge state={detail.triage} label={tr(`triage.${detail.triage}`)} />
          )}
        </div>
        <div className={clsx('mt-3 text-[14px] font-semibold',
          primary?.tone === 'danger' && 'text-[var(--danger-text)]',
          primary?.tone === 'warn' && 'text-[var(--sev-low)]',
          analystOnly && 'text-[var(--danger-text)]')}>
          {primary?.title ?? (analystOnly
            ? tr('actors.signal.analystConfirmed') : tr('actors.signal.none'))}
        </div>
        <p className="mt-1 text-[12px] leading-relaxed text-[var(--muted)]">
          {primary?.detail ?? (analystOnly
            ? tr('actors.signal.noAutomatic') : tr('actors.signal.noneDetail'))}
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button variant="primary" onClick={onTrace}>
            <Crosshair size={14} /> {detail.alerts.some((alert) => alert.example)
              ? tr('actors.inspectTrace') : tr('actors.inspectTraceAll')}
          </Button>
          {!detail.in_box && <Button onClick={onCollect}><Box size={14} /> {tr('actors.toIocBox')}</Button>}
          {detail.triage && (
            <Button onClick={onArtifact}>
              <FileSearch size={14} /> {tr('actors.openEvidence')}
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-3 border-b border-[var(--line)]">
        <Metric label={tr('table.requests')} value={formatCount(actor.requests)} />
        <Metric label={tr('hunt.duration')} value={formatSpan(actor.first_epoch, actor.last_epoch)} />
        <Metric label={tr('table.errors')} value={formatCount(actor.err4 + actor.err5)} />
      </div>

      <div className="max-h-[calc(100vh-22rem)] min-h-[220px] overflow-y-auto p-4">
        <InspectorSection title={tr('actors.inspector.assessment')}>
          {detail.triage ? (
            <div className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2.5">
              <div className="flex items-center gap-2">
                <ShieldCheck size={14} className="text-[var(--accent)]" />
                <TriageBadge state={detail.triage} label={tr(`triage.${detail.triage}`)} />
                {detail.triaged_at && <span className="ml-auto text-[10px] text-[var(--muted)]">{detail.triaged_at}</span>}
              </div>
              {detail.triage_note && <p className="mt-2 text-[12px] leading-relaxed">{detail.triage_note}</p>}
            </div>
          ) : <p className="text-[12px] text-[var(--muted)]">{tr('actors.inspector.noDecision')}</p>}
        </InspectorSection>

        <InspectorSection title={tr('actors.inspector.findings')} count={detail.findings.length}>
          {detail.findings.length ? detail.findings.slice(0, 4).map((finding) => (
            <div key={finding.id} className="rounded-lg border border-[var(--line-soft)] p-2.5">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <span className="min-w-0 truncate text-[12px] font-semibold">{finding.rule}</span>
              </div>
              <p className="mt-1.5 line-clamp-3 text-[11px] leading-relaxed text-[var(--muted)]">
                {finding.evidence}
              </p>
            </div>
          )) : <p className="text-[12px] text-[var(--muted)]">{tr('actors.inspector.noFindings')}</p>}
        </InspectorSection>

        <InspectorSection title={tr('actors.inspector.signals')} count={signals.length}>
          {signals.length ? signals.map((signal) => (
            <div key={signal.key} className="flex items-start gap-2 text-[12px]">
              <span className={clsx('mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full',
                signal.tone === 'danger' ? 'bg-[var(--sev-high)]'
                  : signal.tone === 'warn' ? 'bg-[var(--sev-low)]' : 'bg-[var(--muted)]')} />
              <div><span className="font-semibold">{signal.title}</span>
                <span className="text-[var(--muted)]"> · {signal.detail}</span></div>
            </div>
          )) : <p className="text-[12px] text-[var(--muted)]">{tr('actors.signal.noneDetail')}</p>}
        </InspectorSection>

        <InspectorSection title={tr('actors.inspector.paths')}>
          {detail.top_paths.map((path) => (
            <div key={path.uri} className="flex min-w-0 items-start gap-2 text-[11px]">
              <span className="mono min-w-0 flex-1 break-all">{path.uri}</span>
              <span className="shrink-0 tabular text-[var(--muted)]">
                {formatCount(path.n)} · {tr('actors.path.ok', { n: formatCount(path.ok) })}
              </span>
            </div>
          ))}
        </InspectorSection>

        <InspectorSection title={tr('actors.inspector.agents')}>
          {detail.top_agents.map((agent) => (
            <div key={agent.agent} className="flex min-w-0 gap-2 text-[11px]">
              <span className="min-w-0 flex-1 break-words text-[var(--muted)]">{agent.agent || '—'}</span>
              <span className="shrink-0 tabular">{formatCount(agent.n)}</span>
            </div>
          ))}
        </InspectorSection>

        <div className="text-[11px] text-[var(--muted)]">
          {tr('actors.inspector.period', {
            first: formatLogTime(actor.first_epoch, actor.tz),
            last: formatLogTime(actor.last_epoch, actor.tz),
          })}
        </div>
      </div>
    </aside>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 px-3 py-2.5 text-center">
      <div className="truncate text-[10px] uppercase tracking-wider text-[var(--muted)]">{label}</div>
      <div className="mt-0.5 truncate text-[13px] font-semibold tabular">{value}</div>
    </div>
  )
}

function InspectorSection({ title, count, children }: {
  title: string; count?: number; children: ReactNode
}) {
  return (
    <section className="mb-5">
      <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
        {title}{count != null && <span className="ml-1.5 tabular opacity-70">{count}</span>}
      </h3>
      <div className="flex flex-col gap-2">{children}</div>
    </section>
  )
}
