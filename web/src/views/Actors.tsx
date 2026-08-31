// Actors.tsx -- an investigation workspace over every client in the logs.
//
// The list answers "who deserves attention?"; the inspector answers "why?".
// Telemetry, automatic detections, IOC membership and analyst decisions stay
// visibly separate so that one source can never masquerade as another.
import { type ReactNode, useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Activity, Box, ChevronLeft, ChevronRight, Crosshair, Download, FileSearch,
  GitCompareArrows, Link2, ListFilter, Rows3, ShieldCheck,
  SlidersHorizontal, Users, X,
} from 'lucide-react'
import { useT, type Translate } from '../i18n'
import {
  api, downloadUrl, post, type Actor, type ActorComparison, type ActorDetail,
  type ActorsResponse, type CaseDetail,
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
import type { Navigate } from '../App'

const PAGE_SIZE = 50
const BF_FALLBACK = 30
const NO_ACTORS: Actor[] = []

type ActorView = 'relevant' | 'confirmed' | 'all'
type FocusFilter = 'any' | 'notable' | 'scanner' | 'bruteforce' | 'probes'
type DecisionFilter = 'any' | 'new' | 'review' | 'dismissed'
type Density = 'comfortable' | 'compact'
export type ActorInspectorTab = 'overview' | 'evidence' | 'activity' | 'relations'

function actorDeepLink() {
  const params = new URLSearchParams(location.search)
  const section = params.get('section')
  return {
    ip: params.get('actor'),
    search: params.get('search') ?? '',
    section: section === 'evidence' || section === 'activity' || section === 'relations'
      ? section : 'overview',
  } as const
}

const VIEWS: { id: ActorView; label: string; help: string }[] = [
  { id: 'relevant', label: 'actors.view.relevant', help: 'actors.view.relevant.help' },
  { id: 'confirmed', label: 'actors.view.confirmed', help: 'actors.view.confirmed.help' },
  { id: 'all', label: 'actors.view.all', help: 'actors.view.all.help' },
]

const FOCUS_FILTERS: { id: FocusFilter; label: string; help: string }[] = [
  { id: 'any', label: 'actors.filter.anySignal', help: 'actors.filter.anySignal.help' },
  { id: 'notable', label: 'actors.view.notable', help: 'actors.view.notable.help' },
  { id: 'scanner', label: 'actors.view.scanner', help: 'actors.view.scanner.help' },
  { id: 'bruteforce', label: 'actors.flag.brute', help: 'actors.flag.brute.hint' },
  { id: 'probes', label: 'actors.flag.probes', help: 'actors.flag.probes.hint' },
]

const DECISION_FILTERS: { id: DecisionFilter; label: string }[] = [
  { id: 'any', label: 'actors.filter.anyDecision' },
  { id: 'new', label: 'actors.filter.undecided' },
  { id: 'review', label: 'actors.view.review' },
  { id: 'dismissed', label: 'triage.dismissed' },
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
  return f[view]
}

function queryFor(view: ActorView, focus: FocusFilter,
                  decision: DecisionFilter): Record<string, string> {
  const query: Record<string, string> = {}
  if (view === 'relevant') query.hide = 'quiet'
  if (view === 'confirmed') query.triage_states = 'confirmed'
  else if (decision === 'new') query.triage_states = 'new'
  else if (decision === 'review') query.triage_states = 'new,reviewed'
  else if (decision === 'dismissed') query.triage_states = 'dismissed'
  if (focus !== 'any') query.flag = focus === 'notable' ? 'alerted' : focus
  return query
}

export function Actors({ slug }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const qc = useQueryClient()
  const triage = useTriage(slug)
  const deepLink = actorDeepLink()
  const [view, setView] = useState<ActorView>('relevant')
  const [focus, setFocus] = useState<FocusFilter>('any')
  const [decision, setDecision] = useState<DecisionFilter>('any')
  const [filtersOpen, setFiltersOpen] = useState(false)
  const [density, setDensity] = useState<Density>('comfortable')
  const [search, setSearch] = useState(deepLink.search)
  const [sort, setSort] = useState('evidence')
  const [page, setPage] = useState(0)
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [activeIp, setActiveIp] = useState<string | null>(deepLink.ip)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [artifact, setArtifact] = useState<ArtifactStub | null>(null)
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [compareOpen, setCompareOpen] = useState(false)

  const filters = queryFor(view, focus, decision)
  const query = new URLSearchParams({
    search, sort, limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE), ...filters,
  })
  const { data, isFetching } = useQuery({
    queryKey: ['actors', slug, view, focus, decision, search, sort, page],
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

  useEffect(() => { setPage(0) }, [view, focus, decision, search, sort])
  useEffect(() => {
    if (!activeIp && actors.length && window.innerWidth >= 1024) setActiveIp(actors[0].ip)
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
  const appliedFilters = Number(focus !== 'any')
    + Number(decision !== 'any' && view !== 'confirmed')

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

      <nav className="inline-flex w-fit max-w-full overflow-x-auto rounded-xl border border-[var(--line)] bg-[var(--panel)] p-1"
        aria-label={tr('actors.views')}>
        {VIEWS.map((item) => {
          const count = viewCount(item.id, data)
          return (
            <Tooltip key={item.id} hint={tr(item.help)}>
              <button type="button" aria-pressed={view === item.id}
                onClick={() => {
                  setView(item.id)
                  if (item.id === 'confirmed') setDecision('any')
                  setActiveIp(null)
                }}
                className={clsx(
                  'flex shrink-0 cursor-pointer items-center gap-2 rounded-lg px-3 py-2 text-left transition-colors',
                  view === item.id
                    ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                    : 'text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--text)]',
                )}>
                <span className="text-[12px] font-semibold">{tr(item.label)}</span>
                {count != null && <span className="rounded bg-[var(--panel-2)] px-1.5 py-0.5 tabular text-[10px] opacity-80">{formatCount(count)}</span>}
              </button>
            </Tooltip>
          )
        })}
      </nav>

      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--panel)] p-2.5">
        <SearchInput value={search} onChange={setSearch} placeholder={tr('actors.searchExpanded')} />
        <Button variant={filtersOpen || appliedFilters ? 'primary' : 'default'}
          onClick={() => setFiltersOpen((open) => !open)}>
          <SlidersHorizontal size={14} /> {tr('actors.filters')}
          {appliedFilters > 0 && <span className="rounded bg-white/20 px-1.5 text-[10px] tabular">{appliedFilters}</span>}
        </Button>
        <select value={sort} onChange={(e) => setSort(e.target.value)}
          aria-label={tr('common.sort')}
          className="cursor-pointer rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2.5 py-1.5 text-xs outline-none">
          <option value="evidence">{tr('actors.sort.evidence')}</option>
          <option value="last">{tr('actors.sort.last')}</option>
          <option value="requests">{tr('actors.sort.requests')}</option>
          <option value="errors">{tr('actors.sort.errors')}</option>
          <option value="first">{tr('actors.sort.first')}</option>
        </select>
        <Tooltip hint={density === 'comfortable'
          ? tr('actors.density.compact.help') : tr('actors.density.comfortable.help')}>
          <Button variant="ghost" aria-label={tr('actors.density.toggle')}
            onClick={() => setDensity((current) => current === 'comfortable' ? 'compact' : 'comfortable')}>
            <Rows3 size={14} /> {tr(`actors.density.${density}`)}
          </Button>
        </Tooltip>
        <div className="ml-auto flex items-center gap-2 text-[12px] text-[var(--muted)]">
          {isFetching && <span>{tr('common.loading')} · </span>}
          <span className="tabular">{tr('actors.range', {
            from: formatCount(from), to: formatCount(to), total: formatCount(total),
          })}</span>
        </div>
      </div>

      {filtersOpen && (
        <section className="rounded-xl border border-[var(--line)] bg-[var(--panel)] p-3"
          aria-label={tr('actors.filters')}>
          <div className="grid gap-4 md:grid-cols-2">
            <FilterGroup title={tr('actors.filter.signal')}>
              {FOCUS_FILTERS.map((item) => (
                <Tooltip key={item.id} hint={tr(item.help)}>
                  <button type="button" aria-pressed={focus === item.id}
                    onClick={() => setFocus(item.id)}
                    className={clsx('rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors',
                      focus === item.id
                        ? 'border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent-text)]'
                        : 'border-[var(--line)] bg-[var(--panel-2)] hover:border-[var(--accent)]/60')}>
                    {tr(item.label)}
                  </button>
                </Tooltip>
              ))}
            </FilterGroup>
            <FilterGroup title={tr('actors.filter.decision')}>
              {DECISION_FILTERS.map((item) => (
                <button key={item.id} type="button"
                  disabled={view === 'confirmed' && item.id !== 'any'}
                  aria-pressed={(view === 'confirmed' && item.id === 'any') || decision === item.id}
                  onClick={() => setDecision(item.id)}
                  className={clsx('rounded-lg border px-2.5 py-1.5 text-[11px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-35',
                    decision === item.id
                      ? 'border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent-text)]'
                      : 'border-[var(--line)] bg-[var(--panel-2)] hover:border-[var(--accent)]/60')}>
                  {tr(item.label)}
                </button>
              ))}
            </FilterGroup>
          </div>
          {appliedFilters > 0 && (
            <Button className="mt-3" variant="ghost" onClick={() => { setFocus('any'); setDecision('any') }}>
              <X size={13} /> {tr('actors.filter.reset')}
            </Button>
          )}
        </section>
      )}

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
          <Tooltip hint={checked.size > 5
            ? tr('actors.compare.tooMany') : tr('actors.compare.help')}>
            <Button onClick={() => setCompareOpen(true)}
              disabled={checked.size < 2 || checked.size > 5}>
              <GitCompareArrows size={14} /> {tr('actors.compare.action')}
            </Button>
          </Tooltip>
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
            {actors.map((actor, actorIndex) => {
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
                    if (e.key === 'ArrowDown' && actors[actorIndex + 1]) {
                      e.preventDefault()
                      setActiveIp(actors[actorIndex + 1].ip)
                      const nextRow = e.currentTarget.nextElementSibling as HTMLElement | null
                      nextRow?.focus()
                    }
                    if (e.key === 'ArrowUp' && actors[actorIndex - 1]) {
                      e.preventDefault()
                      setActiveIp(actors[actorIndex - 1].ip)
                      const previousRow = e.currentTarget.previousElementSibling as HTMLElement | null
                      previousRow?.focus()
                    }
                  }}
                  className={clsx(
                    'group cursor-pointer transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--accent)]',
                    density === 'comfortable' ? 'p-3' : 'px-3 py-2',
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

                      <div className={clsx('grid min-w-0 gap-3 sm:grid-cols-[minmax(0,1fr)_170px]',
                        density === 'comfortable' ? 'mt-2' : 'mt-1')}>
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
                          {density === 'comfortable' && signals.length > 1 && (
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

                      <div className={clsx('flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-[var(--muted)]',
                        density === 'comfortable' ? 'mt-2' : 'mt-1')}>
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

        <ActorInspector key={activeIp ?? 'empty'} detail={detail} loading={detailLoading}
          initialTab={deepLink.section}
          threshold={data?.bf_threshold}
          tr={tr}
          onClose={() => setActiveIp(null)}
          onTrace={(exact, ips) => detail && openTrace(ips ?? [detail.actor.ip], exact
            ?? detail.alerts.map((alert) => alert.example))}
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

      <ActorCompareDialog slug={slug} ips={[...checked]} open={compareOpen}
        threshold={data?.bf_threshold} tr={tr}
        onTrace={() => { setCompareOpen(false); openTrace([...checked]) }}
        onClose={() => setCompareOpen(false)} />

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

export function ActorInspector({
  detail, loading, threshold, tr, initialTab, embedded = false, showClose = true,
  onClose, onTrace, onCollect, onArtifact,
}: {
  detail?: ActorDetail
  loading: boolean
  threshold?: number
  tr: Translate
  initialTab: ActorInspectorTab
  embedded?: boolean
  showClose?: boolean
  onClose: () => void
  onTrace: (exact?: string[], ips?: string[]) => void
  onCollect: () => void
  onArtifact: () => void
}) {
  const [tab, setTab] = useState<ActorInspectorTab>(initialTab)
  if (!detail) {
    return (
      <aside className={clsx(
        'rounded-xl border border-[var(--line)] bg-[var(--panel)] p-5 text-[13px] text-[var(--muted)]',
        !embedded && 'hidden lg:block',
      )}>
        {loading ? tr('common.loading') : tr('actors.inspector.empty')}
      </aside>
    )
  }
  const actor = detail.actor
  const signals = actorSignals(actor, tr, threshold)
  const primary = signals[0]
  const analystOnly = detail.triage === 'confirmed' && !primary
  return (
    <aside className={clsx(
      embedded
        ? 'relative flex h-full min-h-0 min-w-0 flex-col overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--panel)]'
        : 'fixed inset-0 z-40 min-w-0 overflow-y-auto bg-[var(--bg)] p-3 lg:sticky lg:inset-auto lg:top-3 lg:max-h-[calc(100vh-1.5rem)] lg:overflow-hidden lg:rounded-xl lg:border lg:border-[var(--line)] lg:bg-[var(--panel)] lg:p-0',
    )}
      aria-label={tr('actors.inspector.title')}>
      <div className="border-b border-[var(--line)] p-4">
        <div className="flex flex-wrap items-center gap-2 pr-9 lg:pr-0">
          <IpFlag ip={actor.ip} />
          <h2 className="mono text-base font-bold">{actor.ip}</h2>
          {detail.in_box && <Tag tone="accent" explain={tr('actors.inBox')}>IOC</Tag>}
          {detail.triage && (
            <TriageBadge state={detail.triage} label={tr(`triage.${detail.triage}`)} />
          )}
          {showClose && <Button className={clsx('absolute right-4 top-4', !embedded && 'lg:hidden')} variant="ghost"
            title={tr('common.close')} onClick={onClose}><X size={17} /></Button>
          }
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
          <Button variant="primary" onClick={() => onTrace()}>
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

      <nav className="flex overflow-x-auto border-b border-[var(--line)] px-2"
        aria-label={tr('actors.inspector.sections')}>
        {(['overview', 'evidence', 'activity', 'relations'] as const).map((id) => (
          <button key={id} type="button" aria-pressed={tab === id}
            onClick={() => setTab(id)}
            className={clsx('shrink-0 border-b-2 px-2.5 py-2 text-[11px] font-semibold transition-colors',
              tab === id
                ? 'border-[var(--accent)] text-[var(--accent-text)]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--text)]')}>
            {tr(`actors.inspector.tab.${id}`)}
            {id === 'relations' && detail.relations.length > 0
              && <span className="ml-1 opacity-70"> {detail.relations.length}</span>}
          </button>
        ))}
      </nav>

      <div className={clsx('min-h-[220px] p-4', embedded
        ? 'min-h-0 flex-1 overflow-y-auto'
        : 'lg:max-h-[calc(100vh-27rem)] lg:overflow-y-auto')}>
        {tab === 'overview' && <>
          <InspectorSection title={tr('actors.inspector.why')}>
            <div className="rounded-lg border border-[var(--accent)]/35 bg-[var(--accent-soft)] p-3">
              <div className="text-[12px] font-semibold">{primary?.title
                ?? (analystOnly ? tr('actors.signal.analystConfirmed') : tr('actors.signal.none'))}</div>
              <p className="mt-1 text-[11px] leading-relaxed text-[var(--muted)]">
                {primary?.detail ?? (analystOnly
                  ? tr('actors.signal.noAutomatic') : tr('actors.signal.noneDetail'))}
              </p>
            </div>
          </InspectorSection>
          <InspectorSection title={tr('actors.inspector.sources')}>
            <SourceRow icon={<Activity size={14} />} label={tr('actors.source.measured')}
              value={tr('actors.source.measuredValue', { n: signals.length })} />
            <SourceRow icon={<FileSearch size={14} />} label={tr('actors.source.automatic')}
              value={tr('actors.source.automaticValue', { n: detail.findings.length })} />
            <SourceRow icon={<ShieldCheck size={14} />} label={tr('actors.source.analyst')}
              value={detail.triage ? tr(`triage.${detail.triage}`) : tr('actors.source.open')} />
          </InspectorSection>
          <InspectorSection title={tr('actors.inspector.assessment')}>
            <Assessment detail={detail} tr={tr} />
          </InspectorSection>
        </>}

        {tab === 'evidence' && <>
          <InspectorSection title={tr('actors.inspector.triggers')} count={detail.alerts.length}>
            {detail.alerts.length ? detail.alerts.map((alert, index) => (
              <div key={`${alert.kind}-${index}`} className="rounded-lg border border-[var(--line-soft)] p-2.5">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={alert.severity} />
                  <span className="text-[12px] font-semibold">{tr('actors.source.measured')}</span>
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--muted)]">{alert.detail}</p>
                {alert.example && <button type="button" onClick={() => onTrace([alert.example])}
                  className="mono mt-2 block max-w-full cursor-pointer break-all text-left text-[11px] text-[var(--accent-text)] hover:underline">
                  {alert.example} →
                </button>}
              </div>
            )) : <p className="text-[12px] text-[var(--muted)]">{tr('actors.inspector.noTriggers')}</p>}
          </InspectorSection>
          <InspectorSection title={tr('actors.inspector.findings')} count={detail.findings.length}>
            {detail.findings.length ? detail.findings.map((finding) => (
              <div key={finding.id} className="rounded-lg border border-[var(--line-soft)] p-2.5">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <span className="min-w-0 truncate text-[12px] font-semibold">{finding.rule}</span>
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-[var(--muted)]">{finding.evidence}</p>
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
        </>}

        {tab === 'activity' && <>
          <InspectorSection title={tr('actors.inspector.paths')}>
            {detail.top_paths.map((path) => (
              <button key={path.uri} type="button" onClick={() => onTrace([path.uri])}
                className="flex min-w-0 cursor-pointer items-start gap-2 text-left text-[11px] hover:text-[var(--accent-text)]">
                <span className="mono min-w-0 flex-1 break-all">{path.uri}</span>
                <span className="shrink-0 tabular text-[var(--muted)]">
                  {formatCount(path.n)} · {tr('actors.path.ok', { n: formatCount(path.ok) })}
                </span>
              </button>
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
        </>}

        {tab === 'relations' && <>
          <p className="mb-3 text-[11px] leading-relaxed text-[var(--muted)]">
            {tr('actors.relations.explain')}
          </p>
          {detail.relations.length ? detail.relations.map((peer) => (
            <div key={peer.ip} className="mb-2 rounded-lg border border-[var(--line-soft)] p-2.5">
              <div className="flex flex-wrap items-center gap-1.5">
                <Link2 size={13} className="text-[var(--accent)]" />
                <span className="mono text-[12px] font-semibold">{peer.ip}</span>
                {peer.in_box && <Tag tone="accent">IOC</Tag>}
                {peer.triage && <TriageBadge state={peer.triage} label={tr(`triage.${peer.triage}`)} />}
              </div>
              <p className="mt-1.5 text-[11px] text-[var(--muted)]">
                {tr('actors.relations.requests', {
                  n: formatCount(peer.shared_requests), ok: formatCount(peer.successful),
                })}
              </p>
              <div className="mt-1.5 flex flex-col gap-1">
                {peer.shared_paths.slice(0, 3).map((path) => (
                  <span key={path} className="mono break-all text-[10px]">{path}</span>
                ))}
              </div>
              <Button className="mt-2" variant="ghost"
                onClick={() => onTrace(peer.shared_paths, [actor.ip, peer.ip])}>
                <Crosshair size={13} /> {tr('actors.relations.trace')}
              </Button>
            </div>
          )) : <EmptyState icon={<Link2 size={30} />} title={tr('actors.relations.empty')}
            sub={tr('actors.relations.emptySub')} />}
        </>}
      </div>
    </aside>
  )
}

function Assessment({ detail, tr }: { detail: ActorDetail; tr: Translate }) {
  return detail.triage ? (
    <div className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2.5">
      <div className="flex items-center gap-2">
        <ShieldCheck size={14} className="text-[var(--accent)]" />
        <TriageBadge state={detail.triage} label={tr(`triage.${detail.triage}`)} />
        {detail.triaged_at && <span className="ml-auto text-[10px] text-[var(--muted)]">{detail.triaged_at}</span>}
      </div>
      {detail.triage_note && <p className="mt-2 text-[12px] leading-relaxed">{detail.triage_note}</p>}
    </div>
  ) : <p className="text-[12px] text-[var(--muted)]">{tr('actors.inspector.noDecision')}</p>
}

function SourceRow({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-[var(--line-soft)] px-2.5 py-2 text-[11px]">
      <span className="text-[var(--accent)]">{icon}</span>
      <span className="font-semibold">{label}</span>
      <span className="ml-auto text-right text-[var(--muted)]">{value}</span>
    </div>
  )
}

function FilterGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">{title}</h3>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  )
}

function ActorCompareDialog({ slug, ips, open, threshold, tr, onTrace, onClose }: {
  slug: string
  ips: string[]
  open: boolean
  threshold?: number
  tr: Translate
  onTrace: () => void
  onClose: () => void
}) {
  const stableIps = [...ips].sort()
  const { data, isFetching, isError } = useQuery({
    queryKey: ['actor-comparison', slug, stableIps.join(',')],
    queryFn: () => post<ActorComparison>(`/api/cases/${slug}/actors/compare`, { ips: stableIps }),
    enabled: open && stableIps.length >= 2 && stableIps.length <= 5,
  })
  useEffect(() => {
    if (!open) return
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [open, onClose])
  if (!open) return null
  const zone = data?.actors[0]?.tz ?? 0
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/55 p-0 sm:items-center sm:p-5"
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
      <section role="dialog" aria-modal="true" aria-label={tr('actors.compare.title')}
        className="max-h-[94vh] w-full max-w-5xl overflow-y-auto rounded-t-2xl border border-[var(--line)] bg-[var(--bg)] shadow-2xl sm:rounded-2xl">
        <header className="sticky top-0 z-10 flex items-start gap-3 border-b border-[var(--line)] bg-[var(--bg)] p-4">
          <GitCompareArrows size={19} className="mt-0.5 shrink-0 text-[var(--accent)]" />
          <div className="min-w-0 flex-1">
            <h2 className="text-base font-bold">{tr('actors.compare.title')}</h2>
            <p className="mt-0.5 text-[12px] text-[var(--muted)]">
              {tr('actors.compare.sub', { n: stableIps.length })}
            </p>
          </div>
          <Button variant="ghost" title={tr('common.close')} onClick={onClose}><X size={17} /></Button>
        </header>

        <div className="p-4">
          {isFetching && <p className="text-[13px] text-[var(--muted)]">{tr('common.loading')}</p>}
          {isError && <EmptyState icon={<GitCompareArrows size={32} />}
            title={tr('actors.compare.error')} sub={tr('actors.compare.errorSub')} />}
          {data && <>
            <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-5">
              {data.actors.map((actor) => {
                const primary = actorSignals(actor, tr, threshold)[0]
                return (
                  <article key={actor.ip} className="min-w-0 rounded-xl border border-[var(--line)] bg-[var(--panel)] p-3">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <IpFlag ip={actor.ip} />
                      <span className="mono text-[12px] font-semibold">{actor.ip}</span>
                      {actor.triage && <TriageBadge state={actor.triage} label={tr(`triage.${actor.triage}`)} />}
                    </div>
                    <div className="mt-2 text-[11px] font-semibold">{primary?.title ?? tr('actors.signal.none')}</div>
                    <div className="mt-2 flex gap-3 text-[10px] text-[var(--muted)]">
                      <span>{formatCount(actor.requests)} req.</span>
                      <span>{formatCount(actor.err4 + actor.err5)} err.</span>
                    </div>
                  </article>
                )
              })}
            </div>

            <div className="mt-4 rounded-xl border border-[var(--line)] bg-[var(--panel)] p-3">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                {tr('actors.compare.time')}
              </div>
              <div className="mt-1 text-[13px] font-semibold">
                {data.time_overlap
                  ? `${formatLogTime(data.time_overlap.from_epoch, zone)} – ${formatLogTime(data.time_overlap.to_epoch, zone)}`
                  : tr('actors.compare.noTime')}
              </div>
              <p className="mt-1 text-[11px] text-[var(--muted)]">{tr('actors.compare.timeHelp')}</p>
            </div>

            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <ComparisonList title={tr('actors.compare.paths')} empty={tr('actors.compare.noPaths')}>
                {data.shared_paths.map((path) => (
                  <div key={path.uri} className="rounded-lg border border-[var(--line-soft)] p-2.5">
                    <div className="mono break-all text-[11px] font-semibold">{path.uri}</div>
                    <div className="mt-1 text-[10px] text-[var(--muted)]">
                      {tr('actors.compare.overlap', {
                        actors: path.actors, hits: formatCount(path.hits), ok: formatCount(path.ok),
                      })}
                    </div>
                  </div>
                ))}
              </ComparisonList>
              <ComparisonList title={tr('actors.compare.agents')} empty={tr('actors.compare.noAgents')}>
                {data.shared_agents.map((agent) => (
                  <div key={agent.agent} className="rounded-lg border border-[var(--line-soft)] p-2.5">
                    <div className="break-words text-[11px] font-semibold">{agent.agent}</div>
                    <div className="mt-1 text-[10px] text-[var(--muted)]">
                      {tr('actors.compare.overlap', {
                        actors: agent.actors, hits: formatCount(agent.hits), ok: formatCount(agent.ok),
                      })}
                    </div>
                  </div>
                ))}
              </ComparisonList>
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-[var(--line)] pt-4">
              <Button variant="primary" onClick={onTrace}><Crosshair size={14} /> {tr('actors.compare.trace')}</Button>
              <p className="text-[11px] text-[var(--muted)]">{tr('actors.compare.caution')}</p>
            </div>
          </>}
        </div>
      </section>
    </div>
  )
}

function ComparisonList({ title, empty, children }: {
  title: string; empty: string; children: ReactNode
}) {
  const hasChildren = Array.isArray(children) ? children.length > 0 : Boolean(children)
  return (
    <section>
      <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">{title}</h3>
      <div className="flex flex-col gap-2">
        {hasChildren ? children : <p className="text-[12px] text-[var(--muted)]">{empty}</p>}
      </div>
    </section>
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
