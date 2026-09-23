// AccessLogs.tsx -- a full-case, request-centred investigation workspace.
//
// Actors starts with an entity and TraceWindow answers "what did it do?".
// This page starts with every parsed access-log request and lets the analyst
// narrow the case by time, field, path shape and measured signal. Every
// operation remains a structured server query; no SQL or query-language text
// from the browser is ever executed.
import './accessLogs.css'
import { useEffect, useRef, useState, type CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Activity, Bookmark, ChevronLeft, ChevronRight, Clock3, Download,
  Filter, Minus, Pin, Plus, Radar, Save, Search, ShieldAlert, Trash2, X, MoreHorizontal, Maximize2,
} from 'lucide-react'
import {
  api, del, downloadUrl, post,
  type AccessClip, type AccessFacet, type AccessLogQuery, type AccessLogRow,
  type AccessOverview, type AccessPatternsResponse, type AccessRequestContext,
  type AccessSavedQuery, type AccessSearchResponse, type AccessSegmentsResponse,
  type CaseDetail,
} from '../api'
import type { Navigate } from '../App'
import { formatBytes, formatCount, formatLogTime, formatSpan } from '../format'
import { useT } from '../i18n'
import { IpFlag } from '../components/ui/IpFlag'
import { TraceWindow } from '../components/logview/TraceWindow'
import { Button, Card, CopyButton, EmptyState, Modal, SearchInput } from '../components/ui/ui'

type AccessTab = 'requests' | 'patterns' | 'segments'

const PAGE_SIZE = 200

const EMPTY_QUERY: AccessLogQuery = {
  search: '', from_epoch: null, to_epoch: null,
  clients: [], exclude_clients: [], paths: [], exclude_paths: [],
  agents: [], exclude_agents: [], source_ids: [], exclude_source_ids: [],
  status: '', method: '', min_size: null, max_size: null,
  signals_only: false, sort: 'time_desc',
}

function normaliseQuery(value?: Partial<AccessLogQuery>): AccessLogQuery {
  return { ...EMPTY_QUERY, ...(value ?? {}) }
}

function queryBody(query: AccessLogQuery, cursor = '') {
  return { ...query, cursor, limit: PAGE_SIZE }
}

function inputTime(epoch: number | null) {
  return epoch ? new Date(epoch * 1000).toISOString().slice(0, 16) : ''
}

function epochTime(value: string) {
  if (!value) return null
  const parsed = Date.parse(`${value}:00Z`)
  return Number.isFinite(parsed) ? Math.floor(parsed / 1000) : null
}

function signalLabel(kind: string, tr: ReturnType<typeof useT>) {
  const known = new Set([
    'sqli', 'traversal', 'upload_php', 'cms_dir_php', 'scanner_ua',
    'login_flood', 'login_success',
  ])
  return known.has(kind) ? tr(`logs.signal.${kind}`) : kind.replaceAll('_', ' ')
}

function SignalChips({ signals }: { signals: string[] }) {
  const tr = useT()
  if (!signals.length) return null
  return <div className="flex flex-wrap gap-1">
    {signals.map((signal) => (
      <span key={signal}
        className="rounded-md border border-[var(--sev-high)]/30 bg-[var(--danger-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--danger-text)]">
        {signalLabel(signal, tr)}
      </span>
    ))}
  </div>
}

export function AccessLogs({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const qc = useQueryClient()
  const initial = new URLSearchParams(location.search)
  const initialSearch = initial.get('search') ?? ''
  const initialRequest = Number(initial.get('request')) || null
  const [tab, setTab] = useState<AccessTab>('requests')
  const [query, setQuery] = useState<AccessLogQuery>({ ...EMPTY_QUERY, search: initialSearch })
  const [searchDraft, setSearchDraft] = useState(initialSearch)
  const [cursor, setCursor] = useState('')
  const [cursorHistory, setCursorHistory] = useState<string[]>([])
  const [selectedRequest, setSelectedRequest] = useState<number | null>(initialRequest)
  const mountedQuery = useRef(false)
  const [traceRow, setTraceRow] = useState<AccessLogRow | null>(null)
  const [saveOpen, setSaveOpen] = useState(false)
  const [saveName, setSaveName] = useState('')
  const [basketOpen, setBasketOpen] = useState(false)
  const [clipNote, setClipNote] = useState('')
  const [filtersOpen, setFiltersOpen] = useState(false)
  const [timeOpen, setTimeOpen] = useState(false)
  const [savedOpen, setSavedOpen] = useState(false)
  const workspaceRef = useRef<HTMLDivElement>(null)
  const [inspectorWidth, setInspectorWidth] = useState(() => {
    try { const width = Number(localStorage.getItem('shellhound.logs.inspectorWidth')); return width >= 320 && width <= 560 ? width : 380 } catch { return 380 }
  })
  const [workspaceWidth, setWorkspaceWidth] = useState(1200)
  const maxInspector = Math.max(320, Math.min(560, workspaceWidth - 568))
  const displayWidth = Math.min(inspectorWidth, maxInspector)
  const resizeInspector = (width: number) => {
    const next = Math.round(Math.max(320, Math.min(maxInspector, width)))
    setInspectorWidth(next)
    try { localStorage.setItem('shellhound.logs.inspectorWidth', String(next)) } catch { /* Storage may be unavailable. */ }
  }


  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const indexReady = caseInfo?.log_index?.fresh === true
  useEffect(() => {
    const node = workspaceRef.current
    if (!node || typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(entries => setWorkspaceWidth(entries[0].contentRect.width))
    observer.observe(node)
    return () => observer.disconnect()
  }, [indexReady, selectedRequest])

  useEffect(() => {
    const handle = window.setTimeout(() => {
      setQuery((current) => current.search === searchDraft
        ? current : { ...current, search: searchDraft })
    }, 280)
    return () => window.clearTimeout(handle)
  }, [searchDraft])

  useEffect(() => {
    setCursor('')
    setCursorHistory([])
    if (mountedQuery.current) setSelectedRequest(null)
    else mountedQuery.current = true
  }, [query])

  const searchQuery = useQuery({
    queryKey: ['access-search', slug, query, cursor],
    queryFn: () => post<AccessSearchResponse>(
      `/api/cases/${slug}/access/search`, queryBody(query, cursor)),
    enabled: indexReady,
  })
  const overviewQuery = useQuery({
    queryKey: ['access-overview', slug, query],
    queryFn: () => post<AccessOverview>(
      `/api/cases/${slug}/access/overview`, queryBody(query)),
    enabled: indexReady,
  })
  const patternsQuery = useQuery({
    queryKey: ['access-patterns', slug, query],
    queryFn: () => post<AccessPatternsResponse>(
      `/api/cases/${slug}/access/patterns`, queryBody(query)),
    enabled: indexReady && tab === 'patterns',
  })
  const segmentsQuery = useQuery({
    queryKey: ['access-segments', slug, query],
    queryFn: () => post<AccessSegmentsResponse>(
      `/api/cases/${slug}/access/segments`, queryBody(query)),
    enabled: indexReady && tab === 'segments',
  })
  const contextQuery = useQuery({
    queryKey: ['access-request', slug, selectedRequest],
    queryFn: () => api<AccessRequestContext>(
      `/api/cases/${slug}/access/request/${selectedRequest}`),
    enabled: indexReady && selectedRequest !== null,
  })
  const savedQuery = useQuery({
    queryKey: ['access-saved', slug],
    queryFn: () => api<AccessSavedQuery[]>(`/api/cases/${slug}/access/saved`),
  })
  const clipsQuery = useQuery({
    queryKey: ['access-clips', slug],
    queryFn: () => api<AccessClip[]>(`/api/cases/${slug}/access/clips`),
  })

  const saveMutation = useMutation({
    mutationFn: () => post<AccessSavedQuery>(`/api/cases/${slug}/access/saved`, {
      name: saveName.trim(), query,
    }),
    onSuccess: () => {
      setSaveName(''); setSaveOpen(false)
      qc.invalidateQueries({ queryKey: ['access-saved', slug] })
    },
  })
  const deleteSaved = useMutation({
    mutationFn: (id: number) => del(`/api/cases/${slug}/access/saved/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['access-saved', slug] }),
  })
  const clipMutation = useMutation({
    mutationFn: (requestId: number) => post<AccessClip>(
      `/api/cases/${slug}/access/clips`, { request_id: requestId, note: clipNote }),
    onSuccess: () => {
      setClipNote('')
      qc.invalidateQueries({ queryKey: ['access-clips', slug] })
    },
  })
  const deleteClip = useMutation({
    mutationFn: (id: number) => del(`/api/cases/${slug}/access/clips/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['access-clips', slug] }),
  })

  const setField = <K extends keyof AccessLogQuery>(key: K, value: AccessLogQuery[K]) =>
    setQuery((current) => ({ ...current, [key]: value }))

  const includeValue = (field: 'clients' | 'paths' | 'agents' | 'source_ids',
                        value: string | number) => {
    const opposite = ({ clients: 'exclude_clients', paths: 'exclude_paths',
      agents: 'exclude_agents', source_ids: 'exclude_source_ids' } as const)[field]
    setQuery((current) => ({
      ...current,
      [field]: [...new Set([...(current[field] as (string | number)[]), value])],
      [opposite]: (current[opposite] as (string | number)[]).filter((item) => item !== value),
    }))
  }
  const excludeValue = (field: 'clients' | 'paths' | 'agents' | 'source_ids',
                        value: string | number) => {
    const opposite = ({ clients: 'exclude_clients', paths: 'exclude_paths',
      agents: 'exclude_agents', source_ids: 'exclude_source_ids' } as const)[field]
    setQuery((current) => ({
      ...current,
      [field]: (current[field] as (string | number)[]).filter((item) => item !== value),
      [opposite]: [...new Set([...(current[opposite] as (string | number)[]), value])],
    }))
  }

  const removeValue = (field: keyof AccessLogQuery, value: string | number) =>
    setQuery((current) => ({
      ...current,
      [field]: (current[field] as (string | number)[]).filter((item) => item !== value),
    }))

  const loadSaved = (saved: AccessSavedQuery) => {
    const next = normaliseQuery(saved.query)
    setQuery(next)
    setSearchDraft(next.search)
  }

  const reset = () => {
    setQuery(EMPTY_QUERY)
    setSearchDraft('')
  }

  const data = searchQuery.data
  const overview = overviewQuery.data
  const activeCount = activeFilterCount(query)
  const exportFilters = encodeURIComponent(JSON.stringify(query))

  if (caseInfo && !caseInfo.log_index.fresh) {
    return <EmptyState icon={<Search size={36} />} title={tr('logs.index.title')}
      sub={caseInfo.log_index.reason || tr('logs.index.sub')} />
  }

  return <div className="access-workspace flex min-h-0 flex-1 flex-col gap-3">
    {(searchQuery.error || overviewQuery.error || saveMutation.error || clipMutation.error) && <p role="alert" className="text-[13px] text-[var(--danger-text)]">{String((searchQuery.error || overviewQuery.error || saveMutation.error || clipMutation.error)?.message)}</p>}
    <div className="shrink-0 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <div className="min-w-[220px] flex-1"><SearchInput className="w-full" value={searchDraft} onChange={setSearchDraft} placeholder={tr('logs.search')} /></div>
        <Button aria-expanded={timeOpen} onClick={() => setTimeOpen(!timeOpen)}><Clock3 size={14} />{query.from_epoch !== null || query.to_epoch !== null ? `${inputTime(query.from_epoch).replace('T', ' ') || '…'} – ${inputTime(query.to_epoch).replace('T', ' ') || '…'} UTC` : tr('logs.timeScope')}</Button>
        <Button aria-expanded={filtersOpen} onClick={() => setFiltersOpen(!filtersOpen)}><Filter size={14} />{tr('logs.workspace.filters')}</Button>
        <Button onClick={() => setBasketOpen(true)}><Pin size={14} />{tr('logs.basket')} ({clipsQuery.data?.length ?? 0})</Button>
        <details className="relative"><summary aria-label={tr('logs.workspace.actions')} className="cursor-pointer list-none rounded-lg border border-[var(--line)] p-2"><MoreHorizontal size={18} /></summary>
          <div className="absolute right-0 top-full z-20 mt-1 flex min-w-56 flex-col gap-1 rounded-lg border border-[var(--line)] bg-[var(--panel)] p-2 shadow-xl" onClick={event => { const details = event.currentTarget.parentElement as HTMLDetailsElement; details.open = false }}>
            <Button variant="ghost" onClick={() => setSaveOpen(true)}><Save size={14} />{tr('logs.save')}</Button>
            <Button variant="ghost" onClick={() => setSavedOpen(true)}><Bookmark size={14} />{tr('logs.saved')}</Button>
            <a href={downloadUrl(`/api/cases/${slug}/access/export?filters=${exportFilters}`)} className="inline-flex items-center gap-2 rounded px-3 py-2 text-[13px]"><Download size={14} />{tr('logs.export')}</a>
          </div>
        </details>
      </div>
      {timeOpen && <div className="flex flex-wrap gap-3 rounded-lg border border-[var(--line)] bg-[var(--panel)] p-3">
        {(['from_epoch', 'to_epoch'] as const).map(key => <label key={key} className="text-[12px]">{tr(key === 'from_epoch' ? 'logs.fromUtc' : 'logs.toUtc')}<input type="datetime-local" value={inputTime(query[key])} onChange={event => setField(key, epochTime(event.target.value))} className="ml-2 rounded border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1" /></label>)}
      </div>}
      {filtersOpen && <section aria-label={tr('logs.workspace.filters')} className="space-y-3 rounded-lg border border-[var(--line)] bg-[var(--panel)] p-3">
        <button type="button" aria-pressed={query.signals_only} onClick={() => setField('signals_only', !query.signals_only)} className="inline-flex items-center gap-2 rounded border border-[var(--line)] px-3 py-2 text-[13px]"><ShieldAlert size={14} />{tr('logs.signalsOnly')}{query.signals_only && ' ✓'}</button>
        <FacetPanel overview={overview} query={query} onInclude={includeValue} onExclude={excludeValue} onStatus={status => setField('status', status)} onMethod={method => setField('method', method)} />
      </section>}
      <div className="flex flex-wrap items-center gap-2">
        <ActiveFilters query={query} overview={overview} onRemove={removeValue} onStatus={() => setField('status', '')} onMethod={() => setField('method', '')} onTime={() => setQuery(current => ({ ...current, from_epoch: null, to_epoch: null }))} />
        {query.signals_only && <Button variant="ghost" onClick={() => setField('signals_only', false)}>{tr('logs.signalsOnly')} ×</Button>}
        {query.search && <Button variant="ghost" onClick={() => { setSearchDraft(''); setField('search', '') }}>{query.search} ×</Button>}
        {activeCount > 0 && <Button variant="ghost" onClick={reset}>{tr('logs.workspace.clear')}</Button>}
      </div>
    </div>
    <Modal open={saveOpen} onClose={() => setSaveOpen(false)} title={tr('logs.save')}><div className="flex gap-2"><input value={saveName} onChange={event => setSaveName(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && saveName.trim() && !saveMutation.isPending) saveMutation.mutate() }} placeholder={tr('logs.saveName')} className="min-w-0 flex-1 rounded border border-[var(--line)] bg-[var(--panel-2)] p-2" /><Button disabled={!saveName.trim() || saveMutation.isPending} onClick={() => saveMutation.mutate()}>{tr('logs.saveCta')}</Button></div></Modal>
    <Modal open={savedOpen} onClose={() => setSavedOpen(false)} title={tr('logs.saved')}><SavedSearches rows={savedQuery.data ?? []} onLoad={row => { loadSaved(row); setSavedOpen(false) }} onDelete={id => deleteSaved.mutate(id)} />{!savedQuery.data?.length && <p>{tr('logs.workspace.noSaved')}</p>}</Modal>

    <div ref={workspaceRef} className={clsx('access-split', selectedRequest !== null && 'has-inspector')} style={{ '--inspector-width': `${displayWidth}px` } as CSSProperties}>
      <div className="access-results">
        <div className="flex flex-wrap items-center justify-between gap-2">
        <nav className="mb-2 inline-flex rounded-xl border border-[var(--line)] bg-[var(--panel)] p-1"
          aria-label={tr('logs.views')}>
          {(['requests', 'patterns', 'segments'] as AccessTab[]).map((value) => (
            <button key={value} type="button" onClick={() => setTab(value)}
              aria-pressed={tab === value}
              className={clsx('cursor-pointer rounded-lg px-3 py-1.5 text-[12px] font-semibold',
                tab === value
                  ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                  : 'text-[var(--muted)] hover:text-[var(--fg)]')}>
              {tr(`logs.tab.${value}`)}
            </button>
          ))}
        </nav>
        <select value={query.sort} onChange={event => setField('sort', event.target.value as AccessLogQuery['sort'])} aria-label={tr('common.sort')} className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1.5 text-[13px]"><option value="time_desc">{tr('logs.sort.newest')}</option><option value="time">{tr('logs.sort.oldest')}</option></select>
        </div>
        {tab === 'requests' && <RequestTable data={data} loading={searchQuery.isFetching}
          selected={selectedRequest} onSelect={setSelectedRequest} />}
        {tab === 'patterns' && <PatternTable result={patternsQuery.data}
          loading={patternsQuery.isFetching} onInspect={(path) => {
            setField('search', path); setSearchDraft(path); setTab('requests')
          }} />}
        {tab === 'segments' && <SegmentList result={segmentsQuery.data}
          loading={segmentsQuery.isFetching} onInspect={(from, to) => {
            setQuery((current) => ({ ...current, from_epoch: from, to_epoch: to }))
            setTab('requests')
          }} />}

        {tab === 'requests' && data && (cursorHistory.length > 0 || data.next_cursor) && (
          <div className="mt-2 flex items-center justify-center gap-2 text-[12px] text-[var(--muted)]">
            <Button variant="ghost" disabled={!cursorHistory.length} onClick={() => {
              const previous = [...cursorHistory]
              setCursor(previous.pop() ?? '')
              setCursorHistory(previous)
            }}><ChevronLeft size={14} /> {tr('logs.previous')}</Button>
            {tr('logs.page', { n: cursorHistory.length + 1 })}
            <Button variant="ghost" disabled={!data.next_cursor} onClick={() => {
              if (!data.next_cursor) return
              setCursorHistory((history) => [...history, cursor])
              setCursor(data.next_cursor ?? '')
            }}>{tr('logs.next')} <ChevronRight size={14} /></Button>
          </div>
        )}
      </div>

      {selectedRequest !== null && <div role="separator" tabIndex={0} aria-label={tr('logs.workspace.resize')} aria-orientation="vertical" aria-valuemin={320} aria-valuemax={maxInspector} aria-valuenow={displayWidth} className="access-divider"
        onKeyDown={event => { if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) { event.preventDefault(); resizeInspector(event.key === 'Home' ? 320 : event.key === 'End' ? maxInspector : displayWidth + (event.key === 'ArrowLeft' ? 20 : -20)) } }}
        onPointerDown={event => { event.currentTarget.setPointerCapture(event.pointerId) }}
        onPointerMove={event => { if (event.currentTarget.hasPointerCapture(event.pointerId)) resizeInspector((workspaceRef.current?.getBoundingClientRect().right ?? 0) - event.clientX) }} />}
      <RequestInspector context={contextQuery.data} loading={contextQuery.isFetching}
        visible={selectedRequest !== null} onClose={() => setSelectedRequest(null)}
        onSelect={setSelectedRequest}
        onFilterClient={(value) => includeValue('clients', value)}
        onFilterPath={(value) => includeValue('paths', value)}
        onFilterAgent={(value) => includeValue('agents', value)}
        onTrace={(row) => setTraceRow(row)}
        onCreatePattern={(id) => gotoView('hunt', { request: String(id) })}
        clipNote={clipNote} setClipNote={setClipNote}
        onClip={(id) => clipMutation.mutate(id)} clipping={clipMutation.isPending} />
    </div>

    <details className="rounded-xl border border-[var(--line)] bg-[var(--panel)]">
      <summary className="cursor-pointer px-3 py-2.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)] hover:text-[var(--fg)]">
        {tr('logs.overview.toggle')}
      </summary>
      <div className="space-y-3 border-t border-[var(--line)] p-3">
        <SummaryStrip data={data} />
        <AccessHistogram overview={overview} loading={overviewQuery.isFetching}
          onRange={(from, to) => setQuery((current) => ({
            ...current, from_epoch: from, to_epoch: to,
          }))} />
      </div>
    </details>

    <BasketModal slug={slug} open={basketOpen} onClose={() => setBasketOpen(false)}
      clips={clipsQuery.data ?? []} onDelete={(id) => deleteClip.mutate(id)} />
    <TraceWindow slug={slug} ips={traceRow ? [traceRow.client] : null}
      marks={traceRow ? { exact: [traceRow.uri], reason: tr('logs.traceReason') } : undefined}
      onClose={() => setTraceRow(null)} />
  </div>
}

function activeFilterCount(query: AccessLogQuery) {
  return Number(Boolean(query.search)) + Number(query.from_epoch !== null)
    + Number(query.to_epoch !== null) + Number(Boolean(query.status))
    + Number(Boolean(query.method)) + Number(query.signals_only)
    + query.clients.length + query.exclude_clients.length
    + query.paths.length + query.exclude_paths.length
    + query.agents.length + query.exclude_agents.length
    + query.source_ids.length + query.exclude_source_ids.length
}

function SummaryStrip({ data }: { data?: AccessSearchResponse }) {
  const tr = useT()
  const rows = [
    [tr('logs.summary.requests'), data?.total ?? 0, 'text-[var(--fg)]'],
    [tr('logs.summary.ok'), data?.summary.ok ?? 0, 'text-[var(--ok)]'],
    [tr('logs.summary.4xx'), data?.summary.client_errors ?? 0, 'text-[var(--sev-medium)]'],
    [tr('logs.summary.5xx'), data?.summary.server_errors ?? 0, 'text-[var(--sev-high)]'],
  ] as const
  return <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
    {rows.map(([label, value, tone]) => <Card key={label} className="px-3 py-2">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">{label}</div>
      <div className={clsx('mt-0.5 text-lg font-bold tabular', tone)}>{formatCount(value)}</div>
    </Card>)}
  </div>
}

function AccessHistogram({ overview, loading, onRange }: {
  overview?: AccessOverview
  loading: boolean
  onRange: (from: number, to: number) => void
}) {
  const tr = useT()
  const timeline = overview?.timeline ?? []
  const max = Math.max(1, ...timeline.map((point) => point.requests))
  return <Card className="p-3">
    <div className="mb-2 flex items-center justify-between gap-3">
      <div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
          {tr('logs.timeline')}
        </div>
        <div className="text-[11px] text-[var(--muted)]">{tr('logs.timelineHint')}</div>
      </div>
      {loading && <span className="text-[11px] text-[var(--muted)]">{tr('common.loading')}</span>}
    </div>
    {timeline.length ? <div className="flex h-24 items-end gap-px" role="img" aria-label={tr('logs.timeline')}>
      {timeline.map((point) => {
        const height = Math.max(3, (point.requests / max) * 100)
        const errorHeight = point.requests ? (point.errors / point.requests) * height : 0
        return <button key={point.start_epoch} type="button"
          onClick={() => onRange(point.start_epoch, point.end_epoch)}
          title={`${formatLogTime(point.start_epoch, 0, { withZone: true, mode: 'utc' })} · ${formatCount(point.requests)} ${tr('logs.requests')}`}
          className="group relative min-w-[2px] flex-1 cursor-pointer rounded-t-sm bg-[var(--accent)]/35 hover:bg-[var(--accent)]/65"
          style={{ height: `${height}%` }}>
          <span className="absolute inset-x-0 bottom-0 bg-[var(--sev-high)]/75"
            style={{ height: `${Math.max(0, errorHeight)}%` }} />
          {point.signals > 0 && <span className="absolute -top-1 left-1/2 h-1.5 w-1.5 -translate-x-1/2 rounded-full bg-[var(--sev-high)]" />}
        </button>
      })}
    </div> : loading ? (
      <div className="flex h-24 items-end gap-1" role="status" aria-label={tr('common.loading')}>
        {[42, 68, 36, 82, 54, 73, 48, 64, 31, 58, 76, 45].map((height, index) => (
          <span key={index} className="flex-1 rounded-t-sm bg-[var(--panel-raised)] animate-pulse-soft"
            style={{ height: `${height}%` }} />
        ))}
      </div>
    ) : <div className="flex h-24 items-center justify-center text-[12px] text-[var(--muted)]">
      {tr('logs.noTimeline')}
    </div>}
  </Card>
}

function ActiveFilters({ query, overview, onRemove, onStatus, onMethod, onTime }: {
  query: AccessLogQuery
  overview?: AccessOverview
  onRemove: (field: keyof AccessLogQuery, value: string | number) => void
  onStatus: () => void
  onMethod: () => void
  onTime: () => void
}) {
  const tr = useT()
  const sourceLabels = new Map((overview?.facets.sources ?? [])
    .map((item) => [Number(item.value), item.label ?? String(item.value)]))
  const chips: { field: keyof AccessLogQuery; value: string | number; label: string; negative?: boolean }[] = []
  const add = (field: keyof AccessLogQuery, values: (string | number)[], negative = false) =>
    values.forEach((value) => chips.push({ field, value, negative,
      label: field.includes('source') ? (sourceLabels.get(Number(value)) ?? `#${value}`) : String(value) }))
  add('clients', query.clients); add('exclude_clients', query.exclude_clients, true)
  add('paths', query.paths); add('exclude_paths', query.exclude_paths, true)
  add('agents', query.agents); add('exclude_agents', query.exclude_agents, true)
  add('source_ids', query.source_ids); add('exclude_source_ids', query.exclude_source_ids, true)
  if (!chips.length && !query.status && !query.method && query.from_epoch === null && query.to_epoch === null) return null
  return <div className="mt-2 flex flex-wrap items-center gap-1.5 border-t border-[var(--line-soft)] pt-2">
    <Filter size={12} className="text-[var(--muted)]" />
    {chips.map((chip) => <button key={`${chip.field}-${chip.value}`} type="button"
      onClick={() => onRemove(chip.field, chip.value)}
      className={clsx('max-w-[260px] truncate rounded-md border px-2 py-1 text-[10px] font-medium',
        chip.negative
          ? 'border-[var(--sev-medium)]/40 bg-[var(--panel-2)] text-[var(--sev-medium)]'
          : 'border-[var(--accent)]/35 bg-[var(--accent-soft)] text-[var(--accent-text)]')}>
      {chip.negative ? '− ' : '+ '}{chip.label} ×
    </button>)}
    {query.status && <button type="button" onClick={onStatus}
      className="rounded-md bg-[var(--panel-2)] px-2 py-1 text-[10px]">Status {query.status} ×</button>}
    {query.method && <button type="button" onClick={onMethod}
      className="rounded-md bg-[var(--panel-2)] px-2 py-1 text-[10px]">{query.method} ×</button>}
    {(query.from_epoch !== null || query.to_epoch !== null) && <button type="button" onClick={onTime}
      className="rounded-md bg-[var(--panel-2)] px-2 py-1 text-[10px]">{tr('logs.timeScope')} ×</button>}
  </div>
}

function SavedSearches({ rows, onLoad, onDelete }: {
  rows: AccessSavedQuery[]
  onLoad: (row: AccessSavedQuery) => void
  onDelete: (id: number) => void
}) {
  const tr = useT()
  if (!rows.length) return null
  return <Card className="p-2.5">
    <div className="mb-1.5 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
      <Bookmark size={12} /> {tr('logs.saved')}
    </div>
    <div className="space-y-1">
      {rows.slice(0, 8).map((row) => <div key={row.id} className="flex items-center gap-1 rounded-lg hover:bg-[var(--panel-2)]">
        <button type="button" onClick={() => onLoad(row)}
          className="min-w-0 flex-1 cursor-pointer truncate px-2 py-1.5 text-left text-[11px] font-medium">
          {row.name}
        </button>
        <button type="button" onClick={() => onDelete(row.id)} title={tr('common.remove')}
          className="cursor-pointer rounded p-1 text-[var(--muted)] hover:text-[var(--danger-text)]">
          <Trash2 size={11} />
        </button>
      </div>)}
    </div>
  </Card>
}

type FacetField = 'clients' | 'paths' | 'agents' | 'source_ids'

function FacetPanel({ overview, query, onInclude, onExclude, onStatus, onMethod }: {
  overview?: AccessOverview
  query: AccessLogQuery
  onInclude: (field: FacetField, value: string | number) => void
  onExclude: (field: FacetField, value: string | number) => void
  onStatus: (value: string) => void
  onMethod: (value: string) => void
}) {
  const tr = useT()
  return <Card className="p-2.5">
    <details open>
      <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[12px] font-semibold text-[var(--muted)]">
        <Filter size={12} /> {tr('logs.facets')}
      </summary>
      <div className="mt-3 border-t border-[var(--line-soft)] pt-3">
        <FacetGroup title={tr('logs.facets.status')} rows={overview?.facets.status ?? []}
          active={(value) => query.status === String(value)}
          onInclude={(value) => onStatus(String(value))} />
        <FacetGroup title={tr('logs.facets.method')} rows={overview?.facets.methods ?? []}
          active={(value) => query.method === String(value)}
          onInclude={(value) => onMethod(String(value))} />
        <FacetGroup title={tr('logs.facets.clients')} rows={overview?.facets.clients ?? []}
          active={(value) => query.clients.includes(String(value))}
          onInclude={(value) => onInclude('clients', String(value))}
          onExclude={(value) => onExclude('clients', String(value))} />
        <FacetGroup title={tr('logs.facets.paths')} rows={overview?.facets.paths ?? []}
          active={(value) => query.paths.includes(String(value))}
          onInclude={(value) => onInclude('paths', String(value))}
          onExclude={(value) => onExclude('paths', String(value))} />
        <FacetGroup title={tr('logs.facets.sources')} rows={overview?.facets.sources ?? []}
          active={(value) => query.source_ids.includes(Number(value))}
          onInclude={(value) => onInclude('source_ids', Number(value))}
          onExclude={(value) => onExclude('source_ids', Number(value))} />
        <FacetGroup title={tr('logs.facets.agents')} rows={overview?.facets.agents ?? []}
          active={(value) => query.agents.includes(String(value))}
          onInclude={(value) => onInclude('agents', String(value))}
          onExclude={(value) => onExclude('agents', String(value))} />
      </div>
    </details>
  </Card>
}

function FacetGroup({ title, rows, active, onInclude, onExclude }: {
  title: string
  rows: AccessFacet[]
  active: (value: string | number) => boolean
  onInclude: (value: string | number) => void
  onExclude?: (value: string | number) => void
}) {
  const tr = useT()
  if (!rows.length) return null
  return <section className="mb-3 last:mb-0">
    <h3 className="mb-1 px-1 text-[10px] font-semibold text-[var(--muted)]">{title}</h3>
    <div className="space-y-0.5">
      {rows.map((row) => <div key={String(row.value)}
        className={clsx('group flex min-w-0 items-center gap-1 rounded-md px-1 py-0.5',
          active(row.value) && 'bg-[var(--accent-soft)]')}>
        <button type="button" onClick={() => onInclude(row.value)}
          title={row.label ?? String(row.value)}
          className="min-w-0 flex-1 cursor-pointer truncate py-1 text-left text-[10.5px]">
          {row.label ?? String(row.value)}
        </button>
        <span className="tabular text-[9.5px] text-[var(--muted)]">{formatCount(row.count)}</span>
        <button type="button" onClick={() => onInclude(row.value)} title={tr('logs.include')}
          className="hidden cursor-pointer rounded p-0.5 text-[var(--accent-text)] group-hover:block">
          <Plus size={10} />
        </button>
        {onExclude && <button type="button" onClick={() => onExclude(row.value)} title={tr('logs.exclude')}
          className="hidden cursor-pointer rounded p-0.5 text-[var(--sev-medium)] group-hover:block">
          <Minus size={10} />
        </button>}
      </div>)}
    </div>
  </section>
}

function RequestTable({ data, loading, selected, onSelect }: {
  data?: AccessSearchResponse
  loading: boolean
  selected: number | null
  onSelect: (id: number) => void
}) {
  const tr = useT()
  if (!data && loading) return <LoadingBlock />
  return <Card className="access-table-card min-w-0 overflow-hidden">
    <div className="flex items-center justify-between border-b border-[var(--line)] px-3 py-2 text-[11px] text-[var(--muted)]">
      <span>{formatCount(data?.total ?? 0)} {tr('logs.requests')}</span>
      {loading && <span>{tr('common.loading')}</span>}
    </div>
    <div className="access-table-scroll">
      <table className="w-full border-collapse text-[13px]">
        <thead className="sticky top-0 z-10 bg-[var(--panel-2)]"><tr className="border-b border-[var(--line)] text-left text-[12px] text-[var(--muted)]">
          <th className="px-2 py-1.5">{tr('table.time')}</th>
          <th className="px-2 py-1.5">{tr('logs.table.client')}</th>
          <th className="px-2 py-1.5">{tr('table.method')}</th>
          <th className="px-2 py-1.5">URI</th>
          <th className="px-2 py-1.5 text-right">Status</th>
          <th className="px-2 py-1.5 text-right">{tr('logs.table.size')}</th>
        </tr></thead>
        <tbody className="mono">
          {(data?.rows ?? []).map((row) => <tr key={row.request_id}
            tabIndex={0} role="button" onClick={() => onSelect(row.request_id)}
            onKeyDown={(event) => { if (event.key === 'Enter') onSelect(row.request_id) }}
            className={clsx('cursor-pointer border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]',
              selected === row.request_id && 'bg-[var(--accent-soft)]',
              row.signals.length && 'shadow-[inset_3px_0_0_var(--sev-high)]')}>
            <td className="whitespace-nowrap px-2 py-1.5 text-[var(--muted)]">{formatLogTime(row.epoch, row.tz)}</td>
            <td className="whitespace-nowrap px-2 py-1.5"><span className="inline-flex items-center gap-1.5"><IpFlag ip={row.client} />{row.client}</span></td>
            <td className="px-2 py-1.5">{row.method}</td>
            <td className="w-full min-w-40 max-w-0 truncate px-2 py-2" title={row.uri}>
              <span className={row.signals.length ? 'font-semibold text-[var(--danger-text)]' : ''}>{row.uri}</span>
            </td>
            <td className={clsx('px-2 py-1.5 text-right tabular', statusTone(row.status))}>{row.status}</td>
            <td className="whitespace-nowrap px-2 py-1.5 text-right text-[var(--muted)]">{row.size === null ? '—' : formatBytes(row.size)}</td>
          </tr>)}
        </tbody>
      </table>
    </div>
    {data && !data.rows.length && <div className="px-4 py-12 text-center text-[12px] text-[var(--muted)]">{tr('logs.noRequests')}</div>}
  </Card>
}

function PatternTable({ result, loading, onInspect }: {
  result?: AccessPatternsResponse
  loading: boolean
  onInspect: (pattern: string) => void
}) {
  const tr = useT()
  if (!result && loading) return <LoadingBlock />
  return <Card className="overflow-hidden">
    <div className="border-b border-[var(--line)] px-3 py-2">
      <div className="text-[12px] font-semibold">{tr('logs.patterns.title')}</div>
      <div className="text-[10.5px] text-[var(--muted)]">{tr('logs.patterns.sub')}</div>
      {result?.truncated && <div className="mt-1 text-[10px] text-[var(--warning-text)]">{tr('logs.patterns.truncated')}</div>}
    </div>
    <div className="divide-y divide-[var(--line-soft)]">
      {(result?.patterns ?? []).map((pattern) => <button key={pattern.pattern} type="button"
        onClick={() => onInspect(pattern.examples[0] ?? pattern.pattern)}
        className="grid w-full cursor-pointer gap-2 px-3 py-2.5 text-left hover:bg-[var(--panel-2)] sm:grid-cols-[minmax(0,1fr)_auto]">
        <div className="min-w-0">
          <div className="mono truncate text-[12px] font-semibold" title={pattern.pattern}>{pattern.pattern}</div>
          <div className="mt-1 flex flex-wrap gap-1.5 text-[10px] text-[var(--muted)]">
            {pattern.examples.slice(0, 2).map((example) => <span key={example} className="max-w-[360px] truncate rounded bg-[var(--panel-2)] px-1.5 py-0.5">{example}</span>)}
          </div>
          <div className="mt-1"><SignalChips signals={pattern.signals} /></div>
        </div>
        <div className="flex items-center gap-3 text-right text-[10px] text-[var(--muted)]">
          <span><b className="block text-[13px] text-[var(--fg)]">{formatCount(pattern.requests)}</b>{tr('logs.requests')}</span>
          <span><b className="block text-[13px] text-[var(--fg)]">{formatCount(pattern.clients)}</b>{tr('logs.clients')}</span>
          <span><b className="block text-[13px] text-[var(--ok)]">{formatCount(pattern.ok)}</b>2xx</span>
          <span><b className="block text-[13px] text-[var(--sev-medium)]">{formatCount(pattern.errors)}</b>4xx/5xx</span>
        </div>
      </button>)}
    </div>
    {result && !result.patterns.length && <div className="px-4 py-12 text-center text-[12px] text-[var(--muted)]">{tr('logs.patterns.empty')}</div>}
  </Card>
}

function SegmentList({ result, loading, onInspect }: {
  result?: AccessSegmentsResponse
  loading: boolean
  onInspect: (from: number, to: number) => void
}) {
  const tr = useT()
  if (!result && loading) return <LoadingBlock />
  if (result?.requires_client) return <EmptyState icon={<Activity size={34} />}
    title={tr('logs.segments.selectClient')} sub={tr('logs.segments.selectClientSub')} />
  return <div className="space-y-2">
    <Card className="px-3 py-2 text-[11px] text-[var(--muted)]">{tr('logs.segments.disclaimer')}</Card>
    {result?.truncated && <div className="text-[10px] text-[var(--warning-text)]">{tr('logs.segments.truncated')}</div>}
    {(result?.segments ?? []).map((segment, index) => <button key={`${segment.client}-${segment.first_epoch}-${index}`}
      type="button" onClick={() => onInspect(segment.first_epoch, segment.last_epoch)}
      className="grid w-full cursor-pointer gap-3 rounded-xl border border-[var(--line)] bg-[var(--panel)] p-3 text-left hover:border-[var(--accent)]/50 sm:grid-cols-[190px_minmax(0,1fr)_auto]">
      <div>
        <div className="inline-flex items-center gap-1.5 text-[12px] font-semibold"><IpFlag ip={segment.client} />{segment.client}</div>
        <div className="mt-1 text-[10px] text-[var(--muted)]">{formatLogTime(segment.first_epoch, segment.tz)}<br />→ {formatLogTime(segment.last_epoch, segment.tz)}</div>
      </div>
      <div className="min-w-0">
        <div className="flex flex-wrap gap-1">
          {segment.top_paths.map((path) => <span key={String(path.value)} className="mono max-w-[320px] truncate rounded bg-[var(--panel-2)] px-1.5 py-0.5 text-[10px]">{path.value} ×{formatCount(path.count)}</span>)}
        </div>
        <div className="mt-1"><SignalChips signals={segment.signals} /></div>
      </div>
      <div className="flex items-center gap-3 text-right text-[10px] text-[var(--muted)]">
        <span><b className="block text-[13px] text-[var(--fg)]">{formatCount(segment.requests)}</b>{tr('logs.requests')}</span>
        <span><b className="block text-[13px] text-[var(--sev-medium)]">{formatCount(segment.errors)}</b>{tr('logs.errors')}</span>
        <span><b className="block text-[13px] text-[var(--fg)]">{formatSpan(segment.first_epoch, segment.last_epoch)}</b>{tr('logs.duration')}</span>
      </div>
    </button>)}
  </div>
}

function RequestInspector({ context, loading, visible, onClose, onSelect,
  onFilterClient, onFilterPath, onFilterAgent, onTrace,
  onCreatePattern,
  clipNote, setClipNote, onClip, clipping }: {
  context?: AccessRequestContext
  loading: boolean
  visible: boolean
  onClose: () => void
  onSelect: (id: number) => void
  onFilterClient: (value: string) => void
  onFilterPath: (value: string) => void
  onFilterAgent: (value: string) => void
  onTrace: (row: AccessLogRow) => void
  onCreatePattern: (id: number) => void
  clipNote: string
  setClipNote: (value: string) => void
  onClip: (id: number) => void
  clipping: boolean
}) {
  const tr = useT()
  const [rawOpen, setRawOpen] = useState(false)
  const [desktop, setDesktop] = useState(() => window.matchMedia('(min-width: 1280px)').matches)
  useEffect(() => {
    const media = window.matchMedia('(min-width: 1280px)')
    const update = () => setDesktop(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])
  useEffect(() => { setRawOpen(false) }, [context?.request.request_id, visible])
  if (!visible) return null
  const contents = <div className="space-y-4 text-[13px]">
    {loading && !context ? <LoadingBlock /> : context ? <>
      <section className="space-y-2">
        <div className="mono break-all font-semibold">{context.request.method} {context.request.uri}</div>
        <div className="flex flex-wrap items-center gap-2"><span className={clsx('rounded px-2 py-1 font-semibold', statusBg(context.request.status))}>{context.request.status}</span><span className="mono inline-flex items-center gap-2"><IpFlag ip={context.request.client} />{context.request.client}<CopyButton value={context.request.client} label={tr('logs.workspace.copyIp')} /></span></div>
        <p className="text-[var(--muted)]">{formatLogTime(context.request.epoch, context.request.tz, { withZone: true })} · {context.request.size === null ? '—' : formatBytes(context.request.size)}</p>
      </section>
      <section className="space-y-3 border-t border-[var(--line)] pt-3">
        <div><div className="mb-1 flex items-center justify-between gap-2"><h3 className="font-semibold">{tr('logs.workspace.userAgent')}</h3>{context.request.agent && context.request.agent !== '-' && <CopyButton value={context.request.agent} label={tr('logs.workspace.copyAgent')} />}</div><p className="whitespace-pre-wrap break-all">{context.request.agent && context.request.agent !== '-' ? context.request.agent : tr('logs.workspace.notRecorded')}</p></div>
        <div><h3 className="mb-1 font-semibold">{tr('logs.workspace.referrer')}</h3><p className="break-all text-[var(--muted)]">{context.request.referrer && context.request.referrer !== '-' ? context.request.referrer : tr('logs.workspace.notRecorded')}</p></div>
      </section>
      <section className="border-t border-[var(--line)] pt-3">
        <div className="mb-2 flex items-center gap-2"><h3 className="mr-auto font-semibold">{tr('logs.inspector.raw')}</h3>{context.raw_line && <><CopyButton value={context.raw_line} label={tr('logs.workspace.copyRaw')} /><Button variant="ghost" onClick={() => setRawOpen(true)}><Maximize2 size={13} />{tr('logs.workspace.expand')}</Button></>}</div>
        <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2 text-[12px] leading-relaxed">{context.raw_line || tr('logs.inspector.rawMissing')}</pre>
        {context.raw_truncated && <p className="mt-1 text-[12px] text-[var(--warning-text)]">{tr('logs.inspector.rawTruncated')}</p>}
      </section>
      <ContextRows before={context.before} selected={context.request} after={context.after} onSelect={onSelect} />
      <section className="space-y-2 border-t border-[var(--line)] pt-3">
        <div className="flex flex-wrap gap-1.5"><Button variant="ghost" onClick={() => onFilterClient(context.request.client)}><Plus size={12} />IP</Button><Button variant="ghost" onClick={() => onFilterPath(context.request.uri)}><Plus size={12} />URI</Button>{context.request.agent && <Button variant="ghost" onClick={() => onFilterAgent(context.request.agent)}><Plus size={12} />{tr('logs.workspace.userAgent')}</Button>}<Button variant="special" onClick={() => onTrace(context.request)}><Activity size={12} />Trace</Button></div>
        <textarea aria-label={tr('logs.pin.note')} value={clipNote} onChange={event => setClipNote(event.target.value)} placeholder={tr('logs.pin.note')} rows={2} className="w-full resize-none rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2 text-[13px]" />
        <div className="flex flex-wrap gap-2"><Button variant="primary" disabled={clipping} onClick={() => onClip(context.request.request_id)}><Pin size={13} />{tr('logs.pin.cta')}</Button><Button onClick={() => onCreatePattern(context.request.request_id)}><Radar size={13} />{tr('logs.inspector.createPattern')}</Button></div>
      </section>
    </> : <p role="status">{tr('logs.workspace.unavailable')}</p>}
  </div>
  return <>
    {desktop ? <aside className="access-inspector rounded-lg border border-[var(--line)] bg-[var(--panel)] p-3" aria-label={tr('logs.inspector.title')}><div className="mb-3 flex items-center justify-between gap-2 border-b border-[var(--line)] pb-2"><h2 className="font-semibold">{tr('logs.inspector.title')}</h2><Button variant="ghost" onClick={onClose} aria-label={tr('common.close')}><X size={16} /></Button></div>{contents}</aside> : <Modal open onClose={onClose} title={tr('logs.inspector.title')}>{contents}</Modal>}
    <Modal open={rawOpen} onClose={() => setRawOpen(false)} title={tr('logs.inspector.raw')} layer={1}><div className="space-y-3"><CopyButton value={context?.raw_line || ''} label={tr('logs.workspace.copyRaw')} /><pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap break-all rounded bg-[var(--panel-2)] p-3 text-[13px] leading-relaxed">{context?.raw_line}</pre>{context?.raw_truncated && <p>{tr('logs.inspector.rawTruncated')}</p>}</div></Modal>
  </>
}

function ContextRows({ before, selected, after, onSelect }: {
  before: AccessLogRow[]
  selected: AccessLogRow
  after: AccessLogRow[]
  onSelect: (id: number) => void
}) {
  const tr = useT()
  const rows = [...before.slice(-6), selected, ...after.slice(0, 6)]
  return <section className="mt-3">
    <h3 className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">{tr('logs.context')}</h3>
    <div className="max-h-52 overflow-y-auto rounded-lg border border-[var(--line)]">
      {rows.map((row) => <button key={row.request_id} type="button" onClick={() => onSelect(row.request_id)}
        className={clsx('grid w-full cursor-pointer grid-cols-[62px_34px_minmax(0,1fr)_34px] items-center gap-1 border-b border-[var(--line-soft)] px-1.5 py-1 text-left text-[12px] last:border-0 hover:bg-[var(--panel-2)]',
          row.request_id === selected.request_id && 'bg-[var(--accent-soft)]')}>
        <span className="tabular text-[var(--muted)]">{formatLogTime(row.epoch, row.tz).slice(11)}</span>
        <span>{row.method}</span>
        <span className="mono truncate" title={row.uri}>{row.uri}</span>
        <span className={clsx('text-right tabular', statusTone(row.status))}>{row.status}</span>
      </button>)}
    </div>
  </section>
}

function BasketModal({ slug, open, onClose, clips, onDelete }: {
  slug: string
  open: boolean
  onClose: () => void
  clips: AccessClip[]
  onDelete: (id: number) => void
}) {
  const tr = useT()
  return <Modal open={open} onClose={onClose} title={<span className="inline-flex items-center gap-2"><Pin size={15} />{tr('logs.basket.title')}</span>}>
    {clips.length ? <div className="space-y-2">
      <div className="flex justify-end">
        <a href={downloadUrl(`/api/cases/${slug}/access/clips/export`)}
          className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] font-medium hover:border-[var(--accent)]/60">
          <Download size={13} /> {tr('logs.basket.export')}
        </a>
      </div>
      {clips.map((clip) => <article key={clip.id} className="rounded-xl border border-[var(--line)] bg-[var(--panel-2)] p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
              <span className="mono font-semibold">{clip.snapshot.client}</span>
              <span>{formatLogTime(clip.snapshot.epoch, clip.snapshot.tz, { withZone: true })}</span>
              <span className={statusTone(clip.snapshot.status)}>{clip.snapshot.status}</span>
            </div>
            <div className="mono mt-1 break-all text-[11px] font-semibold">{clip.snapshot.method} {clip.snapshot.uri}</div>
            <div className="mt-1 text-[10px] text-[var(--muted)]">{clip.snapshot.source}:{clip.snapshot.line_no}</div>
            {clip.note && <p className="mt-2 text-[11px]">{clip.note}</p>}
            <div className="mt-1"><SignalChips signals={clip.snapshot.signals ?? []} /></div>
          </div>
          <Button variant="ghost" title={tr('common.remove')} onClick={() => onDelete(clip.id)}><Trash2 size={13} /></Button>
        </div>
      </article>)}
    </div> : <div className="py-12 text-center text-[12px] text-[var(--muted)]">{tr('logs.basket.empty')}</div>}
  </Modal>
}

function LoadingBlock() {
  const tr = useT()
  return <Card className="flex min-h-52 items-center justify-center text-[12px] text-[var(--muted)]"><Clock3 size={15} className="mr-2 animate-pulse" />{tr('common.loading')}</Card>
}

function statusTone(status: number) {
  return status >= 500 ? 'text-[var(--sev-high)]'
    : status >= 400 ? 'text-[var(--sev-medium)]'
      : status >= 300 ? 'text-[var(--sev-low)]' : 'text-[var(--ok)]'
}

function statusBg(status: number) {
  return status >= 500 ? 'bg-[var(--danger-soft)] text-[var(--sev-high)]'
    : status >= 400 ? 'bg-[var(--panel-2)] text-[var(--sev-medium)]'
      : status >= 300 ? 'bg-[var(--panel-2)] text-[var(--sev-low)]'
        : 'bg-[var(--accent-soft)] text-[var(--ok)]'
}
