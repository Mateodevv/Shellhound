import { useEffect, useMemo, useRef, useState } from 'react'
import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import clsx from 'clsx'
import {
  AlertTriangle, ChevronRight, ExternalLink,
  FileSearch, LoaderCircle, Network, Search,
} from 'lucide-react'
import {
  api, post, type AccessRequestContext, type ActorDetail, type HuntCluster,
  type HuntClusterPage, type HuntTest,
} from '../../api'
import type { Navigate } from '../../App'
import { formatCount, formatLogTime, formatSpan } from '../../format'
import { useT } from '../../i18n'
import { Button, Tag } from '../../components/ui'
import { IpFlag } from '../../components/IpFlag'

const PAGE_SIZE = 200

export function HuntResults({
  slug, test, selected, collapsed, onSelected, onCollapse, gotoView,
}: {
  slug: string
  test: HuntTest | null
  selected: Set<string>
  collapsed: boolean
  onSelected: (value: Set<string>) => void
  onCollapse: () => void
  gotoView: Navigate
}) {
  const tr = useT()
  const scrollRef = useRef<HTMLDivElement>(null)
  const [inspectedKey, setInspectedKey] = useState('')
  const pages = useInfiniteQuery({
    queryKey: ['hunt-clusters', slug, test?.id],
    initialPageParam: '',
    enabled: Boolean(test?.id),
    queryFn: ({ pageParam }) => post<HuntClusterPage>(
      `/api/cases/${slug}/hunt/tests/${test!.id}/clusters`,
      { cursor: pageParam, limit: PAGE_SIZE }),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
  const clusters = useMemo(
    () => pages.data?.pages.flatMap((page) => page.clusters) ?? [], [pages.data])
  const total = pages.data?.pages[0]?.total ?? 0
  const inspected = clusters.find((cluster) => cluster.cluster_key === inspectedKey)
    ?? clusters[0] ?? null
  const virtualizer = useVirtualizer({
    count: clusters.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 43,
    overscan: 16,
  })
  const lastVirtualIndex = virtualizer.getVirtualItems().at(-1)?.index ?? -1
  const { fetchNextPage, hasNextPage, isFetchingNextPage } = pages

  useEffect(() => {
    if (lastVirtualIndex >= clusters.length - 30 && hasNextPage && !isFetchingNextPage) {
      void fetchNextPage()
    }
  }, [clusters.length, fetchNextPage, hasNextPage, isFetchingNextPage, lastVirtualIndex])

  const context = useQuery({
    queryKey: ['access-request', slug, inspected?.request_id],
    queryFn: () => api<AccessRequestContext>(
      `/api/cases/${slug}/access/request/${inspected!.request_id}`),
    enabled: Boolean(inspected?.request_id),
  })
  const actor = useQuery({
    queryKey: ['actor-detail', slug, inspected?.client],
    queryFn: () => api<ActorDetail>(
      `/api/cases/${slug}/actor?ip=${encodeURIComponent(inspected!.client)}`),
    enabled: Boolean(inspected?.client),
  })

  if (collapsed) return <aside className="flex h-full w-12 flex-col items-center border-l border-[var(--line)] bg-[var(--panel)] py-2">
    <button type="button" onClick={onCollapse} title={tr('hunt.workbench.results')}
      className="cursor-pointer rounded-lg p-2 text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]">
      <Search size={16} />
    </button>
    {test && <span className="mt-3 [writing-mode:vertical-rl] text-[9px] uppercase tracking-wider text-[var(--muted)]">
      {formatCount(test.hits ?? 0)} {tr('hunt.requests')}
    </span>}
  </aside>

  return <section className="flex h-full min-w-0 flex-col bg-[var(--panel)]">
    <header className="flex shrink-0 items-center gap-3 border-b border-[var(--line)] px-3 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="text-[12px] font-semibold">{tr('hunt.workbench.results')}</div>
        {test ? <div className="mt-0.5 flex flex-wrap gap-x-3 text-[10px] text-[var(--muted)]">
          <span><b className="text-[var(--fg)]">{formatCount(test.hits ?? 0)}</b> {tr('hunt.requests')}</span>
          <span><b className="text-[var(--fg)]">{formatCount(test.clients ?? 0)}</b> {tr('hunt.clients')}</span>
          <span><b className="text-[var(--sev-high)]">{formatCount(test.ok_hits ?? 0)}</b> 2xx</span>
          <span>{test.first_epoch && test.last_epoch
            ? formatSpan(test.first_epoch, test.last_epoch) : '—'}</span>
          <span>{formatLogTime(Date.parse(test.tested_at) / 1000, 0, { withZone: true })}</span>
        </div> : <div className="text-[10px] text-[var(--muted)]">{tr('hunt.workbench.noTest')}</div>}
      </div>
      {selected.size > 0 && <Tag tone="accent">{selected.size} {tr('hunt.workbench.selected')}</Tag>}
      <button type="button" onClick={onCollapse} title={tr('common.close')}
        className="cursor-pointer rounded p-1.5 text-[var(--muted)] hover:bg-[var(--panel-2)]">
        <ChevronRight size={15} />
      </button>
    </header>

    {!test ? <div className="flex min-h-0 flex-1 items-center justify-center p-8 text-center">
      <div><Search size={28} className="mx-auto text-[var(--muted)]" />
        <div className="mt-3 text-[13px] font-semibold">{tr('hunt.workbench.testFirst')}</div>
        <p className="mt-1 max-w-sm text-[11px] text-[var(--muted)]">{tr('hunt.workbench.testFirstSub')}</p>
      </div>
    </div> : <>
      <div className="grid shrink-0 grid-cols-[28px_minmax(130px,0.7fr)_54px_minmax(180px,1.5fr)_45px_58px_100px] items-center gap-2 border-b border-[var(--line-soft)] bg-[var(--panel-2)] px-2 py-1.5 text-[9px] font-bold uppercase tracking-wider text-[var(--muted)]">
        <span />
        <span>{tr('hunt.workbench.client')}</span><span>{tr('hunt.field.method')}</span>
        <span>{tr('hunt.field.uri')}</span><span>{tr('hunt.field.status')}</span>
        <span className="text-right">{tr('hunt.requests')}</span><span>{tr('hunt.firstHit')}</span>
      </div>
      <div ref={scrollRef} className="min-h-[150px] flex-[1.15] overflow-y-auto border-b border-[var(--line)]">
        {pages.isLoading ? <Loading /> : clusters.length ? <div className="relative w-full"
          style={{ height: `${virtualizer.getTotalSize()}px` }}>
          {virtualizer.getVirtualItems().map((item) => {
            const cluster = clusters[item.index]
            const checked = selected.has(cluster.cluster_key)
            return <div key={cluster.cluster_key} data-index={item.index}
              ref={virtualizer.measureElement}
              className={clsx(
                'absolute left-0 top-0 grid w-full grid-cols-[28px_minmax(130px,0.7fr)_54px_minmax(180px,1.5fr)_45px_58px_100px] items-center gap-2 border-b border-[var(--line-soft)] px-2 py-1.5 text-[10.5px] hover:bg-[var(--panel-2)]',
                inspected?.cluster_key === cluster.cluster_key && 'bg-[var(--accent-soft)]')}
              style={{ transform: `translateY(${item.start}px)` }}>
              <input type="checkbox" checked={checked} aria-label={tr('hunt.workbench.selectCluster')}
                onChange={() => {
                  const next = new Set(selected)
                  if (checked) next.delete(cluster.cluster_key); else next.add(cluster.cluster_key)
                  onSelected(next)
                }} />
              <button type="button" onClick={() => setInspectedKey(cluster.cluster_key)}
                className="mono inline-flex min-w-0 cursor-pointer items-center gap-1.5 truncate text-left font-semibold">
                <IpFlag ip={cluster.client} />{cluster.client}
              </button>
              <span className="mono">{cluster.method}</span>
              <button type="button" onClick={() => setInspectedKey(cluster.cluster_key)}
                title={cluster.example_uri} className="mono cursor-pointer truncate text-left">{cluster.uri_pattern}</button>
              <span className={clsx('tabular font-semibold', cluster.ok_hits && 'text-[var(--sev-high)]')}>{cluster.status_class}</span>
              <span className="text-right tabular">{formatCount(cluster.requests)}</span>
              <span className="truncate text-[9.5px] text-[var(--muted)]">{formatLogTime(cluster.first_epoch, cluster.tz)}</span>
            </div>
          })}
        </div> : <div className="flex h-full items-center justify-center p-6 text-[11px] text-[var(--muted)]">
          {tr('hunt.workbench.noClusters')}
        </div>}
        {pages.isFetchingNextPage && <div className="flex justify-center p-2"><LoaderCircle size={15} className="animate-spin" /></div>}
        {clusters.length < total && !pages.hasNextPage && <div className="p-2 text-center text-[10px] text-[var(--muted)]">
          {clusters.length} / {total}
        </div>}
      </div>

      <RequestInspector cluster={inspected} context={context.data} actor={actor.data}
        loading={context.isFetching || actor.isFetching} gotoView={gotoView} />

      <CoverageFooter test={test} />
    </>}
  </section>
}

function RequestInspector({ cluster, context, actor, loading, gotoView }: {
  cluster: HuntCluster | null
  context?: AccessRequestContext
  actor?: ActorDetail
  loading: boolean
  gotoView: Navigate
}) {
  const tr = useT()
  if (!cluster) return null
  return <div className="min-h-[190px] flex-1 overflow-y-auto p-3">
    <div className="flex flex-wrap items-center gap-2">
      <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">
        <FileSearch size={12} />{tr('hunt.workbench.inspector')}
      </span>
      <span className="mono text-[11px] font-semibold">{cluster.client}</span>
      <span className="mono text-[10px] text-[var(--muted)]">{cluster.method} {cluster.example_uri}</span>
      {loading && <LoaderCircle size={12} className="animate-spin text-[var(--muted)]" />}
      <span className="ml-auto flex gap-1.5">
        <Button variant="ghost" onClick={() => gotoView('logs', {
          search: cluster.example_uri, request: String(cluster.request_id),
        })}><ExternalLink size={11} />{tr('hunt.workbench.openLogs')}</Button>
        <Button variant="ghost" onClick={() => gotoView('actors', { search: cluster.client })}>
          <ExternalLink size={11} />{tr('hunt.workbench.openActor')}</Button>
      </span>
    </div>
    <div className="mt-2 grid gap-2 2xl:grid-cols-[minmax(0,1.5fr)_minmax(230px,0.75fr)]">
      <div className="min-w-0">
        <pre className="max-h-24 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2 text-[9.5px] leading-relaxed">
          {context?.raw_line || `${cluster.method} ${cluster.example_uri}`}
        </pre>
        {context && <div className="mt-1 text-[9.5px] text-[var(--muted)]">
          {context.request.source}:{context.request.line_no} · {formatLogTime(context.request.epoch, context.request.tz, { withZone: true })}
        </div>}
        {context && <div className="mt-2 flex max-h-24 flex-col overflow-y-auto rounded-lg border border-[var(--line-soft)]">
          {[...context.before.slice(-3), context.request, ...context.after.slice(0, 3)].map((row) => <div key={row.request_id}
            className={clsx('grid grid-cols-[64px_38px_minmax(0,1fr)_34px] gap-1 border-b border-[var(--line-soft)] px-2 py-1 text-[9.5px] last:border-0',
              row.request_id === context.request.request_id && 'bg-[var(--accent-soft)]')}>
            <span className="text-[var(--muted)]">{formatLogTime(row.epoch, row.tz).slice(11)}</span>
            <span>{row.method}</span><span className="mono truncate">{row.uri}</span>
            <span className="text-right">{row.status}</span>
          </div>)}
        </div>}
      </div>
      <div className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2">
        <div className="flex items-center gap-1 text-[9px] font-bold uppercase tracking-wider text-[var(--muted)]">
          <Network size={11} />{tr('hunt.workbench.caseContext')}
        </div>
        {actor ? <div className="mt-2 space-y-1.5 text-[10px]">
          <div>{actor.findings.length} {tr('nav.findings')} · {actor.in_box ? tr('hunt.workbench.inIocBox') : tr('hunt.workbench.notInIocBox')}</div>
          <div>{actor.alerts.length} {tr('hunt.workbench.actorSignals')} · {actor.triage || tr('triage.new')}</div>
          {actor.findings.slice(0, 3).map((finding) => <div key={finding.id}
            className="truncate rounded bg-[var(--panel)] px-2 py-1" title={finding.evidence}>{finding.rule}</div>)}
        </div> : <div className="mt-3 text-[10px] text-[var(--muted)]">{tr('hunt.workbench.noCaseContext')}</div>}
      </div>
    </div>
  </div>
}

function CoverageFooter({ test }: { test: HuntTest }) {
  const tr = useT()
  const gaps = Object.entries(test.coverage?.fields ?? {})
    .filter(([, value]) => (value?.ratio ?? 1) < 1)
  if (!gaps.length && !test.truncated) return null
  return <footer className="shrink-0 border-t border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[9.5px] text-[var(--muted)]">
    <div className="flex items-center gap-1 font-semibold text-[var(--warning-text)]">
      <AlertTriangle size={11} />{tr('hunt.workbench.coverage')}
    </div>
    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
      {gaps.map(([field, value]) => <span key={field}>{tr(`hunt.field.${field}`)}: {Math.round((value?.ratio ?? 0) * 100)}%</span>)}
      {test.truncated && <span>{tr('hunt.workbench.truncated')}</span>}
    </div>
  </footer>
}

function Loading() {
  return <div className="flex h-full items-center justify-center"><LoaderCircle size={18} className="animate-spin text-[var(--muted)]" /></div>
}
