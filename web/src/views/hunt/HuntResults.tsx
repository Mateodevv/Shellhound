import { useEffect, useMemo, useRef, useState } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import clsx from 'clsx'
import {
  AlertTriangle, ArrowDown, ArrowUp, ChevronRight, LoaderCircle, PencilLine, Search,
} from 'lucide-react'
import {
  api, post, type ActorDetail, type HuntClusterPage, type HuntTest,
} from '../../api'
import type { Navigate } from '../../App'
import { formatCount, formatLogTime, formatSpan } from '../../format'
import { useT } from '../../i18n'
import { Button, Modal, Tag } from '../../components/ui'
import { IpFlag } from '../../components/IpFlag'
import { TraceWindow, type TraceMarks } from '../../components/TraceWindow'
import { ActorInspector } from '../Actors'

const PAGE_SIZE = 200
export type HuntResultSort = 'client' | 'method' | 'uri' | 'status' | 'requests' | 'first_hit'

export function HuntResults({
  slug, test, selected, collapsed, ruleName, sort, direction, onSelected, onSort,
  onCollapse, onEdit, editLabel, gotoView,
}: {
  slug: string
  test: HuntTest | null
  selected: Set<string>
  collapsed: boolean
  ruleName?: string
  sort: HuntResultSort
  direction: 'asc' | 'desc'
  onSelected: (value: Set<string>) => void
  onSort: (field: HuntResultSort) => void
  onCollapse?: () => void
  onEdit?: () => void
  editLabel?: string
  gotoView: Navigate
}) {
  const tr = useT()
  const qc = useQueryClient()
  const scrollRef = useRef<HTMLDivElement>(null)
  const [actorIp, setActorIp] = useState<string | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const pages = useInfiniteQuery({
    queryKey: ['hunt-clusters', slug, test?.id, sort, direction],
    initialPageParam: '',
    enabled: Boolean(test?.id),
    queryFn: ({ pageParam }) => post<HuntClusterPage>(
      `/api/cases/${slug}/hunt/tests/${test!.id}/clusters`,
      { cursor: pageParam, limit: PAGE_SIZE, sort, direction }),
    getNextPageParam: (page) => page.next_cursor ?? undefined,
  })
  const clusters = useMemo(
    () => pages.data?.pages.flatMap((page) => page.clusters) ?? [], [pages.data])
  const total = pages.data?.pages[0]?.total ?? 0
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

  const actor = useQuery({
    queryKey: ['actor-detail', slug, actorIp],
    queryFn: () => api<ActorDetail>(
      `/api/cases/${slug}/actor?ip=${encodeURIComponent(actorIp ?? '')}`),
    enabled: Boolean(actorIp),
  })
  const collect = useMutation({
    mutationFn: (ip: string) => post(`/api/cases/${slug}/actors/collect`, { ips: [ip] }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actor-detail', slug, actorIp] })
      qc.invalidateQueries({ queryKey: ['iocs', slug] })
    },
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
          {ruleName && <span className="font-semibold text-[var(--fg)]">{ruleName}</span>}
          <span><b className="text-[var(--fg)]">{formatCount(test.hits ?? 0)}</b> {tr('hunt.requests')}</span>
          <span><b className="text-[var(--fg)]">{formatCount(test.clients ?? 0)}</b> {tr('hunt.clients')}</span>
          <span><b className="text-[var(--sev-high)]">{formatCount(test.ok_hits ?? 0)}</b> 2xx</span>
          <span>{test.first_epoch && test.last_epoch
            ? formatSpan(test.first_epoch, test.last_epoch) : '—'}</span>
          <span>{formatLogTime(Date.parse(test.tested_at) / 1000, 0, { withZone: true })}</span>
        </div> : <div className="text-[10px] text-[var(--muted)]">
          {ruleName && <span className="font-semibold text-[var(--fg)]">{ruleName} · </span>}
          {tr('hunt.workbench.noTest')}
        </div>}
      </div>
      {selected.size > 0 && <Tag tone="accent">{selected.size} {tr('hunt.workbench.selected')}</Tag>}
      {onEdit && <Button onClick={onEdit}><PencilLine size={12} /> {editLabel || tr('hunt.workbench.editRule')}</Button>}
      {onCollapse && <button type="button" onClick={onCollapse} title={tr('common.close')}
        className="cursor-pointer rounded p-1.5 text-[var(--muted)] hover:bg-[var(--panel-2)]">
        <ChevronRight size={15} />
      </button>}
    </header>

    {!test ? <div className="flex min-h-0 flex-1 items-center justify-center p-8 text-center">
      <div><Search size={28} className="mx-auto text-[var(--muted)]" />
        <div className="mt-3 text-[13px] font-semibold">{tr('hunt.workbench.testFirst')}</div>
        <p className="mt-1 max-w-sm text-[11px] text-[var(--muted)]">{tr('hunt.workbench.testFirstSub')}</p>
      </div>
    </div> : <>
      <div className="flex min-h-0 flex-1 flex-col">
        <div className="flex min-h-0 min-w-0 flex-col overflow-hidden">
          <div className="grid shrink-0 grid-cols-[28px_minmax(130px,0.7fr)_54px_minmax(180px,1.5fr)_45px_58px_100px] items-center gap-2 border-b border-[var(--line-soft)] bg-[var(--panel-2)] px-2 py-1.5 text-[9px] font-bold uppercase tracking-wider text-[var(--muted)]">
            <span />
            <SortHeader field="client" active={sort} direction={direction} onSort={onSort}>
              {tr('hunt.workbench.client')}
            </SortHeader>
            <SortHeader field="method" active={sort} direction={direction} onSort={onSort}>
              {tr('hunt.field.method')}
            </SortHeader>
            <SortHeader field="uri" active={sort} direction={direction} onSort={onSort}>
              {tr('hunt.field.uri')}
            </SortHeader>
            <SortHeader field="status" active={sort} direction={direction} onSort={onSort}>
              {tr('hunt.field.status')}
            </SortHeader>
            <SortHeader field="requests" active={sort} direction={direction} onSort={onSort}
              className="justify-end">{tr('hunt.requests')}</SortHeader>
            <SortHeader field="first_hit" active={sort} direction={direction} onSort={onSort}>
              {tr('hunt.firstHit')}
            </SortHeader>
          </div>
          <div ref={scrollRef} className="min-h-[150px] flex-1 overflow-y-auto">
        {pages.isLoading ? <Loading /> : clusters.length ? <div className="relative w-full"
          style={{ height: `${virtualizer.getTotalSize()}px` }}>
          {virtualizer.getVirtualItems().map((item) => {
            const cluster = clusters[item.index]
            const checked = selected.has(cluster.cluster_key)
            return <div key={cluster.cluster_key} data-index={item.index}
              ref={virtualizer.measureElement}
              className={clsx(
                'absolute left-0 top-0 grid w-full grid-cols-[28px_minmax(130px,0.7fr)_54px_minmax(180px,1.5fr)_45px_58px_100px] items-center gap-2 border-b border-[var(--line-soft)] px-2 py-1.5 text-[10.5px] hover:bg-[var(--panel-2)]',
                checked && 'bg-[var(--accent-soft)]')}
              style={{ transform: `translateY(${item.start}px)` }}>
              <input type="checkbox" checked={checked} aria-label={tr('hunt.workbench.selectCluster')}
                onChange={() => {
                  const next = new Set(selected)
                  if (checked) next.delete(cluster.cluster_key); else next.add(cluster.cluster_key)
                  onSelected(next)
                }} />
              <button type="button" onClick={() => {
                setActorIp(cluster.client)
              }}
                className="mono inline-flex min-w-0 cursor-pointer items-center gap-1.5 truncate text-left font-semibold">
                <IpFlag ip={cluster.client} />{cluster.client}
              </button>
              <span className="mono">{cluster.method}</span>
              <span title={cluster.example_uri} className="mono truncate">{cluster.uri_pattern}</span>
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
        </div>
      </div>

      <CoverageFooter test={test} />
      <Modal open={Boolean(actorIp)} onClose={() => setActorIp(null)}
        title={<span className="flex items-center gap-2">
          {actorIp && <IpFlag ip={actorIp} />}
          <span>{tr('actors.inspector.title')}</span>
          {actorIp && <span className="mono text-[13px] text-[var(--muted)]">{actorIp}</span>}
        </span>}>
        <div className="h-[min(720px,calc(92vh-7rem))]">
          {actorIp && <ActorInspector key={actorIp} embedded showClose={false}
            detail={actor.data} loading={actor.isFetching} initialTab="activity" tr={tr}
            onClose={() => setActorIp(null)}
            onTrace={(exact = [], ips = [actorIp]) => {
              setTraceMarks({ exact, reason: tr('marks.alertTrigger') })
              setTraceIps(ips)
            }}
            onCollect={() => collect.mutate(actorIp)}
            onArtifact={() => gotoView('actors', {
              search: actorIp, actor: actorIp, section: 'evidence',
            })} />}
        </div>
      </Modal>
      <TraceWindow slug={slug} ips={traceIps} marks={traceMarks} layer={1}
        onClose={() => setTraceIps(null)} />
    </>}
  </section>
}

function SortHeader({ field, active, direction, onSort, className, children }: {
  field: HuntResultSort
  active: HuntResultSort
  direction: 'asc' | 'desc'
  onSort: (field: HuntResultSort) => void
  className?: string
  children: React.ReactNode
}) {
  const tr = useT()
  const selected = field === active
  const nextDirection = selected
    ? direction === 'asc' ? 'desc' : 'asc'
    : ['requests', 'first_hit'].includes(field) ? 'desc' : 'asc'
  return <button type="button" onClick={() => onSort(field)}
    aria-label={`${children} · ${tr(nextDirection === 'asc'
      ? 'hunt.workbench.sortAsc' : 'hunt.workbench.sortDesc')}`}
    className={clsx('flex cursor-pointer items-center gap-0.5 text-left hover:text-[var(--fg)]',
      selected && 'text-[var(--accent-text)]', className)}>
    <span className="truncate">{children}</span>
    {selected && (direction === 'asc' ? <ArrowUp size={10} /> : <ArrowDown size={10} />)}
  </button>
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
