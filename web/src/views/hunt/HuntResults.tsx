import { useT } from '../../i18n'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, ArrowRight, Check, PencilLine } from 'lucide-react'
import { api, post, type AccessLogRow, type AccessRequestContext, type HuntClusterPage, type HuntIpPage, type HuntTest } from '../../api'
import { formatCount, formatLogTime } from '../../format'
import { Button, Card, Tag } from '../../components/ui'
import { TraceWindow } from '../../components/TraceWindow'
import { ErrorMessage } from './HuntRunOverview'

const PAGE_SIZE = 50
const SELECTION_LIMIT = 200
const timestamp = (epoch?: number | null, tz?: number) => formatLogTime(epoch, tz, { withZone: true })

export function HuntResults({ slug, test, selected, ruleName, ruleMeaning, ruleNotMeaning,
  fresh, applyHint, applying, onSelected, onApply, onEdit }: {
  slug: string; test: HuntTest | null; selected: Set<string>
  ruleName?: string; ruleMeaning?: string; ruleNotMeaning?: string
  fresh: boolean; applyHint: string; applying: boolean
  onSelected: (value: Set<string>) => void; onApply: () => void; onEdit?: () => void
}) {
  const tr = useT()
  const [client, setClient] = useState('')
  const [cursors, setCursors] = useState([''])
  const [sort, setSort] = useState<'requests' | 'first_hit' | 'last_hit' | 'client'>('requests')
  const cursor = cursors[cursors.length - 1]
  const clients = useQuery({ queryKey: ['hunt-clients', slug, test?.id, sort, cursor], enabled: Boolean(test && fresh),
    queryFn: () => post<HuntIpPage>(`/api/cases/${slug}/hunt/tests/${test!.id}/clients`, {
      cursor, limit: PAGE_SIZE, sort, direction: sort === 'client' || sort === 'first_hit' ? 'asc' : 'desc',
    }) })
  const chooseClient = (ip: string) => { onSelected(new Set()); setClient(ip) }
  if (!test) return <Card className="p-6 text-sm">{tr('hunt.flow.missingResult')}</Card>
  const gaps = Object.entries(test.coverage?.fields ?? {}).filter(([, value]) => (value?.ratio ?? 1) < 1)
  return <div className="space-y-4">
    <Card className="p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div><h2 className="text-xl font-semibold">{ruleName || tr('hunt.flow.patternResults')}</h2>
          <p className="mt-1 text-sm text-[var(--muted)]">{tr('hunt.flow.resultVersion', { time: test.tested_at.replace('T', ' ').slice(0, 19), version: test.pattern_version || tr('hunt.flow.draft') })}</p></div>
        {onEdit && <Button onClick={onEdit}><PencilLine size={15} /> {tr('hunt.flow.editPattern')}</Button>}
      </div>
      <p className="mt-4 text-sm leading-relaxed">{ruleMeaning || tr('hunt.flow.matchMeaning')}</p>
      <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{ruleNotMeaning || tr('hunt.flow.matchLimits')}</p>
      <dl className="mt-5 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[[tr('hunt.flow.matchingRequests'), formatCount(test.hits)], [tr('hunt.flow.ipAddresses'), formatCount(test.clients)],
          [tr('hunt.flow.firstMatch'), timestamp(test.first_epoch, test.tz)], [tr('hunt.flow.lastMatch'), timestamp(test.last_epoch, test.tz)]].map(([label, value]) =>
          <div key={label}><dt className="text-sm text-[var(--muted)]">{label}</dt><dd className="mt-1 font-semibold">{value}</dd></div>)}
      </dl>
      {gaps.length > 0 && <div className="mt-4 rounded-lg bg-[var(--panel-2)] p-3 text-sm text-[var(--sev-medium)]">{tr('hunt.flow.someLogFieldsAreMissing')} {gaps.map(([field, value]) => tr('hunt.flow.fieldCoverage', { field: field.replaceAll('_', ' '), percent: Math.round((value?.ratio ?? 0) * 100) })).join(' · ')}{tr('hunt.flow.resultsCoverTheIndexedInformationAvailable')}</div>}
    </Card>
    {!fresh ? <ErrorMessage message={tr('hunt.flow.staleResult')} />
      : client ? <>
        <Button variant="ghost" onClick={() => chooseClient('')}><ArrowLeft size={15} /> {tr('hunt.flow.allMatchingIps')}</Button>
        <ClientMatches key={`${test.id}:${client}`} slug={slug} test={test} client={client} selected={selected}
          onSelected={onSelected} onApply={onApply} applyHint={applyHint} applying={applying} />
      </> : <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] p-4">
          <h3 className="font-semibold">{tr('hunt.flow.matchingIpAddresses')}</h3>
          <label className="text-sm">{tr('hunt.flow.sortBy')} <select value={sort} onChange={(e) => { setCursors(['']); setSort(e.target.value as typeof sort) }}
            className="ml-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2">
            <option value="requests">{tr('hunt.flow.mostMatchingRequests')}</option><option value="first_hit">{tr('hunt.flow.firstMatch')}</option>
            <option value="last_hit">{tr('hunt.flow.lastMatch')}</option><option value="client">{tr('hunt.flow.ipAddress')}</option></select></label>
        </div>
        {clients.isError ? <div className="px-4"><ErrorMessage message={clients.error.message} onRetry={() => void clients.refetch()} /></div>
          : clients.isPending ? <p role="status" className="p-6 text-sm">{tr('hunt.flow.loadingIpAddresses')}</p>
            : !clients.data?.clients.length ? <p className="p-6 text-sm text-[var(--muted)]">{tr('hunt.flow.noIpAddressesMatchedThisPattern')}</p>
              : <div className="overflow-x-auto"><table className="w-full text-left text-sm">
                <thead className="bg-[var(--panel-2)] text-[var(--muted)]"><tr>
                  {[tr('hunt.flow.ipAddress'), tr('hunt.flow.matches'), tr('hunt.flow.response2xx'), tr('hunt.flow.firstMatch'), tr('hunt.flow.lastMatch')].map((label) => <th key={label} className="whitespace-nowrap px-4 py-3 font-medium">{label}</th>)}
                </tr></thead><tbody>
                  {clients.data.clients.map((row) => <tr key={row.client} className="border-t border-[var(--line)] hover:bg-[var(--panel-2)]">
                    <td className="px-4 py-3"><button type="button" onClick={() => chooseClient(row.client)}
                      className="mono cursor-pointer text-left font-semibold text-[var(--accent-text)] underline-offset-4 hover:underline">{row.client}</button></td>
                    <td className="px-4 py-3 tabular-nums">{formatCount(row.requests)}</td><td className="px-4 py-3 tabular-nums">{formatCount(row.ok_hits)}</td>
                    <td className="whitespace-nowrap px-4 py-3">{timestamp(row.first_epoch, row.tz)}</td>
                    <td className="whitespace-nowrap px-4 py-3">{timestamp(row.last_epoch, row.tz)}</td>
                  </tr>)}
                </tbody></table></div>}
        <Pager page={cursors.length} total={clients.data?.total ?? 0} hasNext={Boolean(clients.data?.next_cursor)} loading={clients.isFetching}
          onPrevious={() => setCursors((v) => v.slice(0, -1))}
          onNext={() => clients.data?.next_cursor && setCursors((v) => [...v, clients.data!.next_cursor!])} />
      </Card>}
  </div>
}

function ClientMatches({ slug, test, client, selected, onSelected, onApply, applyHint, applying }: {
  slug: string; test: HuntTest; client: string; selected: Set<string>
  onSelected: (value: Set<string>) => void; onApply: () => void; applyHint: string; applying: boolean
}) {
  const tr = useT()
  const [cursors, setCursors] = useState([''])
  const [requestId, setRequestId] = useState<number | null>(null)
  const [traceRequest, setTraceRequest] = useState<AccessLogRow | null>(null)
  const clientHeading = useRef<HTMLHeadingElement>(null)
  const requestHeading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { clientHeading.current?.focus() }, [client])
  useEffect(() => { if (requestId !== null) requestHeading.current?.focus() }, [requestId])
  const cursor = cursors[cursors.length - 1]
  const clusters = useQuery({ queryKey: ['hunt-clusters', slug, test.id, client, cursor],
    queryFn: () => post<HuntClusterPage>(`/api/cases/${slug}/hunt/tests/${test.id}/clusters`, {
      client, cursor, limit: PAGE_SIZE, sort: 'first_hit', direction: 'asc',
    }) })
  const rows = useMemo(() => clusters.data?.clusters ?? [], [clusters.data])
  useEffect(() => {
    if (clusters.isError) { setRequestId(null); setTraceRequest(null) }
  }, [clusters.isError])
  const visibleKeys = useMemo(() => new Set(rows.map((row) => row.cluster_key)), [rows])
  // Refreshes or page changes cannot leave an invisible selection eligible for application.
  useEffect(() => {
    const valid = new Set([...selected].filter((key) => visibleKeys.has(key)))
    if (valid.size !== selected.size) onSelected(valid)
  }, [visibleKeys, selected, onSelected])
  const request = useQuery({ queryKey: ['hunt-request', slug, test.id, requestId], enabled: requestId !== null,
    queryFn: () => api<AccessRequestContext>(`/api/cases/${slug}/access/request/${requestId}?index_fingerprint=${encodeURIComponent(test.index_fingerprint)}`) })
  const allSelected = rows.length > 0 && rows.every((row) => selected.has(row.cluster_key))
  const changePage = (next: string[] ) => { onSelected(new Set()); setRequestId(null); setCursors(next) }
  const traceIps = useMemo(() => traceRequest ? [client] : null, [traceRequest, client])
  return <>
    <Card className="overflow-hidden">
      <header className="border-b border-[var(--line)] p-5">
        <h3 ref={clientHeading} tabIndex={-1} className="text-lg font-semibold outline-none">{tr('hunt.flow.matchingActivity')} <span className="mono">{client}</span></h3>
        <p className="mt-2 text-sm text-[var(--muted)]">{tr('hunt.flow.groupExplanation')}</p>
      </header>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] bg-[var(--panel-2)] p-4">
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={allSelected} disabled={!rows.length || clusters.isFetching}
          onChange={() => onSelected(allSelected ? new Set() : new Set(rows.slice(0, SELECTION_LIMIT).map((r) => r.cluster_key)))} /> {tr('actors.selectPage')}</label>
        <Button variant="primary" disabled={Boolean(applyHint) || applying || clusters.isFetching || clusters.isError || !selected.size || selected.size > SELECTION_LIMIT}
          onClick={onApply}><Check size={15} /> {applying ? tr('hunt.flow.adding') : tr('hunt.flow.addSelectedToFindings')} ({selected.size})</Button>
        <p className="w-full text-sm text-[var(--muted)]">{applyHint || tr('hunt.flow.selectionHint', { limit: SELECTION_LIMIT })}</p>
      </div>
      {clusters.isError ? <div className="px-4"><ErrorMessage message={clusters.error.message} onRetry={() => void clusters.refetch()} /></div>
        : clusters.isPending ? <p role="status" className="p-6 text-sm">{tr('hunt.flow.loadingMatchingActivity')}</p>
          : <div className="divide-y divide-[var(--line)]">{rows.map((row) => <div key={row.cluster_key} className="flex gap-3 p-4">
            <input type="checkbox" className="mt-1 self-start" aria-label={tr('hunt.flow.selectGroup', { method: row.method, path: row.uri_pattern, response: row.status_class })}
              checked={selected.has(row.cluster_key)} disabled={applying || (!selected.has(row.cluster_key) && selected.size >= SELECTION_LIMIT)}
              onChange={() => { const next = new Set(selected); if (next.has(row.cluster_key)) next.delete(row.cluster_key); else next.add(row.cluster_key); onSelected(next) }} />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2 text-sm"><Tag>{row.method}</Tag><Tag>{row.status_class}</Tag>
                <span>{formatCount(row.requests)} {tr('trace.requests')}</span></div>
              <p className="mono mt-2 break-all text-sm">{row.uri_pattern}</p>
              <div className="mt-2 flex flex-wrap justify-between gap-3 text-sm text-[var(--muted)]">
                <span>{timestamp(row.first_epoch, row.tz)} → {timestamp(row.last_epoch, row.tz)}</span>
                <Button onClick={() => setRequestId(row.request_id)}>{tr('hunt.flow.inspectFirstRequest')} <ArrowRight size={14} /></Button>
              </div>
            </div>
          </div>)}{!rows.length && <p className="p-6 text-sm">{tr('hunt.flow.noMatchingActivityOnThisPage')}</p>}</div>}
      <Pager page={cursors.length} total={clusters.data?.total ?? 0} hasNext={Boolean(clusters.data?.next_cursor)} loading={clusters.isFetching || applying}
        onPrevious={() => changePage(cursors.slice(0, -1))} onNext={() => clusters.data?.next_cursor && changePage([...cursors, clusters.data.next_cursor])} />
    </Card>
    {requestId !== null && !clusters.isError && <Card className="p-5">
      <div className="flex items-center justify-between gap-3"><h3 ref={requestHeading} tabIndex={-1} className="text-lg font-semibold outline-none">{tr('hunt.flow.requestAndSurroundingActivity')}</h3>
        <Button variant="ghost" onClick={() => setRequestId(null)}>{tr('hunt.flow.closeRequest')}</Button></div>
      {request.isError ? <ErrorMessage message={request.error.message} onRetry={() => void request.refetch()} />
        : request.isPending ? <p role="status" className="mt-4 text-sm">{tr('hunt.flow.loadingRequestContext')}</p> : request.data && <>
          <div className="mt-4 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-4">
            <p className="text-sm">{timestamp(request.data.request.epoch, request.data.request.tz)} · {request.data.request.source} {tr('hunt.flow.line')} {request.data.request.line_no}</p>
            <p className="mono mt-2 break-all text-sm">{request.data.request.method} {request.data.request.uri} · {request.data.request.status}</p>
            <Button className="mt-3" disabled={request.data.request.epoch == null} onClick={() => setTraceRequest(request.data!.request)}>{tr('hunt.flow.activityAfterThisRequest')} <ArrowRight size={15} /></Button>
            {request.data.request.epoch == null && <p className="mt-2 text-sm text-[var(--muted)]">{tr('hunt.flow.missingTimestamp')}</p>}
          </div>
          <p className="mt-4 text-sm text-[var(--muted)]">{tr('hunt.flow.nearbyExplanation')}</p>
          <div className="mt-3 overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr>
            {[tr('table.time'), tr('hunt.flow.request'), tr('hunt.flow.response'), tr('logs.table.source')].map((v) => <th key={v} className="p-2 font-medium text-[var(--muted)]">{v}</th>)}
          </tr></thead><tbody>{[...request.data.before, request.data.request, ...request.data.after].map((r) => <tr key={r.request_id}
            className={`border-t border-[var(--line)] ${r.request_id === requestId ? 'bg-[var(--accent-soft)]' : ''}`}>
            <td className="whitespace-nowrap p-2">{timestamp(r.epoch, r.tz)}</td><td className="mono max-w-md break-all p-2">{r.method} {r.uri}</td>
            <td className="p-2">{r.status}</td><td className="p-2">{r.source}:{r.line_no}</td></tr>)}</tbody></table></div>
        </>}
    </Card>}
    <TraceWindow slug={slug} ips={clusters.isError ? null : traceIps} onClose={() => setTraceRequest(null)} anchor={traceRequest ? {
      requestId: traceRequest.request_id, epoch: traceRequest.epoch, tz: traceRequest.tz, method: traceRequest.method,
      uri: traceRequest.uri, source: traceRequest.source, lineNo: traceRequest.line_no, indexFingerprint: test.index_fingerprint,
    } : undefined} />
  </>
}

function Pager({ page, total, hasNext, loading, onPrevious, onNext }: {
  page: number; total: number; hasNext: boolean; loading: boolean; onPrevious: () => void; onNext: () => void
}) {
  const tr = useT()
  if (page === 1 && !hasNext) return null
  return <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--line)] p-4 text-sm">
    <span>{tr('hunt.flow.pageTotal', { page, total: formatCount(total) })}</span>
    <div className="flex gap-2"><Button disabled={page === 1 || loading} onClick={onPrevious}>{tr('evidence.skips.previous')}</Button>
      <Button disabled={!hasNext || loading} onClick={onNext}>{tr('evidence.skips.next')}</Button></div>
  </div>
}
