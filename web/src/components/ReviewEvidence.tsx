import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, type DatabaseRow, type DatabaseRowSource, type Finding } from '../api'
import { useT } from '../i18n'
import { Button, CopyButton, Modal, Tag } from './ui'
import { ChevronLeft, ChevronRight, Expand, FileCode2 } from 'lucide-react'
import { IocTypeBadge } from './IocTypeBadge'
import { absoluteTime, formatCount, formatBytes, formatLogTime } from '../format'

export function SuccessfulAccesses({ slug, ip, onView }: { slug: string; ip: string; onView: (path: string, line: number | null) => void }) {
  const tr = useT()
  const [page, setPage] = useState(0)
  const { data, error, isPending } = useQuery({ queryKey: ['artifact-accesses', slug, ip, page],
    queryFn: () => api<{ available: boolean; total: number; rows: { path: string; hits: number; last_epoch: number | null; statuses: number[]; files: { path: string; name: string }[] }[] }>(`/api/cases/${slug}/artifact/accesses?ip=${encodeURIComponent(ip)}&offset=${page * 50}`) })
  return <section className="space-y-3 text-[12px]">
    <p className="text-[var(--muted)]">{tr('review.accessHelp')}</p>
    {isPending && <p role="status">{tr('common.loading')}</p>}
    {error && <p role="alert" className="text-[var(--danger-text)]">{error.message}</p>}
    {data && !data.available && <p role="status">{tr('review.noIndex')}</p>}
    {data?.available && <>
      <div className="overflow-x-auto rounded-lg border border-[var(--line)]"><table className="w-full text-left text-[12px]">
        <thead className="bg-[var(--panel-2)]"><tr>{['review.filePath', 'review.lastAccess', 'review.successCount', 'review.status', 'review.actions'].map(key => <th className="px-3 py-2" key={key}>{tr(key)}</th>)}</tr></thead>
        <tbody>{data.rows.map(row => <tr key={row.path} className="border-t border-[var(--line)] align-top">
          <td className="max-w-72 break-all px-3 py-2"><div className="mono">{row.path}</div>{!row.files.length && <p className="mt-1 text-[11px] text-[var(--muted)]">{tr('review.noLocalFile')}</p>}
            {row.files.map(file => <button type="button" className="mt-1 flex items-center gap-2 text-[var(--accent-text)] hover:underline" key={file.path} title={file.path} onClick={() => onView(file.path, null)}><IocTypeBadge type="file" />{file.name}</button>)}
          </td>
          <td className="px-3 py-2 text-[var(--muted)]">{row.last_epoch ? `${absoluteTime(new Date(row.last_epoch * 1000).toISOString())} UTC` : '—'}</td>
          <td className="px-3 py-2 tabular">{formatCount(row.hits)}</td><td className="px-3 py-2"><div className="flex flex-wrap gap-1">{row.statuses.map(status => <Tag key={status} tone="ok">{status}</Tag>)}</div></td>
          <td className="px-3 py-2">{row.files.map(file => <Button key={file.path} variant="special" className="mb-1 whitespace-nowrap" aria-label={row.files.length > 1 ? file.name : tr('review.openFile')} title={file.path} onClick={() => onView(file.path, null)}><FileCode2 size={13} />{row.files.length > 1 ? file.name : tr('review.openFile')}</Button>)}</td>
        </tr>)}{!data.rows.length && <tr><td colSpan={5} className="p-3 text-[var(--muted)]">{tr('review.noSuccess')}</td></tr>}</tbody>
      </table></div>
      <div className="flex items-center justify-between"><span>{tr('review.pathsCount', { n: data.total })}</span><div className="flex gap-2"><Button aria-label={tr('review.previousPage')} disabled={!page} onClick={() => setPage(page - 1)}><ChevronLeft size={14} /></Button><Button aria-label={tr('review.nextPage')} disabled={(page + 1) * 50 >= data.total} onClick={() => setPage(page + 1)}><ChevronRight size={14} /></Button></div></div>
    </>}
  </section>
}

export function TableRecord({ slug, sources, finding, tableName }: { slug: string; sources: DatabaseRowSource[]; finding?: Finding | null; tableName: string }) {
  const tr = useT()
  const [sourceId, setSourceId] = useState<number | null>(sources.length === 1 ? sources[0].dump_id : null)
  const [row, setRow] = useState(finding?.line || 1)
  const [expanded, setExpanded] = useState(false)
  const source = sources.find(item => item.dump_id === sourceId)
  const { data, error, isPending } = useQuery({ queryKey: ['review-table-row', slug, sourceId, source?.table_id, finding?.id, row],
    queryFn: () => api<DatabaseRow>(source?.table_id != null
      ? `/api/cases/${slug}/database/table-row?table_id=${source.table_id}&row=${row}`
      : `/api/cases/${slug}/database/row?finding_id=${finding!.id}&dump_id=${sourceId}`),
    enabled: sourceId != null && (source?.rows !== 0) && (!!source?.table_id || !!finding) })
  const columns = <div className="overflow-x-auto rounded-lg border border-[var(--line)]"><table className="w-full table-fixed text-left text-[12px]"><thead className="bg-[var(--panel-2)]"><tr><th className="w-1/4 px-3 py-2">{tr('review.field')}</th><th className="px-3 py-2">{tr('review.value')}</th></tr></thead><tbody>{data?.columns.map((column, index) => {
    // Highlight only a field containing the recorded evidence excerpt.
    const excerpt = finding?.evidence?.split(' · dump:')[0].replace(/^…|…$/g, '').replace(/\s+/g, ' ').trim() || ''
    const hit = finding?.retired !== 1 && finding?.line === row && excerpt.length >= 4 && column.value?.replace(/\s+/g, ' ').includes(excerpt)
    return <tr key={index} className={`border-t border-[var(--line)] align-top ${hit ? 'bg-[var(--danger-soft)]' : ''}`}><th className="mono break-all px-3 py-3 font-medium">{column.name}</th><td className="px-3 py-3"><div className="flex items-start gap-2"><pre className="mono min-w-0 flex-1 whitespace-pre-wrap break-all">{column.value === null ? 'NULL' : column.value}</pre>{column.value != null && <CopyButton value={column.value} label={tr('review.copyValue')} />}</div>{column.truncated && <p className="text-[var(--warn)]">{tr('database.row.valueTruncated')}</p>}</td></tr>
  })}</tbody></table></div>
  return <section className="flex min-h-0 flex-1 flex-col gap-3 text-[12px]">
    <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">{tr('review.record')} · {tableName} · {tr('database.row.label')} {row}</h3><div className="flex gap-2">
      <Button variant="special" disabled={!data} onClick={() => setExpanded(true)}><Expand size={13} />{tr('review.expandRecord')}</Button>
      <Button aria-label={tr('review.previousRow')} disabled={!source?.table_id || row <= 1} onClick={() => setRow(row - 1)}><ChevronLeft size={14} /></Button><Button aria-label={tr('review.nextRow')} disabled={!source?.table_id || row >= (source.rows ?? row)} onClick={() => setRow(row + 1)}><ChevronRight size={14} /></Button>
    </div></div>
    <label className="flex flex-col gap-1 text-[var(--muted)]">{tr('database.row.source')}<select aria-label={tr('database.row.source')} value={sourceId ?? ''} onChange={event => { setSourceId(Number(event.target.value) || null); setRow(finding?.line || 1) }} className="min-w-0 rounded border border-[var(--line)] bg-[var(--panel-2)] p-2 text-[var(--fg)]"><option value="" disabled>{tr('database.row.choose')}</option>{sources.map(item => <option key={item.dump_id} value={item.dump_id}>{item.dump_path}</option>)}</select></label>
    {sources.length > 1 && <p className="text-[var(--muted)]">{tr('database.row.multiple')}</p>}
    {!sources.length && <p role="status">{tr('database.row.noSource')}</p>}
    {source?.rows === 0 ? <p role="status">{tr('review.emptyTable')}</p> : sourceId != null && isPending && <p role="status">{tr('common.loading')}</p>}
    {error && <p role="alert" className="text-[var(--danger-text)]">{error.message}</p>}
    <div data-artifact-scroll="primary" tabIndex={0} className="min-h-0 flex-1 overflow-auto">{data && <>{data.truncated && <p className="text-[var(--warn)]">{tr('database.row.truncated')}</p>}{columns}</>}</div>
    <p className="text-[11px] text-[var(--muted)]">{tr('database.row.explain')}</p>
    {expanded && <Modal open layer={2} contained onClose={() => setExpanded(false)} title={`${tableName} · ${tr('database.row.label')} ${row}`}>{columns}</Modal>}
  </section>
}


/** Only requests contributing to the selected finding; no broad trace fallback. */
export function FindingRequests({ slug, finding }: { slug: string; finding: Finding }) {
  const tr = useT()
  const [page, setPage] = useState(0)
  const { data, error, isPending } = useQuery({
    queryKey: ['finding-requests', slug, finding.id, page],
    queryFn: () => api<{ available: boolean; reason?: string; total: number; rule_kind?: string; rows: { request_id: number; epoch: number | null; tz: number | null; method: string; uri: string; status: number; size: number | null; source: string; line: number; agent: string }[] }>(`/api/cases/${slug}/artifact/finding-requests?finding_id=${finding.id}&offset=${page * 50}`),
  })
  return <section className="flex min-h-0 flex-1 flex-col gap-2 text-[12px]" aria-label={tr('review.findingRequests')}>
    <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">{tr('review.findingRequests')}{data?.available ? ` · ${formatCount(data.total)}` : ''}</h3>
      {data?.available && data.total > 50 && <div className="flex items-center gap-2"><span className="text-[var(--muted)]">{page * 50 + 1}–{Math.min((page + 1) * 50, data.total)} / {formatCount(data.total)}</span><Button aria-label={tr('review.previousPage')} disabled={!page} onClick={() => setPage(page - 1)}><ChevronLeft size={14} /></Button><Button aria-label={tr('review.nextPage')} disabled={(page + 1) * 50 >= data.total} onClick={() => setPage(page + 1)}><ChevronRight size={14} /></Button></div>}
    </div>
    <p className="text-[11px] text-[var(--muted)]">{tr(data?.rule_kind === 'login_success' ? 'review.findingLoginContext' : 'review.findingRequestHelp')}</p>
    {isPending && <p role="status">{tr('common.loading')}</p>}
    {error && <p role="alert" className="text-[var(--danger-text)]">{error.message}</p>}
    {data && !data.available && <p role="status" className="text-[var(--muted)]">{tr(`review.requestReason.${data.reason || 'unsupported'}`)}</p>}
    {data?.available && <div data-artifact-scroll="primary" tabIndex={0} className="min-h-0 overflow-auto rounded-lg border border-[var(--line)]"><table className="w-full text-left">
      <thead className="sticky top-0 bg-[var(--panel-2)]"><tr>{['review.requestTime','review.requestMethod','review.filePath','review.status','review.requestSize','review.requestSource'].map(key => <th key={key} className="px-3 py-2">{tr(key)}</th>)}</tr></thead>
      <tbody>{data.rows.map(row => <tr key={row.request_id} className="border-t border-[var(--line)] align-top">
        <td className="whitespace-nowrap px-3 py-2 text-[var(--muted)] tabular">{formatLogTime(row.epoch, row.tz ?? 0, { withZone: true })}</td>
        <td className="mono px-3 py-2">{row.method}</td><td className="min-w-48 max-w-lg break-all px-3 py-2"><span className="mono">{row.uri}</span>{data.rule_kind === 'scanner_ua' && <div className="mt-1 text-[var(--muted)]">{row.agent}</div>}</td>
        <td className="px-3 py-2"><Tag tone={row.status >= 200 && row.status < 300 ? 'ok' : undefined}>{row.status}</Tag></td><td className="whitespace-nowrap px-3 py-2 tabular">{row.size == null ? '—' : formatBytes(row.size)}</td>
        <td className="break-all px-3 py-2 text-[var(--muted)]">{row.source}{row.line ? `:${row.line}` : ''}</td>
      </tr>)}{!data.rows.length && <tr><td colSpan={6} className="p-3 text-[var(--muted)]">{tr('review.noFindingRequests')}</td></tr>}</tbody>
    </table></div>}
  </section>
}
