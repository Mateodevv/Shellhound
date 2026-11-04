import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, post, type DatabaseRow, type DatabaseRowSource, type Finding } from '../../api'
import { useT } from '../../i18n'
import { Button, CopyButton, Tag } from '../ui/ui'
import { ChevronLeft, ChevronRight, Expand, FileCode2, FolderOpen } from 'lucide-react'
import { IocTypeBadge } from '../iocs/IocTypeBadge'
import { DatabaseField, MatchText } from './DatabaseField'
import { absoluteTime, formatCount, formatBytes, formatLogTime } from '../../format'

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

type TableRecordProps = {
  slug: string; sources: DatabaseRowSource[]; finding?: Finding | null; tableName: string
  sourceId?: number | null; onSourceChange?: (id: number | null) => void; initialRow?: number
}

export function TableRecord(props: TableRecordProps) {
  return <TableRecordSource key={`${props.slug}:${props.tableName}`} {...props} />
}

function TableRecordSource({ slug, sources, finding, tableName, sourceId: controlledSource, onSourceChange, initialRow }: TableRecordProps) {
  const [sourcePath, setSourcePath] = useState<string | null | undefined>(sources.length ? sources.length === 1 ? sources[0].dump_path : null : undefined)
  if (sourcePath === undefined && sources.length) setSourcePath(sources.length === 1 ? sources[0].dump_path : null)
  const sourceId = controlledSource === undefined ? sources.find(item => item.dump_path === sourcePath)?.dump_id ?? null : controlledSource
  const source = sources.find(item => item.dump_id === sourceId)
  return <TableRecordBody key={`${slug}:${tableName}:${sourceId}:${source?.dump_path}:${finding?.id}:${initialRow}`} slug={slug} sources={sources} finding={finding} tableName={tableName} source={source} initialRow={initialRow}
    onSourceChange={id => { setSourcePath(sources.find(item => item.dump_id === id)?.dump_path ?? null); onSourceChange?.(id) }} />
}

function TableRecordBody({ slug, sources, source, finding, tableName, onSourceChange, initialRow }: {
  slug: string; sources: DatabaseRowSource[]; source?: DatabaseRowSource; finding?: Finding | null; tableName: string
  onSourceChange: (id: number | null) => void; initialRow?: number
}) {
  const tr = useT()
  const reveal = useMutation({ mutationFn: (path: string) => post(`/api/cases/${slug}/reveal-file`, { path }) })
  const [row, setRow] = useState(initialRow ?? finding?.line ?? 1)
  const [matchIndex, setMatchIndex] = useState(0)
  const [expandedColumn, setExpandedColumn] = useState<number | null>(null)
  const rowFinding = finding?.line === row ? finding : undefined
  const { data, error, isPending } = useQuery({ queryKey: ['review-table-row', slug, source?.dump_id, source?.table_id, source?.dump_path, tableName, finding?.id, row],
    queryFn: () => api<DatabaseRow>(source?.table_id != null
      ? `/api/cases/${slug}/database/table-row?table_id=${source.table_id}&row=${row}&expected_dump_path=${encodeURIComponent(source.dump_path)}&expected_table=${encodeURIComponent(tableName)}${rowFinding ? `&finding_id=${rowFinding.id}` : ''}`
      : `/api/cases/${slug}/database/row?finding_id=${finding!.id}&dump_id=${source?.dump_id}&expected_dump_path=${encodeURIComponent(source!.dump_path)}`),
    enabled: !!source && source.rows !== 0 && (source.table_id != null || !!finding) })
  const matches = data?.finding_match?.matches ?? []
  const match = matches[matchIndex] ?? matches[0]
  const details = data?.columns.filter((column, index) => !matches.some(hit => hit.column_index === (column.index ?? index))) ?? []
  const canExpand = data?.table_id != null && !!data.record_version
  function navigate(next: number) { setRow(next); setMatchIndex(0); setExpandedColumn(null) }
  return <section className="flex min-h-0 flex-1 flex-col gap-3 text-[12px]">
    <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">{tr('review.record')} · {tableName} · {tr('database.row.label')} {row}</h3><div className="flex gap-2">
      <Button aria-label={tr('review.previousRow')} disabled={source?.table_id == null || row <= 1} onClick={() => navigate(row - 1)}><ChevronLeft size={14} /></Button><Button aria-label={tr('review.nextRow')} disabled={source?.table_id == null || row >= (source.rows ?? row)} onClick={() => navigate(row + 1)}><ChevronRight size={14} /></Button>
    </div></div>
    <div data-artifact-scroll="primary" tabIndex={0} className="min-h-0 flex-1 space-y-3 overflow-auto">
      {data?.finding_match && <p role="status" className="text-[var(--muted)]" title={['recorded', 'current'].includes(data.finding_match.state) ? tr(`database.row.match.${data.finding_match.state}Hint`) : undefined}>{tr(`database.row.match.${data.finding_match.state}`)}</p>}
      {match && <div className="space-y-2 rounded-lg border border-[var(--line)] p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          {matches.length > 1 ? <select aria-label={tr('database.row.matchingField')} className="max-w-full rounded border border-[var(--line)] bg-[var(--panel-2)] p-1" value={matchIndex} onChange={event => { setMatchIndex(Number(event.target.value)); setExpandedColumn(null) }}>{matches.map((item, index) => <option key={index} value={index}>{item.column_name}</option>)}</select> : <h4 className="mono break-all font-semibold">{match.column_name}</h4>}
          <div className="flex gap-2"><CopyButton value={match.before + match.text + match.after} label={tr('database.row.copyVisible')} /><Button disabled={!canExpand} onClick={() => setExpandedColumn(match.column_index)}><Expand size={13} />{tr('database.row.expandField')}</Button></div>
        </div>
        <pre className="mono whitespace-pre-wrap break-all"><MatchText match={match} finding={rowFinding} /></pre>
      </div>}
      {rowFinding?.evidence && data?.finding_match && !matches.length && <div className="rounded-lg border border-[var(--line)] p-3"><h4 className="mb-2 font-semibold">{tr('database.row.recordedExcerpt')}</h4><pre className="mono whitespace-pre-wrap break-all">{rowFinding.evidence}</pre></div>}
      {sources.length > 0 && <div className="flex min-w-0 flex-wrap items-end gap-2"><label className="flex min-w-0 flex-1 flex-col gap-1 text-[var(--muted)]">{tr('database.row.source')}<select aria-label={tr('database.row.source')} title={source?.dump_path} value={source?.dump_id ?? ''} onChange={event => onSourceChange(Number(event.target.value) || null)} className="min-w-0 rounded border border-[var(--line)] bg-[var(--panel-2)] p-2 text-[var(--fg)]"><option value="" disabled>{tr('database.row.choose')}</option>{sources.map(item => <option key={item.dump_id} value={item.dump_id}>{item.dump_path}</option>)}</select></label>
        <Button disabled={!source || reveal.isPending} onClick={() => source && reveal.mutate(source.dump_path)}><FolderOpen size={13} />{tr('artifact.showInFileManager')}</Button></div>}
      {reveal.error && <p role="alert" className="text-[var(--danger-text)]">{reveal.error.message}</p>}
      {!sources.length && <p role="status">{tr('database.row.noSource')}</p>}
      {source?.rows === 0 ? <p role="status">{tr('review.emptyTable')}</p> : source && isPending && <p role="status">{tr('common.loading')}</p>}
      {error && <p role="alert" className="text-[var(--danger-text)]">{error.message}</p>}
      {data && <details open={!rowFinding || !matches.length} className="rounded-lg border border-[var(--line)]"><summary className="cursor-pointer bg-[var(--panel-2)] px-3 py-2 font-semibold">{tr('database.row.details')}</summary>
        {data.truncated && <p role="status" className="p-3 text-[var(--warn)]">{tr('database.row.truncated')}</p>}
        <dl>{details.map((column) => {
          const index = column.index ?? data.columns.indexOf(column)
          return <div key={index} className="border-t border-[var(--line)] p-3"><dt className="mono mb-2 break-all font-medium">{column.name}</dt><dd>
            <div className="mb-2 flex gap-2">{column.value != null && <CopyButton value={column.value} label={column.truncated ? tr('database.row.copyVisible') : tr('review.copyValue')} />}<Button disabled={!canExpand} onClick={() => setExpandedColumn(index)}><Expand size={13} />{tr('database.row.expandField')}</Button></div>
            <pre className="mono whitespace-pre-wrap break-all">{column.value ?? 'NULL'}</pre>{column.truncated && <span className="text-[var(--warn)]">{tr('database.row.valueTruncated')}</span>}
          </dd></div>
        })}</dl>
      </details>}
      {data && !canExpand && data.columns.some(column => column.truncated) && <p role="status">{tr('database.row.unavailableField')}</p>}
    </div>
    {data && expandedColumn != null && <DatabaseField key={`${row}:${expandedColumn}:${data.record_version}`} slug={slug} record={data} columnIndex={expandedColumn} match={matches.find(item => item.column_index === expandedColumn)} finding={rowFinding} onClose={() => setExpandedColumn(null)} />}
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
