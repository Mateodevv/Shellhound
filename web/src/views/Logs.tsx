import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, ChevronLeft, ChevronRight, FileText, Search, TriangleAlert } from 'lucide-react'
import { post } from '../api'
import type { Navigate } from '../App'
import type { LogEvent, LogSearch } from '../logApi'
import { useT } from '../i18n'
import { formatCount } from '../format'
import { Button, Card, EmptyState, Modal, Section } from '../components/ui/ui'
import { LogSourceList } from '../components/logview/LogSources'
import { useLogSources } from '../components/logview/useLogSources'
import { AccessLogs } from './AccessLogs'
import { FileViewer } from '../components/review/FileViewer'
import { LogEntryContext } from '../components/logview/LogEntryContext'

const FAMILIES = ['access', 'error', 'ftp', 'malware', 'text'] as const
const fieldClass = 'min-w-0 w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px]'
const eventTime = (event: LogEvent) => event.epoch == null ? event.raw_time : new Date(event.epoch * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC')

export function Logs({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const url = new URL(location.href)
  const sourceQuery = useLogSources(slug)
  const requested = url.searchParams.get('section') || FAMILIES.find(f => sourceQuery.data?.sources.some(s => s.family === f)) || 'access'
  const family = FAMILIES.includes(requested as typeof FAMILIES[number]) ? requested : 'access'
  return <div className="logs-page flex min-h-0 flex-col gap-3">
    <Section title={tr('logEvidence.title')}
      right={<Button onClick={() => gotoView('evidence')}>{tr('logEvidence.add')}<ArrowRight size={14} /></Button>}>{null}</Section>
    <div className="flex flex-wrap gap-2" role="tablist" aria-label={tr('logEvidence.types')}>
      {FAMILIES.map(value => <button key={value} role="tab" aria-selected={family === value}
        className={`border-b-2 px-3 py-2 text-sm transition-colors ${family === value ? 'border-[var(--accent)] bg-[var(--review-soft)] text-[var(--accent)]' : 'border-[var(--line)] text-[var(--muted)] hover:text-[var(--fg)]'}`}
        onClick={() => gotoView('logs', { section: value })}>{tr(`logEvidence.family.${value}`)}
        {!!sourceQuery.data?.sources.filter(s => s.family === value).length && <span className="ml-2 text-xs opacity-70">{sourceQuery.data.sources.filter(s => s.family === value).length}</span>}</button>)}
    </div>
    {family === 'access' ? <AccessLogs slug={slug} gotoView={gotoView} /> : <EventBrowser key={`${slug}:${family}`} slug={slug} family={family} gotoView={gotoView} initialEvent={url.searchParams.get('event') || ''} />}
  </div>
}

function EventBrowser({ slug, family, gotoView, initialEvent }: { slug: string; family: string; gotoView: Navigate; initialEvent: string }) {
  const tr = useT()
  const qc = useQueryClient()
  const sources = useLogSources(slug)
  const [filters, setFilters] = useState<Record<string, string>>({})
  const [query, setQuery] = useState('')
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [open, setOpen] = useState<LogEvent | null>(null)
  const [note, setNote] = useState('')
  const [file, setFile] = useState<string | null>(null)
  useEffect(() => {
    if (query === search) return
    const timer = setTimeout(() => { setSearch(query); setOffset(0); setSelected(new Set()) }, 250)
    return () => clearTimeout(timer)
  }, [query, search])
  const body = useMemo(() => ({ family, ...filters, search, offset, limit: 100,
    from_epoch: filters.from ? Date.parse(filters.from + 'Z') / 1000 : undefined,
    to_epoch: filters.to ? Date.parse(filters.to + 'Z') / 1000 : undefined }), [family, filters, search, offset])
  const events = useQuery({ queryKey: ['log-events', slug, body], queryFn: () => post<LogSearch>(`/api/cases/${slug}/log-events/search`, body), refetchInterval: 5000 })
  const focused = useQuery({ queryKey: ['log-focus', slug, initialEvent], queryFn: () => post<LogSearch>(`/api/cases/${slug}/log-events/search`, { id: initialEvent }), enabled: !!initialEvent })
  useEffect(() => { if (focused.data?.rows[0]) setOpen(focused.data.rows[0]) }, [focused.data])
  const filter = (key: string, value: string) => { setFilters({ ...filters, [key]: value }); setOffset(0); setSelected(new Set()) }
  const visible = events.data?.rows ?? []
  const selectedRows = visible.filter(row => row.fresh && selected.has(row.id))
  const apply = useMutation({ mutationFn: () => post(`/api/cases/${slug}/log-events/apply`, { selections: selectedRows.map(e => ({ id: e.id, fingerprint: e.fingerprint })), note }),
    onSuccess: () => { setSelected(new Set()); setNote(''); qc.invalidateQueries() } })
  const registered = sources.data?.sources.filter(s => s.family === family) ?? []
  const operations = family === 'ftp' ? ['upload', 'download', 'login', 'delete', 'mkdir', 'rmdir', 'rename', 'observation']
    : family === 'malware' ? ['malware_detection', 'scan_warning', 'scan_result', 'scan_summary', 'observation']
      : ['web_error', 'observation']
  const outcomes = family === 'ftp' ? ['success', 'failed', 'incomplete']
    : family === 'malware' ? ['error', 'reported_detection', 'warning', 'reported_ok', 'reported_action', 'summary'] : ['error']
  return <div className="space-y-4">
    {family === 'text' && <p className="rounded-lg bg-[var(--review-soft)] p-3 text-sm text-[var(--review-text)]">{tr('logEvidence.manual')}</p>}
    <details className="rounded-xl border border-[var(--line)] bg-[var(--panel)] p-4" open={!visible.length}>
      <summary className="cursor-pointer text-sm font-semibold">{tr('logEvidence.sources')} · {registered.length}</summary>
      <div className="mt-3"><LogSourceList slug={slug} family={family} onInspect={id => filter('source_id', id)} /></div>
    </details>
    <Card className="space-y-3 p-4">
      <div className="flex items-center gap-2"><Search size={16} className="text-[var(--muted)]" /><input className={`${fieldClass} flex-1`} aria-label={tr('logEvidence.search')} placeholder={tr('logEvidence.search')} value={query} onChange={e => setQuery(e.target.value)} /></div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.source')}<select className={fieldClass} value={filters.source_id || ''} onChange={e => filter('source_id', e.target.value)}><option value="">{tr('logEvidence.allSources')}</option>{registered.map(s => <option key={s.id} value={s.id}>{s.settings.label || s.path}</option>)}</select></label>
        {(family === 'error' || family === 'ftp') && <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.ip')}<input className={fieldClass} value={filters.ip || ''} onChange={e => filter('ip', e.target.value)} /></label>}
        {family === 'ftp' && <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.account')}<input className={fieldClass} value={filters.account || ''} onChange={e => filter('account', e.target.value)} /></label>}
        {family !== 'text' && <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.path')}<input className={fieldClass} value={filters.path || ''} onChange={e => filter('path', e.target.value)} /></label>}
      </div>
      {family !== 'text' && <details><summary className="cursor-pointer text-xs text-[var(--muted)]">{tr('logEvidence.moreFilters')}</summary><div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {(['from', 'to'] as const).map(key => <label key={key} className="flex flex-col gap-1 text-xs">{tr(`logEvidence.${key}`)}<input type="datetime-local" className={fieldClass} value={filters[key] || ''} onChange={e => filter(key, e.target.value)} /></label>)}
        {(['operation', 'outcome'] as const).map(key => <label key={key} className="flex flex-col gap-1 text-xs">{tr(`logEvidence.${key}`)}<select className={fieldClass} value={filters[key] || ''} onChange={e => filter(key, e.target.value)}><option value="">{tr('logEvidence.all')}</option>{(key === 'operation' ? operations : outcomes).map(value => <option key={value} value={value}>{tr(`logEvidence.${key}.${value}`)}</option>)}</select></label>)}
      </div></details>}
    </Card>
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line)] p-4">
        <div><h3 className="font-semibold">{tr('logEvidence.results', { n: formatCount(events.data?.total ?? 0) })}</h3><p className="mt-1 text-xs text-[var(--muted)]">{tr('logEvidence.selectionHelp')}</p></div>
        <Button variant="primary" disabled={!selectedRows.length || apply.isPending || events.isFetching} onClick={() => apply.mutate()}>{tr('logEvidence.apply', { n: selectedRows.length })}<ArrowRight size={14} /></Button>
      </div>
      {!!selectedRows.length && <label className="flex flex-col gap-1 border-b border-[var(--line)] p-3 text-xs">{tr('logEvidence.note')}<input className={fieldClass} value={note} maxLength={2000} onChange={e => setNote(e.target.value)} /></label>}
      {apply.isSuccess && <p role="status" className="px-4 py-2 text-sm text-[var(--ok)]">{tr('logEvidence.added')} <button className="underline" onClick={() => gotoView('findings')}>{tr('logEvidence.viewFindings')}</button></p>}
      {(events.error || apply.error) && <p role="alert" className="p-4 text-[var(--danger-text)]">{(events.error || apply.error)?.message}</p>}
      {events.isPending && <p role="status" className="p-4">{tr('common.loading')}</p>}
      {!events.isPending && !events.error && !visible.length && <EmptyState icon={<FileText size={28} />} title={tr('logEvidence.noEntries')} sub={tr(registered.length ? 'logEvidence.noEntriesHelp' : 'logEvidence.noSourcesHelp')} />}
      {!!visible.length && <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-[var(--muted)]"><tr>
        <th className="p-3"><input type="checkbox" aria-label={tr('logEvidence.selectVisible')} checked={!!visible.filter(e => e.fresh).length && visible.filter(e => e.fresh).every(e => selected.has(e.id))} onChange={e => setSelected(new Set(e.target.checked ? visible.filter(e => e.fresh).map(e => e.id) : []))} /></th>
        <th className="p-3">{tr('logEvidence.time')}</th><th className="p-3">{tr('logEvidence.entry')}</th><th className="p-3">{tr('logEvidence.source')}</th>
      </tr></thead><tbody>{visible.map(event => <tr key={event.id} className="border-t border-[var(--line-soft)] hover:bg-[var(--panel-2)]">
        <td className="p-3"><input type="checkbox" aria-label={tr('logEvidence.selectEntry', { n: event.line, name: event.source_name })} checked={selected.has(event.id)} disabled={!event.fresh} onChange={e => { const next = new Set(selected); if (e.target.checked) next.add(event.id); else next.delete(event.id); setSelected(next) }} /></td>
        <td className="max-w-44 p-3 align-top tabular">{eventTime(event) || <span className="text-[var(--muted)]">{tr('logEvidence.undated')}</span>}{event.epoch == null && event.raw_time && <p className="text-[var(--review-text)]">{tr('logEvidence.unknownZone')}</p>}</td>
        <td className="min-w-60 max-w-lg p-3"><button className="w-full space-y-1 text-left" onClick={() => setOpen(event)}><p className={event.triage === 'confirmed' ? 'font-semibold text-[var(--danger-text)]' : (event.detection || event.outcome === 'warning' || (event.family === 'malware' && event.outcome === 'error')) ? 'font-semibold text-[var(--review-text)]' : 'font-medium'}>{event.triage === 'confirmed' && <span>{tr('logEvidence.confirmed')} · </span>}{tr(`logEvidence.operation.${event.operation}`)}{event.outcome && ` · ${tr(`logEvidence.outcome.${event.outcome}`)}`}</p><p className="mono break-all text-[var(--muted)]">{event.path || event.raw.slice(0, 200)}</p>{event.signature && <p className="text-[var(--muted)]">{event.signature}</p>}{(event.ip || event.account) && <p className="text-[var(--muted)]">{[event.ip || event.remote_host, event.account].filter(Boolean).join(' · ')}</p>}{!event.fresh && <p className="flex items-center gap-1 text-[var(--review-text)]"><TriangleAlert size={12} />{tr('logEvidence.stale')}</p>}</button></td>
        <td className="max-w-48 break-all p-3 text-[var(--muted)]">{event.source_name}:{event.line}</td>
      </tr>)}</tbody></table></div>}
      <div className="flex justify-end gap-2 border-t border-[var(--line)] p-3"><Button aria-label={tr('logEvidence.previous')} disabled={!offset} onClick={() => { setOffset(Math.max(0, offset - 100)); setSelected(new Set()) }}><ChevronLeft size={14} /></Button><Button aria-label={tr('logEvidence.next')} disabled={events.data?.next_offset == null} onClick={() => { setOffset(events.data!.next_offset!); setSelected(new Set()) }}><ChevronRight size={14} /></Button></div>
    </Card>
    {open && <Modal open onClose={() => setOpen(null)} title={tr('logEvidence.entry')}><LogEntryContext slug={slug} event={open} onFile={path => setFile(path)} />
      <div className="mt-4 flex flex-wrap gap-2"><Button onClick={() => gotoView('timeline', open.timeline_id ? { event: open.timeline_id } : {})}>{tr('logEvidence.timeline')}</Button>{open.ip && <Button onClick={() => { filter('ip', open.ip); setOpen(null) }}>{tr('logEvidence.sameIp')}</Button>}</div>
    </Modal>}
    <FileViewer slug={slug} path={file} onClose={() => setFile(null)} />
  </div>
}
