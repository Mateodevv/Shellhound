import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Check, FileText, Settings2, TriangleAlert } from 'lucide-react'
import { api, patch, post, type CaseDetail } from '../api'
import type { LogSettings, LogSource } from '../logApi'
import { useT } from '../i18n'
import { Button, Card, Modal, Tag } from './ui'
import { formatCount } from '../format'
import { useLogSources } from './useLogSources'

const inputClass = 'min-w-0 w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] text-[var(--fg)]'

export function LogImport({ slug, path, onClose, onDone }: { slug: string; path: string; onClose: () => void; onDone: () => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [label, setLabel] = useState('')
  const [page, setPage] = useState(0)
  const [timezone, setTimezone] = useState('')
  const [formats, setFormats] = useState<Record<string, string>>({})
  const preview = useQuery({ queryKey: ['log-preview', slug, path], queryFn: () => post<{ sources: (LogSource & { ambiguous: boolean; error: string })[]; formats: Record<string, string> }>(`/api/cases/${slug}/log-sources/preview`, { path }) })
  const save = useMutation({ mutationFn: () => post(`/api/cases/${slug}/log-sources/register`, { path, label, timezone, formats }),
    onSuccess: () => { qc.invalidateQueries(); onDone() } })
  return <Modal open onClose={onClose} title={tr('logEvidence.add')}>
    <div className="space-y-4">
      <p className="text-sm text-[var(--muted)]">{tr('logEvidence.previewHelp')}</p>
      <p className="mono break-all text-xs">{path}</p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.label')}<input className={inputClass} value={label} onChange={e => setLabel(e.target.value)} maxLength={120} /></label>
        <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.timezone')}<input className={inputClass} value={timezone} onChange={e => setTimezone(e.target.value)} placeholder="UTC / +02:00 / Europe/Berlin" /></label>
      </div>
      <p className="text-xs text-[var(--muted)]">{tr('logEvidence.timezoneHelp')}</p>
      {preview.isPending && <p role="status">{tr('logEvidence.discovering')}</p>}
      {preview.error && <p role="alert" className="text-[var(--danger-text)]">{preview.error.message}</p>}
      <div className="max-h-80 space-y-2 overflow-y-auto">
        {preview.data?.sources.slice(page * 100, (page + 1) * 100).map(source => <Card key={source.id} className="flex flex-wrap items-center gap-3 p-3">
          <FileText size={17} className="shrink-0 text-[var(--muted)]" />
          <div className="min-w-0 flex-1"><p className="mono break-all text-xs">{source.path}</p>
            <p className="mt-1 text-xs text-[var(--review-text)]">{source.error || (source.ambiguous ? tr('logEvidence.ambiguous') : source.format === 'text' ? tr('logEvidence.manual') : '')}</p>
          </div>
          <select aria-label={tr('logEvidence.formatFor', { name: source.path })} className={`${inputClass} w-full sm:w-auto sm:max-w-full`}
            value={formats[source.id] ?? 'auto'} onChange={e => setFormats({ ...formats, [source.id]: e.target.value })}>
            {Object.entries(preview.data!.formats).map(([value, name]) => <option key={value} value={value}>{value === 'auto' ? `${name} (${preview.data!.formats[source.format]})` : name}</option>)}
          </select>
        </Card>)}
      </div>
      {(preview.data?.sources.length ?? 0) > 100 && <div className="flex items-center justify-end gap-2 text-xs"><span>{tr('logEvidence.previewPage', { n: page + 1, total: Math.ceil(preview.data!.sources.length / 100) })}</span><Button disabled={!page} onClick={() => setPage(page - 1)}>{tr('logEvidence.previous')}</Button><Button disabled={(page + 1) * 100 >= preview.data!.sources.length} onClick={() => setPage(page + 1)}>{tr('logEvidence.next')}</Button></div>}
      {preview.data && !preview.data.sources.length && <p>{tr('logEvidence.emptyFolder')}</p>}
      {save.error && <p role="alert" className="text-[var(--danger-text)]">{save.error.message}</p>}
      <div className="flex justify-end gap-2"><Button onClick={onClose}>{tr('common.cancel')}</Button>
        <Button variant="primary" disabled={!preview.data?.sources.length || save.isPending} onClick={() => save.mutate()}>{tr('logEvidence.register')}<ArrowRight size={14} /></Button></div>
    </div>
  </Modal>
}

function SourceSettings({ slug, source, formats, onClose }: { slug: string; source: LogSource; formats: Record<string, string>; onClose: () => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [draft, setDraft] = useState<LogSettings>({ format: 'auto', timezone: '', label: '', server_root: '', webroot: '', ...source.settings })
  const info = useQuery({ queryKey: ['case', slug], queryFn: () => api<CaseDetail>(`/api/cases/${slug}`) })
  const save = useMutation({ mutationFn: () => patch(`/api/cases/${slug}/log-sources/${source.id}`, draft), onSuccess: () => { qc.invalidateQueries(); onClose() } })
  return <Modal open onClose={onClose} title={tr('logEvidence.settings')}><div className="space-y-4">
    <p className="mono break-all text-xs">{source.path}</p>
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.label')}<input className={inputClass} value={draft.label} onChange={e => setDraft({ ...draft, label: e.target.value })} /></label>
      <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.format')}<select className={inputClass} value={draft.format} onChange={e => setDraft({ ...draft, format: e.target.value })}>{Object.entries(formats).map(([value, name]) => <option key={value} value={value}>{name}</option>)}</select></label>
      <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.timezone')}<input className={inputClass} placeholder="UTC / +02:00 / Europe/Berlin" value={draft.timezone} onChange={e => setDraft({ ...draft, timezone: e.target.value })} /></label>
    </div>
    <p className="text-xs text-[var(--muted)]">{tr('logEvidence.timezoneHelp')}</p>
    <details className="rounded-lg border border-[var(--line)] p-3"><summary className="cursor-pointer text-sm font-medium">{tr('logEvidence.mapping')}</summary>
      <p className="my-3 text-xs text-[var(--muted)]">{tr('logEvidence.mappingHelp')}</p>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2"><label className="flex flex-col gap-1 text-xs">{tr('logEvidence.serverRoot')}<input className={inputClass} value={draft.server_root} onChange={e => setDraft({ ...draft, server_root: e.target.value })} placeholder="/var/www/site" /></label>
        <label className="flex flex-col gap-1 text-xs">{tr('logEvidence.evidenceRoot')}<select className={inputClass} value={draft.webroot} onChange={e => setDraft({ ...draft, webroot: e.target.value })}><option value="">{tr('logEvidence.noMapping')}</option>{info.data?.evidence_items.filter(e => e.kind === 'webroot').map(e => <option key={e.id} value={e.path}>{e.label || e.path}</option>)}</select></label></div>
    </details>
    <p className="text-xs text-[var(--review-text)]">{tr('logEvidence.settingsReindex')}</p>
    {save.error && <p role="alert" className="text-[var(--danger-text)]">{save.error.message}</p>}
    <div className="flex justify-end"><Button variant="primary" disabled={save.isPending} onClick={() => save.mutate()}>{tr('common.save')}</Button></div>
  </div></Modal>
}

export function LogSourceList({ slug, family, onInspect }: { slug: string; family?: string; onInspect?: (id: string) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const query = useLogSources(slug)
  const [editing, setEditing] = useState<LogSource | null>(null)
  const run = useMutation({ mutationFn: (id: string) => post(`/api/cases/${slug}/log-sources/analyze`, { source_ids: [id] }), onSuccess: () => qc.invalidateQueries() })
  const accept = useMutation({ mutationFn: (id: string) => post(`/api/cases/${slug}/log-sources/${id}/accept-warning`), onSuccess: () => qc.invalidateQueries() })
  const rows = query.data?.sources.filter(s => (!family || s.family === family)) ?? []
  return <div className="space-y-2">
    {query.isPending && <p role="status">{tr('common.loading')}</p>}
    {query.error && <p role="alert" className="text-[var(--danger-text)]">{query.error.message}</p>}
    {rows.map(source => <Card key={source.id} className="p-3">
      <div className="flex flex-wrap items-center gap-2">
        <FileText size={15} className="text-[var(--muted)]" />
        <button className="min-w-0 flex-1 break-all text-left text-sm font-medium hover:text-[var(--accent)]" disabled={!onInspect} onClick={() => onInspect?.(source.id)}>{source.settings.label || source.path.replace(/\\/g, '/').split('/').pop()}</button>
        <Tag>{query.data!.formats[source.format]}</Tag>
        {source.family !== 'access' && <span className="text-xs text-[var(--muted)]">{tr('logEvidence.entries', { n: formatCount(source.stats.events ?? 0) })}</span>}
        <Button aria-label={tr('logEvidence.settingsFor', { name: source.path })} onClick={() => setEditing(source)}><Settings2 size={14} /></Button>
        {source.family !== 'access' && <Button disabled={run.isPending || source.state === 'indexing'} onClick={() => run.mutate(source.id)}>{tr(source.fresh ? 'logEvidence.recheck' : 'logEvidence.retry')}</Button>}
      </div>
      {source.family === 'access' && <p className="mt-2 text-xs text-[var(--muted)]">{tr('logEvidence.accessShared')}</p>}
      {!source.fresh && <p className="mt-2 flex items-center gap-2 text-xs text-[var(--review-text)]"><TriangleAlert size={13} />{tr(source.state === 'new' ? 'logEvidence.notIndexed' : 'logEvidence.stale')}</p>}
      {!!source.stats.undated && <p className="mt-2 text-xs text-[var(--muted)]">{tr('logEvidence.undatedCount', { n: formatCount(source.stats.undated) })}</p>}
      {source.warning && <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg bg-[var(--panel-2)] p-2 text-xs">
        {source.accepted ? <Check size={14} className="text-[var(--ok)]" /> : <TriangleAlert size={14} className="text-[var(--review-text)]" />}
        <span className="min-w-0 flex-1">{source.warning}</span>
        {source.accepted ? <Tag>{tr('logEvidence.accepted')}</Tag> : <Button disabled={accept.isPending} onClick={() => accept.mutate(source.id)}>{tr('logEvidence.accept')}</Button>}
      </div>}
    </Card>)}
    {(run.error || accept.error) && <p role="alert" className="text-[var(--danger-text)]">{(run.error || accept.error)?.message}</p>}
    {editing && <SourceSettings key={editing.id} slug={slug} source={editing} formats={query.data?.formats ?? {}} onClose={() => setEditing(null)} />}
  </div>
}
