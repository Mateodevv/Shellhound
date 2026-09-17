import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, FolderClock, Plus, RefreshCw } from 'lucide-react'
import { api, patch, post, type EvidenceItem } from '../../api'
import type { BackupComparison, BackupHistoryData, BackupOverview, BackupSnapshot } from '../../backupApi'
import { useT } from '../../i18n'
import { Button, Card, Modal, Tag } from '../ui/ui'
import { SourceTimezone, sourceInput } from '../SourceTimezone'
import { BackupHistory, BackupStatus } from './BackupHistory'
import { FileViewer } from '../review/FileViewer'

function BackupEditor({ slug, evidence, overview, initial, onClose, onSaved }: {
  slug: string; evidence: EvidenceItem[]; overview: BackupOverview; initial?: BackupSnapshot; onClose: () => void; onSaved: () => void
}) {
  const tr = useT()
  const roots = evidence.filter(e => e.kind === 'webroot')
  const [site, setSite] = useState(initial?.site_id ?? overview.sites[0]?.id ?? 0)
  const [siteName, setSiteName] = useState('')
  const [evidenceId, setEvidenceId] = useState(initial?.evidence_id ?? roots[0]?.id ?? 0)
  const [root, setRoot] = useState(initial?.root ?? roots[0]?.path ?? '')
  const [label, setLabel] = useState(initial?.label ?? '')
  const [date, setDate] = useState(initial?.captured_at ?? '')
  const [zone, setZone] = useState(initial?.timezone ?? overview.sites[0]?.timezone ?? roots[0]?.source_timezone ?? 'auto')
  const [coverage, setCoverage] = useState(initial?.completeness ?? 'unknown')
  const [previewRoot, setPreviewRoot] = useState('')
  const preview = useQuery({ queryKey: ['backups', slug, 'root-preview', evidenceId, previewRoot], enabled: !!previewRoot,
    queryFn: () => post<{ paths: string[]; more: boolean; warning: boolean }>(`/api/cases/${slug}/backups/preview-root`, { evidence_id: evidenceId, root: previewRoot }), retry: false })
  const save = useMutation({ mutationFn: async () => {
    const siteId = site || (await post<{ id: number }>(`/api/cases/${slug}/backups/sites`, { label: siteName, timezone: zone })).id
    if (!site) setSite(siteId)
    const body = { site_id: siteId, evidence_id: evidenceId, root, label, captured_at: date, timezone: zone, completeness: coverage }
    return initial ? patch(`/api/cases/${slug}/backups/snapshots/${initial.id}`, body) : post(`/api/cases/${slug}/backups/snapshots`, body)
  }, onSuccess: onSaved })
  return <Modal open onClose={onClose} title={tr(initial ? 'backups.edit' : 'backups.add')}><form className="space-y-4" onSubmit={event => { event.preventDefault(); save.mutate() }}>
    <label className="flex flex-col gap-1 text-xs">{tr('backups.website')}<select className={sourceInput} value={site} onChange={event => { const id = Number(event.target.value); setSite(id); setZone(overview.sites.find(s => s.id === id)?.timezone ?? 'auto') }}><option value={0}>{tr('backups.newWebsite')}</option>{overview.sites.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}</select></label>
    {!site && <label className="flex flex-col gap-1 text-xs">{tr('backups.name')}<input required maxLength={120} className={sourceInput} value={siteName} onChange={event => setSiteName(event.target.value)} /></label>}
    <label className="flex flex-col gap-1 text-xs">{tr('backups.source')}<select className={sourceInput} value={evidenceId} onChange={event => { const id = Number(event.target.value); setEvidenceId(id); setRoot(roots.find(r => r.id === id)?.path ?? '') }}>{roots.map(e => <option key={e.id} value={e.id}>{e.label || e.path}</option>)}</select></label>
    <label className="flex flex-col gap-1 text-xs">{tr('backups.root')}<input required className={sourceInput} value={root} onChange={event => setRoot(event.target.value)} /></label>
    <Button type="button" onClick={() => { setPreviewRoot(root); if (previewRoot === root) preview.refetch() }}>{tr('backups.previewRoot')}</Button>
    {previewRoot === root && <>{preview.isFetching && <p role="status" className="text-xs">{tr('common.loading')}</p>}{preview.error && <p role="alert" className="text-xs text-[var(--review-text)]">{preview.error.message}</p>}{preview.data && <div className="rounded-lg bg-[var(--panel-2)] p-3 text-xs"><p className="mb-2 text-[var(--muted)]">{tr('backups.rootHelp')}</p>{preview.data.paths.map(path => <p className="mono break-all" key={path}>{path}</p>)}{!preview.data.paths.length && <p>{tr('backups.emptyRoot')}</p>}{preview.data.more && <p>…</p>}{preview.data.warning && <p className="text-[var(--review-text)]">{tr('backups.previewWarning')}</p>}</div>}</>}
    <label className="flex flex-col gap-1 text-xs">{tr('backups.label')}<input required maxLength={120} className={sourceInput} value={label} onChange={event => setLabel(event.target.value)} /></label>
    <div className="grid gap-3 sm:grid-cols-2"><label className="flex flex-col gap-1 text-xs">{tr('backups.date')}<input className={sourceInput} placeholder="2026-09-17T12:00:00" value={date} onChange={event => setDate(event.target.value)} /></label>
      <label className="flex flex-col gap-1 text-xs">{tr('backups.completeness')}<select className={sourceInput} value={coverage} onChange={event => setCoverage(event.target.value)}>{['unknown', 'complete', 'partial'].map(value => <option key={value} value={value}>{tr(`backups.${value}`)}</option>)}</select></label></div>
    <SourceTimezone value={zone} onChange={setZone} filesystem />
    <p className="text-xs text-[var(--muted)]">{tr('backups.dateHelp')}</p>
    {save.error && <p role="alert" className="text-sm text-[var(--danger-text)]">{save.error.message}</p>}
    <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>{tr('common.cancel')}</Button><Button type="submit" variant="primary" disabled={save.isPending}>{tr('common.save')}</Button></div>
  </form></Modal>
}

const params = () => new URLSearchParams(location.search)

export function BackupPanel({ slug, evidence }: { slug: string; evidence: EvidenceItem[] }) {
  const tr = useT()
  const qc = useQueryClient()
  const query = useQuery({ queryKey: ['backups', slug], queryFn: async () => {
    const result = await api<BackupOverview>(`/api/cases/${slug}/backups`)
    if (!Array.isArray(result?.sites) || !Array.isArray(result?.snapshots)) throw new Error(tr('backups.loadError'))
    return result
  }, retry: false, refetchInterval: 4000 })
  const [editing, setEditing] = useState<BackupSnapshot | 'new' | null>(null)
  const [siteId, setSiteId] = useState(Number(params().get('backup_site')) || 0)
  const [scope, setScope] = useState(params().get('backup_scope') || 'suspicious')
  const [search, setSearch] = useState(params().get('backup_search') || '')
  const [open, setOpen] = useState(!!params().get('backup_site'))
  const [page, setPage] = useState(0)
  const [selectedPath, setSelectedPath] = useState(params().get('backup_path') || '')
  const [viewing, setViewing] = useState('')
  const actualSite = siteId || query.data?.sites[0]?.id || 0
  const refresh = () => { qc.invalidateQueries({ queryKey: ['backups', slug] }); qc.invalidateQueries({ queryKey: ['jobs', slug] }); setEditing(null) }
  const prepare = useMutation({ mutationFn: (snapshot_ids?: number[]) => post(`/api/cases/${slug}/backups/prepare`, snapshot_ids ? { snapshot_ids } : {}), onSuccess: refresh })
  const comparison = useQuery({ queryKey: ['backups', slug, 'compare', actualSite, scope, search, page], enabled: open && !!actualSite,
    queryFn: () => api<BackupComparison>(`/api/cases/${slug}/backups/compare?${new URLSearchParams({ site_id: String(actualSite), scope, search, offset: String(page * 50), limit: '50' })}`), refetchInterval: 5000 })
  const selected = useQuery({ queryKey: ['backup-history', slug, actualSite, selectedPath], enabled: !!selectedPath && !!actualSite,
    queryFn: () => api<BackupHistoryData>(`/api/cases/${slug}/backups/history?${new URLSearchParams({ site_id: String(actualSite), path: selectedPath })}`), refetchInterval: 5000 })
  const selectPath = (path: string) => {
    const url = new URL(location.href)
    if (path) url.searchParams.set('backup_path', path)
    else for (const key of ['backup_path', 'backup_left', 'backup_right']) url.searchParams.delete(key)
    history.pushState(null, '', url)
    setSelectedPath(path)
  }
  useEffect(() => {
    const url = new URL(location.href)
    if (open && actualSite) { url.searchParams.set('backup_site', String(actualSite)); url.searchParams.set('backup_scope', scope); url.searchParams.set('backup_search', search) }
    else { for (const key of ['backup_site', 'backup_scope', 'backup_search']) url.searchParams.delete(key) }
    history.replaceState(null, '', url)
  }, [open, actualSite, scope, search])
  useEffect(() => {
    const restore = () => { setSiteId(Number(params().get('backup_site')) || 0); setScope(params().get('backup_scope') || 'suspicious'); setSearch(params().get('backup_search') || ''); setSelectedPath(params().get('backup_path') || ''); setOpen(!!params().get('backup_site')); setPage(0) }
    window.addEventListener('popstate', restore)
    return () => window.removeEventListener('popstate', restore)
  }, [])
  if (!evidence.some(e => e.kind === 'webroot')) return null
  return <Card className="space-y-4 p-4">
    <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="flex items-center gap-2 font-semibold"><FolderClock size={17} />{tr('backups.title')}</h2><p className="mt-1 text-xs text-[var(--muted)]">{tr('backups.help')}</p></div>
      <div className="flex flex-wrap gap-2"><Button disabled={!query.data} onClick={() => setEditing('new')}><Plus size={14} />{tr('backups.add')}</Button>
        {!!query.data?.snapshots.length && <Button disabled={prepare.isPending || query.data.snapshots.some(s => s.state === 'indexing')} onClick={() => prepare.mutate(undefined)}><RefreshCw size={14} />{tr(query.data.snapshots.some(s => s.generation) ? 'backups.refresh' : 'backups.prepare')}</Button>}</div></div>
    {query.isPending && <p role="status">{tr('common.loading')}</p>}
    {(query.error || prepare.error) && <p role="alert" className="text-sm text-[var(--danger-text)]">{(query.error || prepare.error)?.message}</p>}
    {query.error && <Button onClick={() => query.refetch()}>{tr('common.retry')}</Button>}
    {!!query.data?.snapshots.length && <>
      <div className="flex flex-wrap items-center gap-3"><label className="flex min-w-48 flex-1 flex-col gap-1 text-xs">{tr('backups.website')}<select className={sourceInput} value={actualSite} onChange={event => { setSiteId(Number(event.target.value)); setPage(0) }}>{query.data.sites.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}</select></label><Button variant="primary" onClick={() => setOpen(v => !v)}>{tr('backups.compare')}<ArrowRight size={14} /></Button></div>
      <div className="flex flex-wrap gap-2">{query.data.snapshots.filter(s => s.site_id === actualSite).map(snapshot => <button key={snapshot.id} onClick={() => setEditing(snapshot)} className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 text-left text-xs"><strong>{snapshot.label}</strong><span className="ml-2 text-[var(--muted)]">{snapshot.captured_at || tr('sourceTime.unknown')}</span><p className="mt-1 text-[var(--muted)]">{snapshot.state === 'indexing' ? tr('backups.preparing') : ['stale', 'unavailable'].includes(snapshot.state) ? tr(`backups.${snapshot.state}`) : snapshot.stats.prepared || tr('backups.unprepared')}</p>{snapshot.stats.error && <p className="mt-1 text-[var(--review-text)]">{snapshot.stats.error}</p>}</button>)}</div>
      {query.data.snapshots.filter(s => s.site_id === actualSite && ['stale', 'partial', 'unavailable'].includes(s.state)).map(snapshot => <div key={snapshot.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-[var(--review-bg)] p-2 text-xs text-[var(--review-text)]"><span>{snapshot.label}: {snapshot.stats.unavailable ? tr('backups.unreadableCount', { n: snapshot.stats.unavailable }) : tr('backups.stale')}</span><Button disabled={prepare.isPending} onClick={() => prepare.mutate([snapshot.id])}>{tr('common.retry')}</Button></div>)}
    </>}
    {open && actualSite > 0 && <div className="space-y-3 border-t border-[var(--line)] pt-4">
      <div className="flex flex-wrap gap-2">{['suspicious', 'changes', 'all'].map(value => <Button key={value} variant={scope === value ? 'primary' : 'default'} onClick={() => { setScope(value); setPage(0) }}>{tr(`backups.${value}`)}</Button>)}<input aria-label={tr('backups.search')} placeholder={tr('backups.search')} className={`${sourceInput} flex-1`} value={search} onChange={event => { setSearch(event.target.value); setPage(0) }} /></div>
      {comparison.isPending && <p role="status">{tr('common.loading')}</p>}
      {comparison.error && <p role="alert">{comparison.error.message}</p>}
      {comparison.error && <Button onClick={() => comparison.refetch()}>{tr('common.retry')}</Button>}
      {comparison.data && <>
        <p className="text-xs text-[var(--muted)]">{tr('backups.results', { n: comparison.data.total })}</p>
        {!comparison.data.rows.length && <p className="py-4 text-sm text-[var(--muted)]">{tr(comparison.data.prepared ? 'backups.noMatches' : 'backups.unprepared')}</p>}
        <div className="space-y-2">{comparison.data.rows.map(row => <button key={row.path} onClick={() => selectPath(row.path)} className="block w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 text-left hover:border-[var(--accent)]"><p className="mono break-all text-sm">{row.path}</p><div className="mt-2 flex flex-wrap gap-x-5 gap-y-2">{row.entries.map(entry => <div key={entry.snapshot.id} className="min-w-32 text-xs"><p className="mb-1 text-[var(--muted)]">{entry.snapshot.label}</p><BackupStatus entry={entry} />{entry.file?.sha256 && <p className="mono mt-1 text-[10px] text-[var(--muted)]">{entry.file.sha256.slice(0, 12)}</p>}</div>)}</div></button>)}</div>
        {comparison.data.total > 50 && <div className="flex justify-end gap-2"><Button disabled={!page} onClick={() => setPage(v => v - 1)}>{tr('backups.previous')}</Button><Tag>{page + 1} / {Math.ceil(comparison.data.total / 50)}</Tag><Button disabled={(page + 1) * 50 >= comparison.data.total} onClick={() => setPage(v => v + 1)}>{tr('backups.next')}</Button></div>}
      </>}
    </div>}
    {editing && query.data && <BackupEditor slug={slug} evidence={evidence} overview={query.data} initial={editing === 'new' ? undefined : editing} onClose={() => setEditing(null)} onSaved={refresh} />}
    {selectedPath && <Modal open onClose={() => selectPath('')} title={tr('backups.history')}>{selected.isPending && <p role="status">{tr('common.loading')}</p>}{selected.error && <><p role="alert">{selected.error.message}</p><Button onClick={() => selected.refetch()}>{tr('common.retry')}</Button></>}{selected.data && <BackupHistory key={`${slug}:${actualSite}:${selectedPath}`} slug={slug} data={selected.data} onOpenFile={setViewing} persist />}</Modal>}
    {viewing && <FileViewer slug={slug} path={viewing} focusLine={null} onClose={() => setViewing('')} />}
  </Card>
}
