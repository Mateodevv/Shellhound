import { useState, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, LoaderCircle, Radar, Search, Upload } from 'lucide-react'
import { post, type Ioc } from '../api'
import { useT } from '../i18n'
import { useOpenCti, useOpenCtiSettings, openCtiKey, safeCtiUrl, initialExportOptions, type OpenCtiLookup, type OpenCtiReference, type OpenCtiPreview, type OpenCtiOptions, type OpenCtiEnrichmentPreview } from '../opencti'
import { Button, Card, Modal, Tag, Tabs } from './ui'
import { CtiError } from './CaseProfile'
import { OpenCtiExportDialog } from './OpenCtiExport'
import { IocTag } from './IocTags'
import { InfoDot } from './Tooltip'
import { SelectColumn } from './OpenCtiSelection'
import { iocCategories, inIocCategory, selectBatch, selectionTable, selectionHead } from './ctiSelectionModel'

export function OpenCtiScore({ lookup, loading, error }: { lookup?: OpenCtiLookup; loading?: boolean; error?: boolean }) {
  const tr = useT()
  const scored = lookup?.entities?.filter(entity => typeof entity.score === 'number' && Number.isFinite(entity.score) && entity.score >= 0 && entity.score <= 100) ?? []
  return <div className="min-w-0 space-y-2 py-3">
    <div className="flex items-center gap-2 font-semibold">{tr('cti.scoreTitle')}<InfoDot body={<>{tr('cti.scoreDescription')}{lookup?.checked_at && <span className="mt-2 block">{tr('cti.cached', { at: lookup.checked_at })}</span>}</>} /></div>
    <div className="flex flex-wrap items-center gap-2">
      {scored.map(entity => <span key={entity.id} className="inline-flex items-center gap-2">
        {scored.length > 1 && <span className="break-all text-[12px]">{entity.name || entity.type}</span>}
        <span className="rounded px-2 py-1 text-[11px] font-medium tabular-nums" style={{ background: 'var(--review-soft)', color: 'var(--review-text)' }}>{entity.score} / 100</span>
      </span>)}
      {!scored.length && <span className="text-[var(--muted)]">{tr(loading ? 'common.loading' : error || lookup?.status === 'error' ? 'cti.scoreUnavailable' : !lookup ? 'cti.unchecked' : 'cti.noScore')}</span>}
      {lookup?.stale && <Tag tone="warn">{tr('cti.stale')}</Tag>}
      {(error || lookup?.status === 'error') && scored.length > 0 && <span className="text-[var(--danger-text)]">{tr('cti.scoreUnavailable')}</span>}
    </div>
  </div>
}

export function OpenCtiStatus({ lookup, sync, onClick, value }: { lookup?: OpenCtiLookup; sync?: string; onClick: () => void; value: string }) {
  const tr = useT()
  return <button type="button" aria-label={tr('cti.inspect', { value })} onClick={onClick} className="flex shrink-0 cursor-pointer items-center gap-1 rounded border border-[var(--line)] px-1.5 py-1 text-[10px] text-[var(--muted)] hover:border-[var(--accent)]">
    <Radar size={12} />{tr(lookup?.stale ? 'cti.stale' : `cti.${lookup?.status ?? 'unchecked'}`)}{sync && <span> · {tr(`cti.${sync}`)}</span>}
  </button>
}
function ReferenceList({ title, items }: { title: string; items?: (string | OpenCtiReference)[] }) {
  const tr = useT()
  if (!items?.length) return null
  const name = (item: OpenCtiReference) => item.name || item.observable_value || item.value || item.source_name || item.external_id || item.description || item.id || ''
  return <div><h4 className="font-semibold">{title}</h4><ul className="list-inside list-disc">{items.map((item, index) => {
    const label = typeof item === 'string' ? item : item.relationship_type ? [item.from && name(item.from), item.relationship_type, item.to && name(item.to)].filter(Boolean).join(' → ') : name(item)
    const href = typeof item === 'string' ? undefined : safeCtiUrl(item.url)
    return <li key={index}>{href ? <a href={href} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-text)] hover:underline">{label}</a> : label}
      {typeof item !== 'string' && item.createdBy && <span className="ml-2 text-[var(--muted)]">{tr('cti.sourceAuthor', { name: name(item.createdBy) })}</span>}
    </li>
  })}</ul></div>
}
export function OpenCtiDetails({ lookup }: { lookup?: OpenCtiLookup }) {
  const tr = useT()
  return <div className="flex flex-col gap-3 text-[12px]">
    <p className="text-[var(--muted)]">{tr('cti.localOnly')}</p>
    <Tag tone={lookup?.status === 'error' ? 'danger' : undefined}>{tr(`cti.${lookup?.status ?? 'unchecked'}`)}</Tag>
    {lookup?.stale && <Tag tone="warn">{tr('cti.stale')}</Tag>}
    {lookup?.checked_at && <p>{tr('cti.cached', { at: lookup.checked_at })}</p>}
    <CtiError error={lookup?.error} />
    {lookup?.entities?.map((entity) => <Card key={entity.id} className="flex flex-col gap-2 p-3">
      <div className="flex flex-wrap items-center gap-2"><strong className="break-all">{entity.name}</strong><Tag>{entity.type}</Tag>
        {entity.score != null && <Tag>{tr('cti.score', { n: entity.score })}</Tag>}{entity.confidence != null && <Tag>{tr('cti.confidence', { n: entity.confidence })}</Tag>}
      </div>
      {entity.description && <p className="whitespace-pre-wrap break-words">{entity.description}</p>}
      {entity.first_seen && <p className="text-[var(--muted)]">{tr('cti.entityTime', { label: tr('cti.firstSeen'), at: entity.first_seen })}</p>}
      {entity.last_seen && <p className="text-[var(--muted)]">{tr('cti.entityTime', { label: tr('cti.lastSeen'), at: entity.last_seen })}</p>}
      {entity.created_at && <p className="text-[var(--muted)]">{tr('cti.entityTime', { label: tr('cti.createdAt'), at: entity.created_at })}</p>}
      {entity.updated_at && <p className="text-[var(--muted)]">{tr('cti.entityTime', { label: tr('cti.updatedAt'), at: entity.updated_at })}</p>}
      {!!entity.labels?.length && <div className="flex flex-wrap gap-1">{entity.labels.map((item, index) => <IocTag key={index} value={typeof item === 'string' ? item : item.value} />)}</div>}
      <ReferenceList title={tr('cti.sources')} items={entity.sources} /><ReferenceList title={tr('cti.reports')} items={entity.reports} />
      <ReferenceList title={tr('cti.malware')} items={entity.malware} /><ReferenceList title={tr('cti.relationships')} items={entity.relationships} />
      {safeCtiUrl(entity.url) && <a href={safeCtiUrl(entity.url)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-[var(--accent-text)] hover:underline"><ExternalLink size={12} />{tr('cti.open')}</a>}
    </Card>)}
    <p className="text-[var(--muted)]">{tr('cti.opinion')}</p>
  </div>
}

export function OpenCtiToolbar({ slug, iocs, selectedIds, onSelectAll, onClear, mode = 'full', actionScope = 'selection', leadingAction }: {
  slug: string; iocs: Ioc[]; selectedIds: number[]; onSelectAll: () => void; onClear: () => void; onSettings: () => void
  mode?: 'full' | 'actions' | 'activity' | 'inline'
  actionScope?: 'selection' | 'case'
  leadingAction?: ReactNode
}) {
  const tr = useT()
  const qc = useQueryClient()
  const conf = useOpenCtiSettings()
  const status = useOpenCti(slug)
  const actionIds = actionScope === 'case' ? iocs.map(ioc => ioc.id) : selectedIds
  const inline = mode === 'inline'
  const [preview, setPreview] = useState<{ data: OpenCtiPreview; options: OpenCtiOptions } | null>(null)
  const [enrichment, setEnrichment] = useState<{ data: OpenCtiEnrichmentPreview; ids: number[] } | null>(null)
  const [queued, setQueued] = useState(false)
  const refreshed = () => { setQueued(true); qc.invalidateQueries({ queryKey: openCtiKey(slug) }); qc.invalidateQueries({ queryKey: ['jobs', slug] }) }
  const lookup = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/lookup`, { ioc_ids: actionIds }), onSuccess: refreshed })
  const prepare = useMutation({ mutationFn: async () => {
    const options = initialExportOptions(actionIds)
    return { options, data: await post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, options) }
  }, onSuccess: setPreview })
  const prepareEnrichment = useMutation({ mutationFn: async () => ({ ids: [...actionIds], data: await post<OpenCtiEnrichmentPreview>(`/api/cases/${slug}/opencti/enrichment/preview`, { ioc_ids: actionIds }) }), onSuccess: setEnrichment })
  const retry = useMutation({ mutationFn: (export_id: string) => post(`/api/cases/${slug}/opencti/retry`, { export_id }), onSuccess: refreshed })
  const refreshEnrichment = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/enrichment/status`, {}), onSuccess: refreshed })
  const busy = lookup.isPending || prepare.isPending || prepareEnrichment.isPending
  const ready = !!conf.data?.configured && actionIds.length > 0 && !busy
  const recentJobs = status.data?.jobs?.slice(0, 8) ?? []
  const scopeHint = actionScope === 'case' ? tr('cti.caseScope', { n: actionIds.length }) : undefined
  const checkLabel = tr(actionScope === 'case' ? 'cti.checkAll' : 'cti.check')
  const exportLabel = tr(actionScope === 'case' ? 'cti.exportAll' : 'cti.export')
  const enrichLabel = tr(actionScope === 'case' ? 'cti.enrichAll' : 'cti.enrich')
  if (!conf.data?.configured) return <>{leadingAction}</>
  const Container = inline ? 'div' : Card
  return <Container className={inline ? 'flex min-w-0 max-w-full flex-col gap-2' : 'flex flex-col gap-3 border-[var(--accent)]/30 p-3'}>
    {mode !== 'activity' && <><div className="flex flex-wrap items-center gap-2">{leadingAction}{!inline && <strong className="mr-auto text-[13px]">{tr('cti.title')}</strong>}
      <Button type="button" disabled={!ready} aria-label={checkLabel} title={scopeHint} onClick={() => { setQueued(false); lookup.mutate() }}>{lookup.isPending ? <LoaderCircle size={13} className="animate-spin" /> : <Search size={13} />}{checkLabel}</Button>
      <Button type="button" disabled={!ready} aria-label={exportLabel} title={scopeHint} onClick={() => prepare.mutate()}>{prepare.isPending ? <LoaderCircle size={13} className="animate-spin" /> : <Upload size={13} />}{exportLabel}</Button>
      <Button type="button" disabled={!ready} aria-label={enrichLabel} title={scopeHint} onClick={() => prepareEnrichment.mutate()}>{prepareEnrichment.isPending ? <LoaderCircle size={13} className="animate-spin" /> : <Radar size={13} />}{enrichLabel}</Button>
    </div>
    {!inline && <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--muted)]"><span>{actionIds.length} {tr('iocWorkspace.ioc_entries_in_this_action')}</span>
      {mode === 'full' && <><Button variant="ghost" onClick={onSelectAll} disabled={selectedIds.length === iocs.length}>{tr('cti.all')}</Button><Button variant="ghost" onClick={onClear} disabled={!selectedIds.length}>{tr('cti.clear')}</Button></>}
    </div>}</>}
    <CtiError error={conf.error || lookup.error || prepare.error || prepareEnrichment.error || retry.error || refreshEnrichment.error || status.error} />
    {queued && <p role="status" className="text-[12px] text-[var(--muted)]">{tr(inline ? 'cti.queuedActivity' : 'cti.queued')}</p>}
    {(mode === 'full' || mode === 'activity') && <>
    {!!recentJobs.length && <details open={recentJobs.some((job) => ['queued', 'running'].includes(job.state))} className="text-[12px]"><summary className="cursor-pointer font-semibold">{tr('cti.jobs')}</summary>
      <div className="mt-2 flex flex-col gap-1">{recentJobs.map((job) => <div key={job.id} className="flex flex-wrap gap-2"><Tag tone={job.state === 'failed' ? 'danger' : undefined}>{job.state}</Tag><span>{job.kind}</span><span>{job.message}</span>{job.error && <CtiError error={job.error} />}</div>)}</div>
    </details>}
    {!!status.data?.enrichments?.length && <details open className="text-[12px]"><summary className="cursor-pointer font-semibold">{tr('cti.connectorJobs')}</summary>
      <div className="mt-2 flex flex-col gap-2">{status.data.enrichments.map((entry) => <div key={entry.id} className="flex flex-wrap items-center gap-2">
        <Tag tone={['error', 'failed'].includes(entry.state) ? 'danger' : undefined}>{entry.state}</Tag>
        <span className="mono max-w-72 truncate" title={iocs.find((ioc) => ioc.id === entry.ioc_id)?.value}>{iocs.find((ioc) => ioc.id === entry.ioc_id)?.value}</span>
        <span title={entry.connector_id}>{entry.connector_name || tr('cti.connectorJob', { id: entry.connector_id.slice(0, 8) })}</span><span className="text-[var(--muted)]">{entry.updated}</span>
        {safeCtiUrl(entry.url) && <a href={safeCtiUrl(entry.url)} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-text)] hover:underline">{tr('cti.openJob')}</a>}<CtiError error={entry.error} />
      </div>)}<div><Button disabled={refreshEnrichment.isPending || !conf.data?.configured} onClick={() => refreshEnrichment.mutate()}>{tr('cti.refreshEnrichment')}</Button></div></div>
    </details>}
    {!!status.data?.exports?.length && <details className="text-[12px]"><summary className="cursor-pointer text-[var(--muted)]">{tr('cti.exportHistory')}</summary><div className="mt-2 flex flex-col gap-2">{status.data.exports.map((entry) => <div key={entry.id} className="flex flex-wrap items-center gap-2">
      <Tag>{entry.state}</Tag><span>{entry.updated || entry.created}</span><CtiError error={entry.error} />
      {['failed', 'partial', 'error', 'pending', 'paused'].includes(entry.state) && <Button disabled={retry.isPending} onClick={() => retry.mutate(entry.id)}>{tr('cti.retry')}</Button>}
      <TransferReceiptDetails stats={entry.stats} />
    </div>)}</div></details>}
    </>}
    {preview && <OpenCtiExportDialog slug={slug} initial={preview.data} initialOptions={preview.options} onClose={() => setPreview(null)} onQueued={() => { setPreview(null); refreshed() }} />}
    {enrichment && <EnrichmentDialog slug={slug} data={enrichment.data} ids={enrichment.ids} onClose={() => setEnrichment(null)} onQueued={() => { setEnrichment(null); refreshed() }} />}
  </Container>
}

function TransferReceiptDetails({ stats }: { stats: Record<string, unknown> }) {
  const tr = useT()
  const batches = (Array.isArray(stats?.batches) ? stats.batches : []) as { state: string; ids: string[]; work_id?: string; status?: { success_count?: number; failure_count?: number; pending_count?: number } }[]
  const samples = (Array.isArray(stats?.samples) ? stats.samples : []) as { id: string; display_path: string; state: string }[]
  const descriptions = (Array.isArray(stats?.descriptions) ? stats.descriptions : []) as { source_id: string; state: string; error?: string }[]
  if (!batches.length && !samples.length && !descriptions.length) return null
  return <details className="w-full rounded border border-[var(--line)] p-2"><summary className="cursor-pointer">{tr('cti.transferDetails')}</summary>
    <div className="mt-2 flex flex-col gap-2">{batches.map((batch, index) => <div key={index}>
      <p>{tr('cti.batch', { n: index + 1, count: batch.ids?.length ?? 0 })} · {batch.state}</p>
      {batch.status && <p className="text-[var(--muted)]">{tr('cti.batchCounts', { done: batch.status.success_count ?? 0, failed: batch.status.failure_count ?? 0, pending: batch.status.pending_count ?? 0 })}</p>}
      {batch.work_id && <p className="break-all text-[var(--muted)]">{tr('cti.workId')}: <code>{batch.work_id}</code></p>}
    </div>)}{samples.map((sample) => <p key={sample.id}>{sample.display_path} · {sample.state}</p>)}
    {!!descriptions.length && <p>{tr('cti.descriptionCounts', { done: descriptions.filter((d) => d.state === 'complete').length, total: descriptions.length })}</p>}
    {descriptions.filter((d) => d.error).map((d) => <p key={d.source_id} className="text-[var(--warn)]">{d.error}</p>)}
    </div>
  </details>
}

function EnrichmentDialog({ slug, data, ids, onClose, onQueued }: { slug: string; data: OpenCtiEnrichmentPreview; ids: number[]; onClose: () => void; onQueued: () => void }) {
  const tr = useT()
  const [tab, setTab] = useState('all')
  const [selectedIds, setSelectedIds] = useState(() => data.entities.filter(entity => ids.includes(entity.ioc_id)).map(entity => entity.ioc_id))
  const [connectors, setConnectors] = useState<string[]>([])
  const [createMissing, setCreateMissing] = useState(false)
  const included = data.entities.filter(entity => selectedIds.includes(entity.ioc_id))
  const visible = data.entities.filter(entity => inIocCategory(entity.type, tab))
  const missing = included.filter(entity => entity.requires_creation)
  const needsTransfer = included.some((entity) => entity.requires_transfer)
  const available = data.connectors.filter((connector) => connector.active)
  const run = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/enrich`, { ioc_ids: selectedIds, connector_ids: connectors, create_missing: createMissing }), onSuccess: onQueued })
  return <Modal open title={tr('cti.enrichPreview')} onClose={onClose} contained bodyClassName="overflow-hidden px-5 py-4"><div className="flex h-full min-h-0 flex-col gap-3 text-[12px]">
    <p className="shrink-0">{tr('cti.enrichBody')}</p>
    <div className="shrink-0 space-y-1 [&_[role=tab]]:shrink-0 [&_[role=tab]]:whitespace-nowrap">
    <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={iocCategories.map(id => ({ id, label: tr(`cti.category.${id}`), badge: <span className="ml-1 text-[10px]">{data.entities.filter(entity => inIocCategory(entity.type, id)).length}</span> }))} /></div>
    <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={[{ id: 'connectors', label: tr('cti.connectors') }, ...(data.warnings.length ? [{ id: 'notices', label: tr('cti.notices'), badge: <span className="ml-2">{data.warnings.length}</span> }] : [])]} /></div></div>
    <div className="min-h-0 flex-1 overflow-hidden">
    <div hidden={tab !== 'notices'} role="tabpanel" aria-label={tr('cti.notices')} className="h-full overflow-y-auto [scrollbar-gutter:stable] space-y-2">{data.warnings.map(warning => <p key={warning} className="rounded border border-[var(--line)] p-3 text-[var(--review-text)]">{warning}</p>)}</div>
    <div hidden={!iocCategories.includes(tab)} role="tabpanel" aria-label={tr('cti.iocs')} className="h-full overflow-auto [scrollbar-gutter:stable]">
      <table className={selectionTable}><colgroup><col style={{ width: 44 }} /><col /><col style={{ width: 110 }} /><col style={{ width: '35%' }} /></colgroup>
        <thead className={selectionHead}><tr><th><SelectColumn label={tr('cti.iocs')} states={visible.map(entity => selectedIds.includes(entity.ioc_id))} onChange={checked => setSelectedIds(selectBatch(selectedIds, visible.map(entity => entity.ioc_id), checked))} /></th><th>{tr('iocTable.object')}</th><th>{tr('iocTable.type')}</th><th>{tr('cti.enrichmentStatus')}</th></tr></thead>
        <tbody>{visible.map(entity => <tr key={entity.ioc_id}><td><input type="checkbox" aria-label={tr('cti.selectIoc', { value: entity.value })} checked={selectedIds.includes(entity.ioc_id)} onChange={e => setSelectedIds(selectBatch(selectedIds, [entity.ioc_id], e.target.checked))} /></td><td className="mono break-all">{entity.value}</td><td><Tag>{entity.type}</Tag></td><td>{tr(entity.requires_transfer ? 'cti.transferRequired' : entity.requires_creation ? 'cti.missingObservable' : 'cti.existingObservable')}</td></tr>)}{!visible.length && <tr><td colSpan={4}>{tr('iocWorkspace.no_matching_objects')}</td></tr>}</tbody>
      </table>
    </div>
    <div hidden={tab !== 'connectors'} role="tabpanel" aria-label={tr('cti.connectors')} className="h-full overflow-y-auto [scrollbar-gutter:stable] ">
    <table className={selectionTable}><colgroup><col style={{ width: 44 }} /><col /><col /></colgroup><thead className={selectionHead}><tr><th><SelectColumn label={tr('cti.connectors')} states={available.map(connector => connectors.includes(connector.id))} onChange={checked => setConnectors(selectBatch(connectors, available.map(connector => connector.id), checked))} /></th><th>{tr('cti.connectors')}</th><th>{tr('cti.connectorScope')}</th></tr></thead><tbody>
      {available.map(connector => <tr key={connector.id}><td><input type="checkbox" aria-label={connector.name} checked={connectors.includes(connector.id)} onChange={e => setConnectors(selectBatch(connectors, [connector.id], e.target.checked))} /></td><td>{connector.name}{connector.auto && <span className="block text-[var(--review-text)]">{tr('cti.automatic')}</span>}</td><td>{connector.scope.join(', ')}</td></tr>)}
      {!available.length && <tr><td colSpan={3}>{tr('cti.noConnectors')}</td></tr>}
    </tbody></table></div>
    </div>
    <div className="shrink-0 space-y-2 border-t border-[var(--line)] pt-3">
    {!!missing.length && <div className="rounded-lg border border-[var(--line)] p-3"><p>{tr('cti.missingCount', { n: missing.length })}</p>
      <label className="mt-3 flex items-center gap-2"><input type="checkbox" checked={createMissing} onChange={(e) => setCreateMissing(e.target.checked)} />{tr('cti.createMissing')}</label>
    </div>}
    <CtiError error={run.error} />
    <div className="flex justify-end gap-2"><Button onClick={onClose}>{tr('common.cancel')}</Button><Button variant="primary" disabled={!selectedIds.length || needsTransfer || !connectors.length || (!!missing.length && !createMissing) || run.isPending} onClick={() => run.mutate()}>{tr('cti.startEnrich')}</Button></div>
    </div>
  </div></Modal>
}
