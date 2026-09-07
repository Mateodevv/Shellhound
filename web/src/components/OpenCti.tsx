import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, Radar, Search, Upload } from 'lucide-react'
import { post, type Ioc } from '../api'
import { useT } from '../i18n'
import { useOpenCti, useOpenCtiSettings, openCtiKey, safeCtiUrl, initialExportOptions, type OpenCtiLookup, type OpenCtiReference, type OpenCtiPreview, type OpenCtiOptions, type OpenCtiEnrichmentPreview } from '../opencti'
import { Button, Card, Modal, Tag } from './ui'
import { CaseProfileButton, CtiError } from './CaseProfile'
import { OpenCtiExportDialog } from './OpenCtiExport'

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
      {!!entity.labels?.length && <div className="flex flex-wrap gap-1">{entity.labels.map((item, index) => <Tag key={index}>{typeof item === 'string' ? item : item.value}</Tag>)}</div>}
      <ReferenceList title={tr('cti.sources')} items={entity.sources} /><ReferenceList title={tr('cti.reports')} items={entity.reports} />
      <ReferenceList title={tr('cti.malware')} items={entity.malware} /><ReferenceList title={tr('cti.relationships')} items={entity.relationships} />
      {safeCtiUrl(entity.url) && <a href={safeCtiUrl(entity.url)} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-[var(--accent-text)] hover:underline"><ExternalLink size={12} />{tr('cti.open')}</a>}
    </Card>)}
    <p className="text-[var(--muted)]">{tr('cti.opinion')}</p>
  </div>
}

export function OpenCtiToolbar({ slug, iocs, selectedIds, onSelectAll, onClear, onSettings }: {
  slug: string; iocs: Ioc[]; selectedIds: number[]; onSelectAll: () => void; onClear: () => void; onSettings: () => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const conf = useOpenCtiSettings()
  const status = useOpenCti(slug)
  const [preview, setPreview] = useState<{ data: OpenCtiPreview; options: OpenCtiOptions } | null>(null)
  const [enrichment, setEnrichment] = useState<{ data: OpenCtiEnrichmentPreview; ids: number[] } | null>(null)
  const [queued, setQueued] = useState(false)
  const refreshed = () => { setQueued(true); qc.invalidateQueries({ queryKey: openCtiKey(slug) }); qc.invalidateQueries({ queryKey: ['jobs', slug] }) }
  const lookup = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/lookup`, { ioc_ids: selectedIds }), onSuccess: refreshed })
  const prepare = useMutation({ mutationFn: async () => {
    const options = initialExportOptions(selectedIds)
    return { options, data: await post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, options) }
  }, onSuccess: setPreview })
  const prepareEnrichment = useMutation({ mutationFn: async () => ({ ids: [...selectedIds], data: await post<OpenCtiEnrichmentPreview>(`/api/cases/${slug}/opencti/enrichment/preview`, { ioc_ids: selectedIds }) }), onSuccess: setEnrichment })
  const retry = useMutation({ mutationFn: (export_id: string) => post(`/api/cases/${slug}/opencti/retry`, { export_id }), onSuccess: refreshed })
  const refreshEnrichment = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/enrichment/status`, {}), onSuccess: refreshed })
  const busy = lookup.isPending || prepare.isPending || prepareEnrichment.isPending
  const ready = !!conf.data?.configured && selectedIds.length > 0 && !busy
  const recentJobs = status.data?.jobs?.slice(0, 8) ?? []
  return <Card className="flex flex-col gap-3 border-[var(--accent)]/30 p-3">
    <div className="flex flex-wrap items-center gap-2"><strong className="mr-auto text-[13px]">{tr('cti.title')}</strong><CaseProfileButton slug={slug} />
      <Button disabled={!ready} onClick={() => { setQueued(false); lookup.mutate() }}><Search size={13} />{tr('cti.check')}</Button>
      <Button disabled={!ready} onClick={() => prepare.mutate()}><Upload size={13} />{tr('cti.export')}</Button>
      <Button disabled={!ready} onClick={() => prepareEnrichment.mutate()}><Radar size={13} />{tr('cti.enrich')}</Button>
    </div>
    <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--muted)]"><span>{tr('cti.scope', { n: selectedIds.length })}</span>
      <Button variant="ghost" onClick={onSelectAll} disabled={selectedIds.length === iocs.length}>{tr('cti.all')}</Button><Button variant="ghost" onClick={onClear} disabled={!selectedIds.length}>{tr('cti.clear')}</Button>
    </div>
    {conf.data && !conf.data.configured && <div className="flex items-center gap-2 text-[12px]"><span>{tr('cti.noConfig')}</span><Button variant="ghost" onClick={onSettings}>{tr('cti.setup')}</Button></div>}
    <CtiError error={conf.error || lookup.error || prepare.error || prepareEnrichment.error || retry.error || refreshEnrichment.error || status.error} />
    {queued && <p role="status" className="text-[12px] text-[var(--muted)]">{tr('cti.queued')}</p>}
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
    {preview && <OpenCtiExportDialog slug={slug} initial={preview.data} initialOptions={preview.options} onClose={() => setPreview(null)} onQueued={() => { setPreview(null); refreshed() }} />}
    {enrichment && <EnrichmentDialog slug={slug} data={enrichment.data} ids={enrichment.ids} onClose={() => setEnrichment(null)} onQueued={() => { setEnrichment(null); refreshed() }} />}
  </Card>
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
  const [connectors, setConnectors] = useState<string[]>([])
  const [createMissing, setCreateMissing] = useState(false)
  const missing = data.entities.filter((entity) => entity.requires_creation)
  const available = data.connectors.filter((connector) => connector.active)
  const run = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/enrich`, { ioc_ids: ids, connector_ids: connectors, create_missing: createMissing }), onSuccess: onQueued })
  return <Modal open title={tr('cti.enrichPreview')} onClose={onClose}><div className="flex flex-col gap-4 text-[12px]">
    <p>{tr('cti.enrichBody')}</p>{data.warnings.map((warning) => <p key={warning} className="text-[var(--warn)]">{warning}</p>)}
    {!!missing.length && <div className="rounded-lg border border-[var(--line)] p-3">{missing.map((entity) => <p key={entity.ioc_id} className="break-all">{tr('cti.creationRequired', { value: entity.value })}</p>)}
      <label className="mt-3 flex items-center gap-2"><input type="checkbox" checked={createMissing} onChange={(e) => setCreateMissing(e.target.checked)} />{tr('cti.createMissing')}</label>
    </div>}
    <fieldset className="flex flex-col gap-2"><legend className="mb-2 font-semibold">{tr('cti.connectors')}</legend>
      {!available.length && <p>{tr('cti.noConnectors')}</p>}{available.map((connector) => <label key={connector.id} className="flex items-start gap-2">
        <input type="checkbox" checked={connectors.includes(connector.id)} onChange={(e) => setConnectors(e.target.checked ? [...connectors, connector.id] : connectors.filter((id) => id !== connector.id))} />
        <span>{connector.name} · {connector.scope.join(', ')}{connector.auto && <span className="block text-[var(--warn)]">{tr('cti.automatic')}</span>}</span>
      </label>)}
    </fieldset><CtiError error={run.error} />
    <div className="flex justify-end gap-2"><Button onClick={onClose}>{tr('common.cancel')}</Button><Button variant="primary" disabled={!connectors.length || (!!missing.length && !createMissing) || run.isPending} onClick={() => run.mutate()}>{tr('cti.startEnrich')}</Button></div>
  </div></Modal>
}
