import { DirectEnrichment } from './DirectEnrichment'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, post, type Ioc } from '../api'
import { useOpenCti, openCtiKey, type OpenCtiEnrichmentPreview } from '../opencti'
import { useT } from '../i18n'
import { Button, Tag } from './ui'
import { ConnectorCapabilities } from './ConnectorCapabilities'
import { EnrichmentDetails } from './EnrichmentDetails'
import { CtiError } from './CaseProfile'
import { RefreshCw, Radar, Search } from 'lucide-react'

/** Uses the same stored objects, connector preview and job queue as the IOC Box. */
export function ArtifactEnrichment({ slug, ids }: { slug: string; ids: number[] }) {
  const tr = useT()
  const qc = useQueryClient()
  const cti = useOpenCti(slug)
  const [preview, setPreview] = useState<OpenCtiEnrichmentPreview | null>(null)
  const [connectors, setConnectors] = useState<string[]>([])
  const [createMissing, setCreateMissing] = useState(false)
  const [queued, setQueued] = useState(false)
  const iocs = useQuery({ queryKey: ['iocs', slug], queryFn: () => api<Ioc[]>(`/api/cases/${slug}/iocs`), enabled: cti.configured && ids.length > 0 })
  const refresh = () => { void qc.invalidateQueries({ queryKey: openCtiKey(slug) }); void qc.invalidateQueries({ queryKey: ['iocs', slug] }); void qc.invalidateQueries({ queryKey: ['jobs', slug] }) }
  const prepare = useMutation({ mutationFn: () => post<OpenCtiEnrichmentPreview>(`/api/cases/${slug}/opencti/enrichment/preview`, { ioc_ids: ids }), onSuccess: data => { setPreview(data); setConnectors([]); setCreateMissing(false) } })
  const check = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/lookup`, { ioc_ids: ids }), onSuccess: () => { setQueued(true); refresh() } })
  const run = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/enrich`, { ioc_ids: ids, connector_ids: connectors, create_missing: createMissing }), onSuccess: () => { setQueued(true); refresh() } })
  const poll = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/enrichment/status`, {}), onSuccess: refresh })
  const missing = preview?.entities.some(entity => entity.requires_creation)
  const needsTransfer = preview?.entities.some(entity => entity.requires_transfer)
  const busy = prepare.isPending || run.isPending || check.isPending || poll.isPending
  if (!cti.configured) return <DirectEnrichment slug={slug} ids={ids} />
  if (!ids.length) return <p role="status" className="text-[12px] text-[var(--muted)]">{tr('review.collectForEnrichment')}</p>
  const jobs = cti.data?.enrichments?.filter(item => ids.includes(item.ioc_id)) ?? []
  return <section className="space-y-3 text-[12px]">
    <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">{tr('review.enrichmentTitle')}</h3><div className="flex flex-wrap gap-2">
      <Button disabled={busy} onClick={() => check.mutate()}><Search size={13} />{tr('cti.check')}</Button>
      <Button disabled={busy} onClick={() => prepare.mutate()}><Radar size={13} />{tr('cti.chooseConnectors')}</Button>
      <Button disabled={busy} onClick={() => poll.mutate()}><RefreshCw size={13} />{tr('review.refresh')}</Button>
    </div></div>
    {preview && <div className="space-y-3 rounded-lg border border-[var(--line)] p-3">
      <p className="text-[var(--muted)]">{tr('cti.enrichBody')}</p>
      {preview.connectors.filter(connector => connector.active).map(connector => <label key={connector.id} className="flex items-start gap-3 border-b border-[var(--line-soft)] py-2"><input type="checkbox" className="mt-1" checked={connectors.includes(connector.id)} onChange={event => setConnectors(old => event.target.checked ? [...old, connector.id] : old.filter(id => id !== connector.id))} /><span className="min-w-0"><strong>{connector.name}</strong><ConnectorCapabilities connector={connector} /></span></label>)}
      {!preview.connectors.some(connector => connector.active) && <p>{tr('cti.noConnectors')}</p>}
      {preview.warnings.map((warning, index) => <p key={index} className="text-[var(--muted)]">{warning}</p>)}
      {missing && <label className="flex items-center gap-2"><input type="checkbox" checked={createMissing} onChange={event => setCreateMissing(event.target.checked)} />{tr('cti.createMissing')}</label>}
      {needsTransfer && <p role="status">{tr('cti.transferRequired')}</p>}
      <div className="flex justify-end"><Button variant="special" disabled={busy || !connectors.length || !preview.entities.length || !!needsTransfer || (!!missing && !createMissing)} onClick={() => run.mutate()}>{tr('review.runEnrichment')}</Button></div>
    </div>}
    <CtiError error={prepare.error || run.error || check.error || poll.error || cti.error || iocs.error} />
    {queued && <p role="status" className="text-[var(--muted)]">{tr('cti.queuedActivity')}</p>}
    {jobs.length > 0 && <div className="max-h-32 overflow-auto rounded border border-[var(--line)]">{jobs.map(job => <div key={job.id} className="flex flex-wrap gap-2 border-b border-[var(--line-soft)] px-3 py-2"><strong>{job.connector_name || job.connector_id}</strong><Tag>{job.state}</Tag><span className="ml-auto text-[var(--muted)]">{job.updated}</span>{job.error && <p role="alert" className="w-full text-[var(--danger-text)]">{job.error}</p>}</div>)}</div>}
    {ids.map(id => <EnrichmentDetails key={id} slug={slug} object={Array.isArray(iocs.data) ? iocs.data.find(item => item.id === id) : undefined} lookup={cti.data?.lookups?.find(item => item.ioc_id === id)} loading={cti.isFetching} error={cti.isError} />)}
  </section>
}
