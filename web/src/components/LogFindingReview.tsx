import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ExternalLink, FileText } from 'lucide-react'
import { api, type ArtifactContext } from '../api'
import type { LogEvent } from '../logApi'
import { useT } from '../i18n'
import { logSourceLink, useLogContext } from '../logReview'
import { Button, Tag, Tabs } from './ui'
import { LogEventEvidence, LogEventFacts } from './LogEntryContext'
import { FileContentPane } from './FileViewer'
import { IocTypeBadge } from './IocTypeBadge'
import { ArtifactEnrichment } from './ArtifactEnrichment'

/** Keeps log observations distinct from the linked file's own review and IOC state. */
export function LogFindingReview({ slug, events, configured, onFile }: {
  slug: string; events: LogEvent[]; configured: boolean; onFile: (path: string, line: number | null) => void
}) {
  const tr = useT()
  const [selected, setSelected] = useState('')
  const event = events.find(item => item.id === selected) ?? events[0]
  if (!event) return <p role="status" className="p-4 text-[12px] text-[var(--muted)]">{tr('logReview.noObservation')}</p>
  return <div className="flex min-h-0 flex-1 flex-col">
    {events.length > 1 && <label className="flex shrink-0 flex-wrap items-center gap-2 border-b border-[var(--line)] px-3 py-2 text-[12px]">{tr('logReview.observation')}<select className="min-w-0 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2" value={event.id} onChange={e => setSelected(e.target.value)}>{events.map(item => <option key={item.id} value={item.id}>{tr(`logEvidence.family.${item.family}`)} · {item.source_name}:{item.line}</option>)}</select></label>}
    <LogFindingDetail key={`${slug}:${event.id}:${event.fingerprint}`} slug={slug} event={event} configured={configured} onFile={onFile} />
  </div>
}

function LogFindingDetail({ slug, event, configured, onFile }: {
  slug: string; event: LogEvent; configured: boolean; onFile: (path: string, line: number | null) => void
}) {
  const tr = useT()
  const [wide, setWide] = useState(() => window.innerWidth >= 1024)
  const [metadataOpen, setMetadataOpen] = useState(false)
  useEffect(() => {
    const resize = () => setWide(window.innerWidth >= 1024)
    window.addEventListener('resize', resize)
    return () => window.removeEventListener('resize', resize)
  }, [])
  const query = useLogContext(slug, event)
  const current = !query.isError ? query.data?.event : undefined
  const shown = current ?? event
  const available = !!current?.artifact_available && !!current.artifact
  const [tab, setTab] = useState('evidence')
  const active = (tab === 'file' && !available) || (tab === 'enrichment' && (!available || !configured)) ? 'evidence' : tab
  const linked = useQuery({
    queryKey: ['log-linked-artifact', slug, current?.artifact, event.fingerprint],
    queryFn: () => api<ArtifactContext>(`/api/cases/${slug}/artifact?artifact=${encodeURIComponent(current!.artifact)}`),
    enabled: available && active !== 'evidence',
  })
  const linkedFile = linked.data?.file
  const linkedCurrent = available && !linked.isError && linkedFile?.exists && linkedFile.available !== false
  const boxUrl = new URL(location.href)
  boxUrl.search = new URLSearchParams({ case: slug, view: 'iocbox', ...(linked.data?.ioc_ids?.[0] ? { ioc: String(linked.data.ioc_ids[0]) } : {}) }).toString()
  return <div className="grid min-h-0 flex-1 overflow-y-auto lg:grid-cols-[minmax(0,26%)_minmax(0,1fr)]" data-artifact-scroll>
    <aside className="min-w-0 border-b border-[var(--line)] p-3 lg:overflow-y-auto lg:border-r lg:border-b-0" data-artifact-scroll>
      <div className="mb-3 flex items-center justify-between gap-2"><h2 className="text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">{tr(`logReview.context.${event.family}`)}</h2>{!wide && <button className="text-[12px] text-[var(--accent)]" aria-expanded={metadataOpen} onClick={() => setMetadataOpen(value => !value)}>{tr(metadataOpen ? 'logReview.hideContext' : 'logReview.showContext')}</button>}</div>
      <div hidden={!wide && !metadataOpen}><LogEventFacts event={shown} sourcePath={query.data?.source_path} /><a className="mt-3 inline-flex items-center gap-2 text-[12px] text-[var(--accent)] underline underline-offset-4" href={logSourceLink(slug, event)}><ExternalLink size={12} />{tr('logEvidence.openLogs')}</a></div>
      {!wide && !metadataOpen && <p className="break-all text-[12px] text-[var(--muted)]">{tr(`logEvidence.family.${event.family}`)} · {event.source_name}:{event.line}</p>}
    </aside>
    <div className="flex min-h-[28rem] min-w-0 flex-col gap-3 p-3 lg:min-h-0">
      <div className="shrink-0"><Tabs active={active} onChange={setTab} tabs={[
        { id: 'evidence', label: tr('logReview.evidence') },
        ...(available ? [{ id: 'file', label: tr('logReview.linkedFile') }] : []),
        ...(available && configured ? [{ id: 'enrichment', label: tr('review.enrichment') }] : []),
      ]} /></div>
      <div role="tabpanel" aria-label={tr(active === 'evidence' ? 'logReview.evidence' : active === 'file' ? 'logReview.linkedFile' : 'review.enrichment')} data-artifact-scroll="primary" tabIndex={0} className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
        {active === 'evidence' ? <LogEventEvidence event={shown} context={query.data} loading={query.isPending} error={query.error} onFile={available ? () => setTab('file') : undefined} /> : <>
          <div className="flex flex-wrap items-center gap-2"><IocTypeBadge type="file" /><span className="mono min-w-0 flex-1 break-all text-[12px]">{current?.artifact.replace(/\\/g, '/').split('/').pop()}</span>{linkedCurrent && <Button variant="special" onClick={() => onFile(current!.artifact, null)}><FileText size={13} />{tr('artifact.expandFile')}</Button>}</div>
          {linked.isPending && <p role="status" className="text-[12px]">{tr('common.loading')}</p>}
          {linked.error && <p role="alert" className="text-[12px] text-[var(--danger-text)]">{linked.error.message}</p>}
          {linked.data && !linkedCurrent && !linked.error && <p role="status" className="text-[12px] text-[var(--muted)]">{linkedFile?.unavailable_reason || tr('artifact.sourceUnavailable')}</p>}
          {active === 'file' && linkedCurrent && <>
            <div className="flex flex-wrap gap-2 text-[12px]">{linkedFile.classifications?.map(value => <Tag key={value} tone="accent">{tr(`artifact.class.${value}`)}</Tag>)}</div>
            <FileContentPane key={current!.artifact} slug={slug} path={current!.artifact} compact className="min-h-[16rem] flex-1" />
          </>}
          {active === 'enrichment' && linkedCurrent && <><p className="text-[12px] text-[var(--muted)]">{tr('logReview.enrichmentHelp')}</p><ArtifactEnrichment key={current!.artifact} slug={slug} ids={linked.data!.ioc_ids ?? []} /><a className="inline-flex items-center gap-2 self-start text-[12px] text-[var(--accent)] underline underline-offset-4" href={boxUrl.toString()} target="_blank" rel="noreferrer"><ExternalLink size={12} />{tr('cti.toBox')}</a></>}
        </>}
      </div>
    </div>
  </div>
}
