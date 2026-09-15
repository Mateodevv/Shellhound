import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, RefreshCw, Search } from 'lucide-react'
import { api, post, type Enrichment, type Ioc } from '../../api'
import { directSupported, providerTypes, useDirectSettings } from '../../directEnrichment'
import { safeCtiUrl, useOpenCtiSettings } from '../../opencti'
import { useT } from '../../i18n'
import { Button, Tag } from '../ui/ui'
import { IocField } from '../iocs/IocField'
import { IocTypeBadge } from '../iocs/IocTypeBadge'
import { IocTag } from '../iocs/IocTags'
import { InfoDot } from '../ui/Tooltip'
import { CtiError } from '../casework/CaseProfile'

export function DirectEnrichment({ slug, ids }: { slug: string; ids: number[] }) {
  const tr = useT()
  const settings = useDirectSettings()
  const cti = useOpenCtiSettings()
  const enabled = cti.data?.configured === false
  const iocs = useQuery({ queryKey: ['iocs', slug], queryFn: () => api<Ioc[]>(`/api/cases/${slug}/iocs`), enabled: enabled && ids.length > 0 })
  const history = useQuery({ queryKey: ['enrichment', slug], queryFn: () => api<{ entries: Enrichment[] }>(`/api/cases/${slug}/enrichment`), enabled })
  if (!enabled) return null
  const objects = Array.isArray(iocs.data) ? iocs.data.filter(object => ids.includes(object.id) && directSupported(settings.data, object.type)) : []
  return <section className="space-y-3 text-[13px]">
    <div><h3 className="ioc-section-title">{tr('direct.title')}</h3><p className="mt-1 text-[12px] text-[var(--muted)]">{tr('direct.reportOnly')}</p></div>
    <CtiError error={settings.error || iocs.error || history.error} />
    {!ids.length && <p role="status">{tr('review.collectForEnrichment')}</p>}
    {iocs.isFetching && <p>{tr('common.loading')}</p>}
    {objects.map(object => <div key={object.id} className="space-y-3"><div className="flex items-center gap-2"><IocTypeBadge type={object.type} value={object.value} /><span className="mono break-all">{object.value}</span></div>
      {Object.entries(providerTypes).filter(([service, kinds]) => settings.data?.services?.[service]?.configured && kinds.includes(object.type)).map(([service]) => <ProviderReport key={`${object.id}:${object.value}:${service}`} slug={slug} object={object} service={service} entry={history.data?.entries?.find(entry => entry.service === service && (object.type === 'url' ? entry.value === object.value : entry.value.toLowerCase() === object.value.toLowerCase()) && entry.kind === (object.type === 'file' ? 'hash' : object.type))} />)}
    </div>)}
  </section>
}
function ProviderReport({ slug, object, service, entry }: { slug: string; object: Ioc; service: string; entry?: Enrichment }) {
  const tr = useT()
  const qc = useQueryClient()
  const run = useMutation({ mutationFn: () => post<Enrichment>(`/api/cases/${slug}/enrich`, { service, value: object.value, kind: object.type, refresh: !!entry }), onSuccess: () => { void qc.invalidateQueries({ queryKey: ['enrichment', slug] }) } })
  const result = entry?.result
  return <section className="overflow-hidden rounded-lg border border-[var(--line)] bg-[var(--panel)]">
    <div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-3 py-2"><h4 className="font-semibold">{tr(`enrich.${service}`)}</h4><InfoDot body={tr(`direct.help.${service}`)} />{entry && <span className="text-[11px] text-[var(--muted)]">{tr('direct.fetched', { at: entry.fetched })}</span>}<Button variant="special" className="ml-auto" disabled={run.isPending} onClick={() => run.mutate()}>{entry ? <RefreshCw size={13} /> : <Search size={13} />}{tr(run.isPending ? 'direct.running' : entry ? 'direct.refresh' : 'direct.lookup')}</Button></div>
    <div className="space-y-3 p-3"><CtiError error={run.error} />
      {!result && <p className="text-[var(--muted)]">{tr('direct.empty')}</p>}
      {result && !result.known && <p>{tr('direct.notFound')}</p>}
      {result?.known && <>
        <div className="grid grid-cols-1 gap-x-6 sm:grid-cols-2">
          <IocField name={tr(service === 'virustotal' ? 'direct.detections' : 'direct.abuseScore')} help={tr(service === 'virustotal' ? 'direct.detectionsHelp' : 'direct.abuseHelp')}><Tag>{result.score == null ? '—' : `${result.score} / ${result.of ?? '—'}`}</Tag></IocField>
          {service === 'virustotal' && <IocField name={tr('direct.suspicious')}>{result.suspicious ?? '—'}</IocField>}
          {result.reports != null && <IocField name={tr('direct.reports')} help={tr('direct.reportWindow')}>{result.reports}</IocField>}
          {result.distinct_reporters != null && <IocField name={tr('direct.reporters')}>{result.distinct_reporters}</IocField>}
          {result.isp && <IocField name={tr('direct.network')}>{result.isp}</IocField>}
          {result.country && <IocField name={tr('direct.country')}>{result.country}</IocField>}
          {result.usage && <IocField name={tr('direct.usage')}>{result.usage}</IocField>}
          {result.last_reported && <IocField name={tr('direct.lastReport')}>{result.last_reported}</IocField>}
          {result.last_analysis != null && <IocField name={tr('direct.lastAnalysis')}>{new Date(result.last_analysis * 1000).toISOString()}</IocField>}
          {result.reputation != null && <IocField name={tr('direct.reputation')} help={tr('direct.reputationHelp')}>{result.reputation}</IocField>}
        </div>
        {(!!result.tags?.length || result.tor) && <div className="flex flex-wrap gap-1.5">{result.tags?.map(tag => <IocTag key={tag} value={tag} />)}{result.tor && <IocTag value="Tor" />}</div>}
        {!!result.names?.length && <IocField name={tr('direct.names')}><span className="break-all">{result.names.join(', ')}</span></IocField>}
        {!!result.engines?.length && <details><summary className="cursor-pointer py-2 font-semibold">{tr('direct.engines', { n: result.engines.length })}</summary><div className="max-h-64 overflow-auto rounded border border-[var(--line)]"><table className="ioc-relationships w-full text-left text-[12px]"><thead><tr><th>{tr('direct.engine')}</th><th>{tr('direct.verdict')}</th><th>{tr('direct.detection')}</th></tr></thead><tbody>{result.engines.map(engine => <tr key={engine.name}><td>{engine.name}</td><td><Tag>{engine.category}</Tag></td><td>{engine.result || '—'}</td></tr>)}</tbody></table></div></details>}
      </>}
      {safeCtiUrl(result?.permalink) && <a className="inline-flex items-center gap-2 text-[12px] text-[var(--accent-text)]" href={safeCtiUrl(result?.permalink)} target="_blank" rel="noreferrer noopener">{tr('direct.openReport')}<ExternalLink size={12} /></a>}
    </div>
  </section>
}
