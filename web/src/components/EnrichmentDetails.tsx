import { ExternalLink } from 'lucide-react'
import { safeCtiUrl, type OpenCtiLookup, type OpenCtiReference } from '../opencti'
import { useT } from '../i18n'
import { Tag } from './ui'
import { IocTag, IocTags } from './IocTags'
import type { Ioc } from '../api'
import { OpenCtiScore } from './OpenCtiScore'
import { IocTypeBadge } from './IocTypeBadge'
import { IocField } from './IocField'
import { InfoDot } from './Tooltip'
import { CtiError } from './CaseProfile'

const types: Record<string, string> = { 'IPv4-Addr': 'ip', 'IPv6-Addr': 'ip', StixFile: 'file', File: 'file', 'Domain-Name': 'domain', Url: 'url', 'Email-Addr': 'email', 'User-Account': 'user', Vulnerability: 'vulnerability' }
const name = (item?: OpenCtiReference) => item?.name || item?.observable_value || item?.value || item?.source_name || item?.external_id || item?.description || item?.id || '—'

function References({ title, items = [], relationships = false }: { title: string; items?: (string | OpenCtiReference)[]; relationships?: boolean }) {
  const tr = useT()
  if (!items.length) return null
  return <section className="space-y-3">
    <h4 className="ioc-section-title">{title}<span className="ml-2 rounded bg-[var(--panel-2)] px-2 text-[11px] text-[var(--muted)]">{items.length}</span></h4>
    <div className="overflow-x-auto rounded-lg border border-[var(--line)]"><table className="ioc-relationships w-full text-left text-[12px]">
      <thead><tr>{(relationships ? ['cti.relationshipFrom', 'iocTable.relationship', 'cti.relationshipTo'] : ['iocTable.object', 'cti.sourceAuthorTitle']).map(key => <th key={key}>{tr(key)}</th>)}</tr></thead>
      <tbody>{items.map((item, index) => {
        if (relationships && typeof item !== 'string') return <tr key={index}><td className="break-words">{name(item.from)}</td><td><Tag>{item.relationship_type || 'related-to'}</Tag>{item.description && <InfoDot body={item.description} />}</td><td className="break-words">{name(item.to)}</td></tr>
        const href = typeof item === 'string' ? undefined : safeCtiUrl(item.url)
        const label = typeof item === 'string' ? item : name(item)
        return <tr key={index}><td className="break-words">{href ? <a href={href} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-[var(--accent-text)] hover:underline">{label}<ExternalLink size={12} /></a> : label}</td><td colSpan={relationships ? 2 : 1} className="text-[var(--muted)]">{typeof item === 'string' ? '—' : name(item.createdBy)}</td></tr>
      })}</tbody>
    </table></div>
  </section>
}

export function EnrichmentDetails({ lookup, object, slug, loading, error }: { lookup?: OpenCtiLookup; object?: Ioc; slug?: string; loading?: boolean; error?: boolean }) {
  const tr = useT()
  return <div className="space-y-3 text-[13px]">
    <div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] pb-3">
      <Tag tone={lookup?.status === 'error' ? 'danger' : undefined}>{tr(`cti.${lookup?.status ?? 'unchecked'}`)}</Tag>
      <InfoDot body={tr('cti.savedHelp')} />
      {lookup?.checked_at && <span className="ml-auto text-[12px] text-[var(--muted)]">{tr('cti.cached', { at: lookup.checked_at })}</span>}
    </div>
    <CtiError error={lookup?.error} />
    <div className="grid grid-cols-1 gap-x-6 border-b border-[var(--line)] sm:grid-cols-2">
      <OpenCtiScore lookup={lookup} loading={loading} error={error} />
      {object && slug && <IocField name={tr('iocTags.title')} help={tr('iocTags.help')}><IocTags key={object.id} slug={slug} object={object} /></IocField>}
    </div>
    {lookup?.entities?.map(entity => <section key={entity.id} className="space-y-3 border-b border-[var(--line)] pb-3 last:border-0">
      <div className="flex flex-wrap items-center gap-3"><h3 className="ioc-section-title break-all">{entity.name}</h3>
        {types[entity.type] ? <IocTypeBadge type={types[entity.type]} value={entity.name} /> : <Tag>{entity.type}</Tag>}
        {safeCtiUrl(entity.url) && <a href={safeCtiUrl(entity.url)} target="_blank" rel="noopener noreferrer" className="ml-auto inline-flex items-center gap-2 text-[12px] text-[var(--accent-text)]">{tr('cti.open')}<ExternalLink size={14} /></a>}
      </div>
      <div className="grid grid-cols-1 gap-x-6 border-y border-[var(--line)] sm:grid-cols-2">
        {entity.confidence != null && <IocField name={tr('cti.confidenceTitle')} help={tr('cti.confidenceHelp')}><Tag>{entity.confidence} / 100</Tag></IocField>}
        {!object && !!entity.labels?.length && <IocField name={tr('iocTags.title')} help={tr('cti.labelsHelp')}><div className="flex flex-wrap gap-1.5">{entity.labels.map((tag, index) => <IocTag key={index} value={typeof tag === 'string' ? tag : tag.value} />)}</div></IocField>}
        {entity.type.toLowerCase() === 'vulnerability' && [
          { value: entity.x_opencti_epss_score, label: 'EPSS', help: 'cti.epssHelp', percent: true },
          { value: entity.x_opencti_epss_percentile, label: 'EPSS percentile', help: 'cti.epssPercentileHelp', percent: true },
          { value: entity.x_opencti_cvss_base_score, label: 'CVSS', help: 'cti.cvssHelp', percent: false },
        ].filter(metric => typeof metric.value === 'number' && Number.isFinite(metric.value)).map(metric => <IocField key={metric.label} name={metric.label} help={tr(metric.help)}><Tag>{metric.percent ? `${(metric.value! * 100).toFixed(2)}%` : `${metric.value} / 10`}</Tag></IocField>)}
        {entity.first_seen && <IocField name={tr('cti.firstSeen')} help={tr('cti.observedHelp')}>{entity.first_seen}</IocField>}
        {entity.last_seen && <IocField name={tr('cti.lastSeen')} help={tr('cti.observedHelp')}>{entity.last_seen}</IocField>}
        {entity.created_at && <IocField name={tr('cti.createdAt')} help={tr('cti.createdHelp')}>{entity.created_at}</IocField>}
        {entity.updated_at && <IocField name={tr('cti.updatedAt')} help={tr('cti.updatedHelp')}>{entity.updated_at}</IocField>}
      </div>
      {entity.description && <section className="space-y-3"><h4 className="ioc-section-title">{tr('cti.descriptionTitle')}</h4><p className="whitespace-pre-wrap break-words leading-relaxed">{entity.description}</p></section>}
      <References title={tr('cti.sources')} items={entity.sources} /><References title={tr('cti.reports')} items={entity.reports} />
      <References title={tr('cti.malware')} items={entity.malware} /><References title={tr('cti.relationships')} items={entity.relationships} relationships />
    </section>)}
  </div>
}
