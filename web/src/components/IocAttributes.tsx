import type { ReactNode } from 'react'
import type { Ioc } from '../api'
import { useT } from '../i18n'
import { useGeo } from '../geo'
import { IocField } from './IocField'
import { valueAttributes } from './iocAttributeValues'
import { iocName, observationTime } from './iocPresentation'

export interface AttributeObservation {
  id: string; kind: string; active: boolean; path: string
  evidence_id: number | null; first_seen: string; last_seen: string
}

export function IocAttributes({ object, observations, iocs, relationships, onNavigate }: {
  object: Ioc; observations: AttributeObservation[]; iocs: Ioc[]
  relationships: { id: number; src: number; dst: number; kind: string; active: boolean }[]
  onNavigate?: (id: number) => void
}) {
  const tr = useT()
  const geo = useGeo(object.type === 'ip' ? object.value : null)
  const field = (key: string, value: ReactNode) => <IocField key={key} name={tr(`iocAttr.${key}`)} help={tr(`iocAttr.${key}Help`)}>{value || tr('iocAttr.missing')}</IocField>
  const active = observations.filter(o => o.active)
  const file = object.file
  const locations = active.filter(o => o.kind === 'file-location' && o.path)
    .filter((o, i, all) => o.evidence_id == null || all.findIndex(other => other.path === o.path && other.evidence_id === o.evidence_id) === i)
  const relatedFiles = iocs.filter(ioc => object.file_ids?.includes(ioc.id))
  const linkKinds = [...new Set(relationships.filter(r => r.active).map(r => r.kind))]
  const knownCveKinds = ['cve-context', 'exploit-attempt', 'exploitation-confirmed']
  return <>
    {valueAttributes(object).map(([key, value]) => field(key, value))}
    {object.type === 'ip' && field('geo', geo?.name || tr('iocAttr.geoMissing'))}
    {object.type === 'path' && <>
      {field('pathKind', tr(`iocAttr.path.${['http-request', 'system', 'local-evidence'].includes(object.path_context || '') ? object.path_context : 'unknown'}`))}
      {field('scope', object.context)}
    </>}
    {object.type === 'user' && field('accountContext', object.context)}
    {object.type === 'other' && field('context', object.context)}
    {object.type === 'hash' && field('linkedFiles', relatedFiles.length ? <div className="space-y-1">{relatedFiles.map(item => <button type="button" key={item.id} disabled={!onNavigate} onClick={() => onNavigate?.(item.id)} className="block max-w-full break-all text-left text-[var(--accent-text)]">{iocName(item)}</button>)}</div> : tr('iocAttr.noLinkedFile'))}
    {object.type === 'file' && <>
      {field('names', file?.names.length ? file.names.join(' · ') : '')}
      {field('size', file?.size == null ? '' : `${file.size.toLocaleString()} bytes`)}
      {field('classification', file?.classifications?.length ? file.classifications.map(value => tr(`artifact.class.${value}`)).join(', ') : file?.classification || tr('iocAttr.unclassified'))}
      {field('verified', file?.verified_at ? observationTime(file.verified_at) : tr('iocAttr.unverified'))}
      <div className="sm:col-span-2">{field('locations', locations.length ? <ul className="max-h-36 space-y-1 overflow-y-auto">{locations.map(o => <li key={o.id} className="flex flex-wrap gap-x-3"><code className="break-all">{o.path}</code><span className="text-[var(--muted)]">{o.evidence_id == null ? tr('iocAttr.sourceUnknown') : tr('iocAttr.source', { id: o.evidence_id })}</span></li>)}</ul> : '')}</div>
    </>}
    {object.type === 'vulnerability' && <>
      {field('cveRecord', /^CVE-\d{4}-\d{4,}$/i.test(object.value) ? <a href={`https://www.cve.org/CVERecord?id=${encodeURIComponent(object.value.toUpperCase())}`} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-text)]">{object.value.toUpperCase()} ↗</a> : '')}
      {field('cveEvidence', linkKinds.some(k => knownCveKinds.includes(k)) ? <div className="space-y-1">{knownCveKinds.filter(k => linkKinds.includes(k)).map(k => <p key={k}>{tr(`iocAttr.cve.${k}`)} · {relationships.filter(r => r.active && r.kind === k).length}</p>)}</div> : '')}
    </>}
    {!!object.context && !['path', 'user', 'other'].includes(object.type) && field('context', object.context)}
  </>
}
