import { useT } from '../i18n'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, post, type Ioc, type CrossCaseIocMatch } from '../api'
import { safeCtiUrl, useOpenCti } from '../opencti'
import { OpenCtiToolbar, OpenCtiScore, OpenCtiDetails, GroupedActions } from './OpenCti'
import { Button, Modal, CopyButton, Tabs } from './ui'
import { TraceWindow } from './TraceWindow'
import { FileViewer } from './FileViewer'
import { ArrowLeft, ArrowRight, ExternalLink, FileCode2, Search, Route, Trash2, Pencil, SlidersHorizontal } from 'lucide-react'
import { IocDeleteDialog } from './IocDeleteDialog'
import { IocEditDialog } from './IocEditDialog'
import { InfoDot, Tooltip } from './Tooltip'
import { descriptions, iocName, iocOrigins, observationTime } from './iocPresentation'
import { IocField } from './IocField'
import { IpFlag } from './IpFlag'
import { IocTypeBadge } from './IocTypeBadge'
import { IocAssessmentBadge } from './IocAssessmentBadge'
import { IocTags } from './IocTags'
import { IocAttributes } from './IocAttributes'
import type { Navigate } from '../App'

interface Observation {
  id: string; kind: string; evidence_id: number | null; finding_id: number | null
  source_ref: string; path: string; local_path: string; first_seen: string; last_seen: string
  count: number | null; detail: string; active: boolean
}
interface Relationship {
  id: number; src: number; dst: number; src_value: string; dst_value: string
  kind: string; origin: string; active: boolean; withdrawal_reason: string
  evidence: { id: string; reference: string; detail: string; first_seen: string; last_seen: string }[]
  events: { id: number; action: string; reason: string; created: string }[]
}
interface Detail {
  object: Ioc; observations: Observation[]
  sources: { id: number; artifact: string; role: string; active: boolean }[]
  findings: { id: number; rule: string; artifact: string; triage: string; evidence: string; retired?: boolean }[]
  assessments: { id: number; state: string; reason: string; created: string }[]
  edits?: { previous_value: string; value: string; reason: string; created: string }[]
  relationships: Relationship[]
  relationship_types: Record<string, { sources: string[]; targets: string[] }>
}
const labels: Record<string, string> = {
  'hash-of': 'Hash of', requested: 'Requested', 'host-in': 'Appears in code of', 'account-of': 'Email of account',
  'located-at': 'Collected at', 'request-context': 'Request-path association', used: 'Used (evidence required)',
  executed: 'Executed (evidence required)', 'cve-context': 'Specific CVE context',
  'exploit-attempt': 'Exploitation attempt', 'exploitation-confirmed': 'Confirmed exploitation',
}

export function IocDetails({ slug, id, iocs, onClose, embedded = false, tab: controlledTab, onTab, onNavigate, gotoView, onDirtyChange, onDeleted, crossMatches = [] }: {
  slug: string; id: number; iocs: Ioc[]; onClose: () => void; embedded?: boolean; tab?: string; onTab?: (tab: string) => void
  onNavigate?: (id: number) => void; gotoView?: Navigate; onDirtyChange?: (dirty: boolean) => void; crossMatches?: CrossCaseIocMatch[]
  onDeleted?: (ids: number[]) => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const { data, error, isPending } = useQuery({
    queryKey: ['iocs', slug, 'detail', id],
    queryFn: () => api<Detail>(`/api/cases/${slug}/iocs/${id}/detail`)
  })
  const cti = useOpenCti(slug)
  const [localTab, setLocalTab] = useState('Overview')
  const requestedTab = controlledTab || localTab
  const canEnrich = cti.configured && !!data?.object && (
    ['ip', 'domain', 'url', 'email', 'hash', 'file', 'vulnerability'].includes(data.object.type)
    || (data.object.type === 'user' && !!data.object.context))
  const tab = requestedTab === 'Enrichment' && canEnrich ? 'Enrichment' : 'Overview'
  const setTab = (value: string) => { setLocalTab(value); onTab?.(value) }
  const [editOpen, setEditOpen] = useState(false)
  const [viewPath, setViewPath] = useState<string | null>(null)
  const [chooseLocation, setChooseLocation] = useState(false)
  const [traceOpen, setTraceOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  useEffect(() => { setViewPath(null); setChooseLocation(false); setTraceOpen(false) }, [slug, id])
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['iocs'] })
    qc.invalidateQueries({ queryKey: ['opencti', slug] })
  }
  const verifyFile = useMutation({ mutationFn: () => post<{ verified_locations: number; unavailable_or_changed_locations: number }>(`/api/cases/${slug}/iocs/${id}/verify-file`, {}), onSuccess: invalidate })
  const object = data?.object
  const failure = error || verifyFile.error
  const current = iocs.find(i => i.id === id)
  const observed = data?.observations.filter(o => o.active) ?? []
  const fileLocations = object?.type === 'file'
    ? observed.filter(o => o.kind === 'file-location' && o.local_path)
      .filter((o, index, all) => all.findIndex(other => other.local_path === o.local_path) === index)
      .map(o => ({ path: o.local_path, label: o.path || o.local_path, evidenceId: o.evidence_id }))
    : object?.type === 'path' && current?.resolved
      ? [{ path: current.resolved, label: object.value, evidenceId: null }] : []
  const associatedFiles = object?.type === 'hash' ? iocs.filter(i => i.type === 'file' && object.file_ids?.includes(i.id)) : []
  const openFile = () => {
    if (fileLocations.length === 1) setViewPath(fileLocations[0].path)
    else setChooseLocation(true)
  }
  const activity = observed.filter(o => ['http-request', 'pattern-hunt'].includes(o.kind))
  const times = activity.flatMap(o => [o.first_seen, o.last_seen]).filter(Boolean).sort()
  const showActivity = object?.type === 'ip' || times.length > 0
  // The IP list includes spans from the access-log index. Scan/collection dates
  // belong to their source records, not generic object activity fields.
  const indexedFirst = object?.type === 'ip' ? current?.first_seen : undefined
  const indexedLast = object?.type === 'ip' ? current?.last_seen : undefined
  const links = data?.relationships.filter(r => r.active) ?? []
  const targetOf = (r: Relationship) => r.src === id ? r.dst : r.src
  const lookup = cti.data?.lookups?.find(entry => entry.ioc_id === id)
  // Lookup writes import provider labels transactionally; refresh the shared
  // local object when that snapshot changes, including during enrichment polling.
  useEffect(() => {
    if (lookup?.checked_at) void qc.invalidateQueries({ queryKey: ['iocs', slug] })
  }, [lookup?.checked_at, qc, slug])
  const ctiLinks = (lookup?.entities ?? []).filter(entity => safeCtiUrl(entity.url))
  const relationshipTable = (relations: Relationship[]) => <div className="overflow-x-auto rounded-lg border border-[var(--line)]">
    <table className="ioc-relationships w-full text-left text-[12px]">
      <thead><tr>{['relationship', 'type', 'object'].map(key => <th key={key} scope="col">{tr(`iocTable.${key}`)}</th>)}</tr></thead>
      <tbody>{relations.map(r => {
        const target = targetOf(r)
        const item = iocs.find(i => i.id === target)
        const name = item ? iocName(item) : r.src === id ? r.dst_value : r.src_value
        const Direction = r.src === id ? ArrowRight : ArrowLeft
        return <tr key={r.id}>
          <td><span className="flex items-center gap-2"><Direction size={14} className="shrink-0 text-[var(--muted)]" aria-label={tr(r.src === id ? 'iocTable.outgoing' : 'iocTable.incoming')} /><span className="rounded bg-[var(--panel-2)] px-2 py-1">{labels[r.kind] || r.kind}</span><InfoDot body={tr(`iocRelationship.help.${r.kind}`)} /></span></td>
          <td><IocTypeBadge type={item?.type || 'other'} value={item?.value} /></td>
          <td><button type="button" disabled={!onNavigate} onClick={() => onNavigate?.(target)} className="flex max-w-[320px] items-center gap-2 text-left font-medium text-[var(--accent-text)]"><span className="truncate" title={name}>{name}</span>{item?.type === 'ip' && <IpFlag ip={item.value} />}</button></td>
        </tr>
      })}{!relations.length && <tr><td colSpan={3} className="text-[var(--muted)]">{tr('iocWorkspace.no_recorded_relationships')}</td></tr>}</tbody>
    </table>
  </div>
  const content = <div className={`flex flex-col gap-3 text-[13px] ${embedded ? 'p-3' : ''}`}>

    {object && <header className="flex flex-wrap items-start gap-3">
      <div className="min-w-0 flex-1 basis-60">
        <div className="mb-1"><IocTypeBadge type={object.type} value={object.value} /></div>
        <div className="flex items-center gap-2">
          {object.type === 'ip' && <IpFlag ip={object.value} />}
          <h2 className="min-w-0 break-all text-xl font-semibold">{iocName(object)}</h2>
          <CopyButton value={object.value} label="Copy object value" />
          {ctiLinks.map(entity => <Tooltip key={entity.id} body={tr('cti.openObject', { name: entity.name || object.value })}>
            <a href={safeCtiUrl(entity.url)} target="_blank" rel="noopener noreferrer" aria-label={ctiLinks.length === 1 ? tr('cti.open') : tr('cti.openObject', { name: entity.name || entity.id })} className="ui-press inline-flex shrink-0 items-center rounded p-1.5 text-[var(--accent-text)] hover:bg-[var(--panel-2)]"><ExternalLink size={16} /></a>
          </Tooltip>)}
        </div>
        <div className="mt-1 flex items-center gap-2 text-[12px]">
          <IocAssessmentBadge assessment={object.assessment} />
        </div>
      </div>
      <OpenCtiToolbar
        mode="inline"
        grouped
        trailingAction={<GroupedActions label={tr('iocEdit.actions')} icon={<SlidersHorizontal size={14} />}>
          <Button type="button" variant="ghost" onClick={() => setEditOpen(true)}><Pencil size={14} />{tr('iocEdit.title')}</Button>
          <Button type="button" variant="danger" onClick={() => setDeleteOpen(true)}><Trash2 size={14} />{tr('iocDelete.single')}</Button>
        </GroupedActions>}
        leadingAction={<>
          {['file', 'path'].includes(object.type) && <Tooltip body={tr(fileLocations.length ? 'iocAction.contentHelp' : 'iocAction.noContent')}>
            <span><Button type="button" variant="special" disabled={!fileLocations.length} onClick={openFile}><FileCode2 size={14} />{tr('iocAction.content')}</Button></span>
          </Tooltip>}
          {object.type === 'ip' && <Button type="button" variant="special" onClick={() => setTraceOpen(true)}><Route size={14} />{tr('artifact.openTrace')}</Button>}
          {gotoView && (['domain', 'url'].includes(object.type) || (object.type === 'path' && object.path_context === 'http-request')) &&
            <Button type="button" variant="special" onClick={() => gotoView('logs', { search: object.value })}><Search size={14} />{tr('iocAction.searchLogs')}</Button>}
          {onNavigate && associatedFiles.map(file => <Button type="button" variant="special" key={file.id} onClick={() => onNavigate(file.id)}><FileCode2 size={14} />{tr('iocAction.associatedFile', { name: iocName(file) })}</Button>)}
        </>}
        slug={slug}
        iocs={iocs}
        selectedIds={[id, ...iocs.filter(i => i.file_ids?.includes(id)).map(i => i.id)]}
        onSelectAll={() => { }}
        onClear={() => { }}
        onSettings={() => gotoView?.('settings')} />
    </header>}

    {object && editOpen && <IocEditDialog slug={slug} object={object} assessments={data?.assessments} edits={data?.edits} onClose={() => setEditOpen(false)} />}

    <div className="overflow-x-auto" aria-label={tr('iocWorkspace.detail_tabs')}>
      <Tabs active={tab} onChange={setTab} tabs={['Overview', ...(canEnrich ? ['Enrichment'] : [])].map(name => ({ id: name, label: tr(`iocWorkspace.tab.${name}`) }))} />
    </div>

    {failure && <p role="alert" className="text-[var(--danger-text)]">{String(failure instanceof Error ? failure.message : failure)}</p>}

    {isPending && <p>{tr('iocWorkspace.loading_case_details')}</p>}

    {object && tab === 'Overview' && <>
      <h3 className="ioc-section-title">{tr('iocAttr.title')}</h3>
      <div className="grid grid-cols-1 gap-x-6 border-b border-[var(--line)] sm:grid-cols-2">

        {object.type === 'user' && !!object.account_sources?.length ? <div className="sm:col-span-2">
          <IocField name={tr('iocAccount.registered')} help={tr('iocAccount.registeredHelp')}>
            <div className="space-y-2">{object.account_sources.map(source => <div key={source.source_key} className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span>{source.registered || tr('iocAccount.notRecorded')}</span>
              <span className="text-[12px] text-[var(--muted)]">{[source.cms, source.table].filter(Boolean).join(' · ')}</span>
            </div>)}</div>
          </IocField>
        </div> : showActivity && <>
          <IocField name="First observed">{observationTime(indexedFirst || times[0])}</IocField>
          <IocField name="Last observed">{observationTime(indexedLast || times[times.length - 1])}</IocField>
        </>}
        <IocAttributes object={object} observations={observed} iocs={iocs} relationships={links} onNavigate={onNavigate} />

        <IocField name="Origin">
          <div className="space-y-1 break-words">{iocOrigins(object, observed, data?.findings ?? []).map(origin => <p key={origin}>{origin}</p>)}</div>
        </IocField>
        {cti.configured && <OpenCtiScore lookup={cti.data?.lookups?.find(entry => entry.ioc_id === id)} loading={cti.isPending} error={Boolean(cti.error)} />}
        <IocField name={tr('iocTags.title')} help={tr(cti.configured ? 'iocTags.help' : 'iocTags.localHelp')}><IocTags key={object.id} slug={slug} object={object} /></IocField>
      </div>
      {object.file && <details className="rounded-lg border border-[var(--line)] p-3">
          <summary className="flex cursor-pointer items-center gap-2">
            {tr('iocWorkspace.hashes')}
            <InfoDot body={descriptions.Hashes} />
          </summary>
          <div className="mt-3 space-y-2">
            {Object.entries(object.file.hashes).map(([algorithm, hash]) => <div key={algorithm}>
              <strong>{algorithm}</strong>
              <div className="flex items-center gap-2">
                <code className="min-w-0 break-all">{hash}</code>
                <CopyButton value={hash} label={`Copy ${algorithm}`} />
              </div>
            </div>)}
            <Button disabled={verifyFile.isPending} onClick={() => verifyFile.mutate()}>{tr('iocWorkspace.verify_available_file_metadata')}</Button>
            {verifyFile.data && <p role="status">{verifyFile.data.verified_locations} {tr('iocWorkspace.verified')} {verifyFile.data.unavailable_or_changed_locations} {tr('iocWorkspace.unavailable_or_changed')}</p>}
          </div>
        </details>}
      {object.legacy_warning && <details className="text-[var(--review-text)]">
        <summary className="cursor-pointer">{tr('iocWorkspace.review_legacy_metadata')}</summary>
        <p>{object.legacy_warning}</p>
      </details>}
      <div>
        <div className="mb-2 flex items-center gap-2">
          <h3 className="ioc-section-title">
          {tr('iocWorkspace.relationships')}</h3><span className="rounded bg-[var(--panel-2)] px-2 text-[12px] text-[var(--muted)]">{links.length}</span>
          <InfoDot body={descriptions.Relationships} />
        </div>
        {relationshipTable(links)}
      </div>
      {object.note && <details>
        <summary className="cursor-pointer text-[var(--accent-text)]">{tr('iocWorkspace.analyst_note')}</summary>
        <p className="mt-2 whitespace-pre-wrap">{object.note}</p>
      </details>}
      {crossMatches.length > 0 && <details>
        <summary className="cursor-pointer text-[var(--accent-text)]">{tr('iocWorkspace.also_seen_in')} {crossMatches.length} {tr('iocWorkspace.other_cases')}</summary>
        {crossMatches.map(m => <a
          className="mt-2 block text-[var(--accent-text)]"
          key={`${m.slug}:${m.id}`}
          href={`?view=iocbox&case=${encodeURIComponent(m.slug)}&ioc=${m.id}`}>{m.name || m.slug} · {m.reference}</a>)}
      </details>}
    </>}

    {object && tab === 'Enrichment' && <section aria-label={tr('iocWorkspace.tab.Enrichment')} className="space-y-3">
      <h3 className="ioc-section-title">{tr('cti.enrichmentResults')}</h3>
      {cti.isPending && <p>{tr('common.loading')}</p>}
      {cti.error && <p role="alert" className="text-[var(--danger-text)]">{String(cti.error instanceof Error ? cti.error.message : cti.error)}</p>}
      {!!cti.data?.enrichments?.some(entry => entry.ioc_id === id) && <div className="space-y-2">
        {cti.data.enrichments.filter(entry => entry.ioc_id === id).map(entry => <div key={entry.id} className="flex flex-wrap items-center gap-2 rounded border border-[var(--line)] p-3 text-[12px]">
          <strong>{entry.connector_name || tr('cti.connectorJob', { id: entry.connector_id.slice(0, 8) })}</strong>
          <span>{entry.state}</span><span className="text-[var(--muted)]">{entry.updated}</span>
          {entry.error && <span className="text-[var(--danger-text)]">{entry.error}</span>}
        </div>)}
      </div>}
      {!cti.isPending && !lookup?.entities?.length && <p className="text-[var(--muted)]">{tr('cti.enrichmentEmpty')}</p>}
      <OpenCtiDetails lookup={lookup} object={object} slug={slug} loading={cti.isPending} error={Boolean(cti.error)} />
    </section>}

    {chooseLocation && <Modal open onClose={() => setChooseLocation(false)} layer={2} title={tr('iocAction.chooseLocation')}>
      <div className="flex flex-col gap-2">{fileLocations.map(location => <Button key={location.path} type="button" className="justify-start text-left" onClick={() => { setChooseLocation(false); setViewPath(location.path) }}>
        <FileCode2 size={14} /><span className="min-w-0 break-all">{location.label}</span>
        {location.evidenceId != null && <span className="shrink-0 text-[var(--muted)]">{tr('iocAttr.source', { id: location.evidenceId })}</span>}
      </Button>)}</div>
    </Modal>}
    {traceOpen && object?.type === 'ip' && <TraceWindow slug={slug} ips={[object.value]} layer={2} onClose={() => setTraceOpen(false)} />}
    <FileViewer slug={slug} path={viewPath} layer={2} onClose={() => setViewPath(null)} />
    {deleteOpen && object && <IocDeleteDialog slug={slug} objects={[object]} onClose={() => setDeleteOpen(false)} onDeleted={ids => {
      onDirtyChange?.(false)
      if (onDeleted) onDeleted(ids); else onClose()
    }} />}

  </div>
  return embedded ? content : <Modal open onClose={onClose} title={object ? iocName(object) : 'IOC details'}>{content}</Modal>
}
