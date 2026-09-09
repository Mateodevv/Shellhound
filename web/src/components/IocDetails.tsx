import { useT } from '../i18n'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, post, type Ioc, type CrossCaseIocMatch } from '../api'
import { safeCtiUrl, useOpenCti } from '../opencti'
import { OpenCtiToolbar, OpenCtiScore } from './OpenCti'
import { Button, Card, Modal, CopyButton, Tabs } from './ui'
import { TraceWindow } from './TraceWindow'
import { FileViewer } from './FileViewer'
import { ArrowLeft, ArrowRight, ExternalLink } from 'lucide-react'
import { InfoDot, Tooltip } from './Tooltip'
import { descriptions, iocName, iocOrigins, observationTime } from './iocPresentation'
import { IocField } from './IocField'
import { IpFlag } from './IpFlag'
import { IocTypeBadge } from './IocTypeBadge'
import { IocAssessmentBadge } from './IocAssessmentBadge'
import { IocTags } from './IocTags'
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
  relationships: Relationship[]
  relationship_types: Record<string, { sources: string[]; targets: string[] }>
}
const field = 'w-full rounded-md border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px]'
const states = ['unassessed', 'suspicious', 'malicious', 'benign'] as const
const labels: Record<string, string> = {
  'hash-of': 'Hash of', requested: 'Requested', 'host-in': 'Appears in code of', 'account-of': 'Email of account',
  'located-at': 'Collected at', 'request-context': 'Request-path association', used: 'Used (evidence required)',
  executed: 'Executed (evidence required)', 'cve-context': 'Specific CVE context',
  'exploit-attempt': 'Exploitation attempt', 'exploitation-confirmed': 'Confirmed exploitation',
}

export function IocDetails({ slug, id, iocs, onClose, embedded = false, tab: controlledTab, onTab, onNavigate, gotoView, onDirtyChange, crossMatches = [] }: {
  slug: string; id: number; iocs: Ioc[]; onClose: () => void; embedded?: boolean; tab?: string; onTab?: (tab: string) => void
  onNavigate?: (id: number) => void; gotoView?: Navigate; onDirtyChange?: (dirty: boolean) => void; crossMatches?: CrossCaseIocMatch[]
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
  const tab = requestedTab === 'Trace' && data?.object.type === 'ip' ? 'Trace' : 'Overview'
  const setTab = (value: string) => { setLocalTab(value); onTab?.(value) }
  const [assessOpen, setAssessOpen] = useState(false)
  const [viewPath, setViewPath] = useState<string | null>(null)
  const [assessment, setAssessment] = useState<Ioc['assessment']>('malicious')
  const [reason, setReason] = useState('')
  useEffect(() => { onDirtyChange?.(Boolean(reason || (assessOpen && assessment !== data?.object.assessment))) }, [reason, assessOpen, assessment, data?.object.assessment, onDirtyChange])
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['iocs'] })
    qc.invalidateQueries({ queryKey: ['opencti', slug] })
  }
  const saveAssessment = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/iocs/${id}/assessments`, { state: assessment, reason }),
    onSuccess: () => { setReason(''); setAssessOpen(false); invalidate() }
  })
  const verifyFile = useMutation({ mutationFn: () => post<{ verified_locations: number; unavailable_or_changed_locations: number }>(`/api/cases/${slug}/iocs/${id}/verify-file`, {}), onSuccess: invalidate })
  const object = data?.object
  const failure = error || saveAssessment.error || verifyFile.error
  const current = iocs.find(i => i.id === id)
  const observed = data?.observations.filter(o => o.active) ?? []
  const times = observed.flatMap(o => [o.first_seen, o.last_seen]).filter(Boolean).sort()
  const links = data?.relationships.filter(r => r.active) ?? []
  const targetOf = (r: Relationship) => r.src === id ? r.dst : r.src
  const lookup = cti.data?.lookups?.find(entry => entry.ioc_id === id)
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
  const content = <div className={`flex flex-col gap-4 text-[13px] ${embedded ? 'p-4 sm:p-5' : ''}`}>

    {object && <header className="flex flex-wrap items-start gap-3">
      <div className="min-w-0 flex-1 basis-60">
        <div className="mb-2"><IocTypeBadge type={object.type} value={object.value} /></div>
        <div className="flex items-center gap-2">
          {object.type === 'ip' && <IpFlag ip={object.value} />}
          <h2 className="min-w-0 break-all text-xl font-semibold">{iocName(object)}</h2>
          <CopyButton value={object.value} label="Copy object value" />
          {ctiLinks.map(entity => <Tooltip key={entity.id} body={tr('cti.openObject', { name: entity.name || object.value })}>
            <a href={safeCtiUrl(entity.url)} target="_blank" rel="noopener noreferrer" aria-label={ctiLinks.length === 1 ? tr('cti.open') : tr('cti.openObject', { name: entity.name || entity.id })} className="ui-press inline-flex shrink-0 items-center rounded p-1.5 text-[var(--accent-text)] hover:bg-[var(--panel-2)]"><ExternalLink size={16} /></a>
          </Tooltip>)}
        </div>
        <div className="mt-2 flex items-center gap-2 text-[12px]">
          <IocAssessmentBadge assessment={object.assessment} />
        </div>
      </div>
      <OpenCtiToolbar
        mode="inline"
        leadingAction={<Button type="button" onClick={() => { setAssessment(object.assessment); setAssessOpen(v => !v) }}>{tr('iocWorkspace.change_assessment')}</Button>}
        slug={slug}
        iocs={iocs}
        selectedIds={[id, ...iocs.filter(i => i.file_ids?.includes(id)).map(i => i.id)]}
        onSelectAll={() => { }}
        onClear={() => { }}
        onSettings={() => gotoView?.('settings')} />
    </header>}

    {object && assessOpen && <form
      className="animate-fade-in space-y-3 rounded-lg border border-[var(--line)] p-3"
      onSubmit={e => { e.preventDefault(); saveAssessment.mutate() }}>
      <label className="block">
        {tr('iocWorkspace.new_assessment')}
        <select
          aria-label="New assessment"
          value={assessment}
          onChange={e => setAssessment(e.target.value as Ioc['assessment'])}
          className={field}>{states.map(s => <option key={s} value={s}>{s}</option>)}</select>
      </label>
      <label className="block">
        {tr('iocWorkspace.assessment_reason')}
        <textarea required value={reason} onChange={e => setReason(e.target.value)} className={field} />
      </label>
      <Button disabled={!reason.trim() || saveAssessment.isPending}>{tr('iocWorkspace.save_assessment')}</Button>
      <Button type="button" onClick={() => { setAssessOpen(false); setReason('') }}>{tr('iocWorkspace.cancel')}</Button>
            <details>
        <summary className="cursor-pointer text-[var(--accent-text)]">{tr('iocWorkspace.assessment_history')}</summary>
        <div className="mt-3 space-y-2">{!data?.assessments.length && <p>{tr('iocWorkspace.default_assessment_malicious')}</p>}{data?.assessments.map(a => <Card key={a.id} className="p-3">
          <strong>{a.state}</strong> ·
          {a.created}
          <p className="whitespace-pre-wrap">{a.reason}</p>
        </Card>)}</div>
      </details>
    </form>}

    <div className="overflow-x-auto" aria-label={tr('iocWorkspace.detail_tabs')}>
      <Tabs active={tab} onChange={setTab} tabs={['Overview', ...(object?.type === 'ip' ? ['Trace'] : [])].map(name => ({ id: name, label: tr(`iocWorkspace.tab.${name}`) }))} />
    </div>

    {failure && <p role="alert" className="text-[var(--danger-text)]">{String(failure instanceof Error ? failure.message : failure)}</p>}

    {isPending && <p>{tr('iocWorkspace.loading_case_details')}</p>}

    {object && tab === 'Overview' && <>
      {current?.resolved && <div><Button type="button" onClick={() => setViewPath(current.resolved!)}>{tr('iocWorkspace.view_file')}</Button></div>}
      <h3 className="ioc-section-title">{tr('iocWorkspace.observation')}</h3>
      <div className="grid grid-cols-1 gap-x-6 border-b border-[var(--line)] sm:grid-cols-2">

        <IocField name="First observed">{observationTime(times[0] || current?.first_seen)}</IocField>

        <IocField name="Last observed">{observationTime(times[times.length - 1] || current?.last_seen)}</IocField>

        <div className="min-w-0"><IocField name="Origin">
          <div className="space-y-1 break-words">{iocOrigins(object, observed, data?.findings ?? []).map(origin => <p key={origin}>{origin}</p>)}</div>
        </IocField>
        {cti.configured && <OpenCtiScore lookup={cti.data?.lookups?.find(entry => entry.ioc_id === id)} loading={cti.isPending} error={Boolean(cti.error)} />}
        </div>
        <IocField name={tr('iocTags.title')} help={tr(cti.configured ? 'iocTags.help' : 'iocTags.localHelp')}><IocTags key={object.id} slug={slug} object={object} /></IocField>
      </div>
      {object.file && <><div className="grid grid-cols-2 gap-x-6">
        <IocField name="Classification">{object.file.classification || 'Not classified'}</IocField>
        <IocField name="Size">{object.file.size == null ? 'Not verified' : `${object.file.size.toLocaleString()} bytes`}</IocField>
      </div><details className="rounded-lg border border-[var(--line)] p-3">
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
        </details></>}
      {object.legacy_warning && <details className="text-[var(--review-text)]">
        <summary className="cursor-pointer">{tr('iocWorkspace.review_legacy_metadata')}</summary>
        <p>{object.legacy_warning}</p>
      </details>}
      {!!object.context && <IocField name="Context">{object.path_context && object.type === 'path' ? `${object.path_context} · ` : ''}{object.context}</IocField>}
      <div>
        <div className="mb-3 flex items-center gap-2">
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

    {object?.type === 'ip' && tab === 'Trace' && <TraceWindow key={`${slug}:${id}`} slug={slug} ips={[object.value]} embedded onClose={() => setTab('Overview')} />}

    <FileViewer slug={slug} path={viewPath} layer={1} onClose={() => setViewPath(null)} />

  </div>
  return embedded ? content : <Modal open onClose={onClose} title={object ? iocName(object) : 'IOC details'}>{content}</Modal>
}
