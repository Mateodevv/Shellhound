import { useT } from '../i18n'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, del, patch, post, type Ioc, type CrossCaseIocMatch } from '../api'
import { useOpenCti } from '../opencti'
import { OpenCtiDetails, OpenCtiToolbar } from './OpenCti'
import { Button, Card, Modal, CopyButton } from './ui'
import { FileViewer } from './FileViewer'
import { TraceWindow } from './TraceWindow'
import { EnrichPanel } from './Enrich'
import { Crosshair, ChevronRight } from 'lucide-react'
import { InfoDot } from './Tooltip'
import { assessmentTone, ctiLabel, descriptions, iocName, observationTime } from './iocPresentation'
import { IocField } from './IocField'
import { defang } from '../defang'
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
  const tab = controlledTab || localTab
  const setTab = (value: string) => { setLocalTab(value); onTab?.(value) }
  const [assessOpen, setAssessOpen] = useState(false)
  const [editOpen, setEditOpen] = useState(false)
  const [relationshipOpen, setRelationshipOpen] = useState(false)
  const [trace, setTrace] = useState(false)
  const [intelligence, setIntelligence] = useState(false)
  const [contextDirty, setContextDirty] = useState(false)
  const [viewPath, setViewPath] = useState<string | null>(null)
  const [assessment, setAssessment] = useState<Ioc['assessment']>('malicious')
  const [reason, setReason] = useState('')
  const [src, setSrc] = useState(id)
  const [dst, setDst] = useState<number | ''>('')
  const [kind, setKind] = useState('')
  const [reference, setReference] = useState('')
  const [evidence, setEvidence] = useState('')
  const [observation, setObservation] = useState('')
  const [first, setFirst] = useState('')
  const [last, setLast] = useState('')
  const [withdrawId, setWithdrawId] = useState<number | null>(null)
  const [withdrawReason, setWithdrawReason] = useState('')
  useEffect(() => { onDirtyChange?.(Boolean(reason || reference || evidence || first || last || withdrawReason || contextDirty || (assessOpen && assessment !== data?.object.assessment) || (relationshipOpen && (kind || dst || observation)))) }, [reason, reference, evidence, first, last, withdrawReason, contextDirty, assessOpen, assessment, data?.object.assessment, relationshipOpen, kind, dst, observation, onDirtyChange])
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['iocs'] })
    qc.invalidateQueries({ queryKey: ['opencti', slug] })
  }
  const saveAssessment = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/iocs/${id}/assessments`, { state: assessment, reason }),
    onSuccess: () => { setReason(''); setAssessOpen(false); invalidate() }
  })
  const saveContext = useMutation({ mutationFn: (body: { context?: string; path_context?: string; type?: string; note?: string }) => patch(`/api/cases/${slug}/iocs/${id}`, body), onSuccess: () => { setContextDirty(false); setEditOpen(false); invalidate() } })
  const remove = useMutation({ mutationFn: () => del(`/api/cases/${slug}/iocs/${id}`), onSuccess: () => { invalidate(); onClose() } })
  const verifyFile = useMutation({ mutationFn: () => post<{ verified_locations: number; unavailable_or_changed_locations: number }>(`/api/cases/${slug}/iocs/${id}/verify-file`, {}), onSuccess: invalidate })
  const saveRelationship = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/ioc-relationships`, {
      src, dst, kind, reference, detail: evidence, observation_id: observation || null, first_seen: first, last_seen: last,
    }), onSuccess: () => { setReference(''); setEvidence(''); setFirst(''); setLast(''); setRelationshipOpen(false); invalidate() }
  })
  const withdraw = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/ioc-relationships/${withdrawId}/withdraw`, { reason: withdrawReason }),
    onSuccess: () => { setWithdrawId(null); setWithdrawReason(''); invalidate() }
  })
  const object = data?.object
  const source = iocs.find(i => i.id === src)
  const relationKinds = Object.entries(data?.relationship_types ?? {}).filter(([, types]) => types.sources.includes(source?.type ?? ''))
  const targets = iocs.filter(i => i.id !== src && data?.relationship_types[kind]?.targets.includes(i.type))
  const failure = error || saveAssessment.error || saveRelationship.error || withdraw.error || saveContext.error || verifyFile.error || remove.error
  const lookup = cti.data?.lookups?.find(entry => entry.ioc_id === id)
  const sync = cti.data?.sync?.find(entry => entry.ioc_id === id)
  const current = iocs.find(i => i.id === id)
  const observed = data?.observations.filter(o => o.active) ?? []
  const requests = observed.filter(o => ['pattern-hunt', 'http-request'].includes(o.kind) && o.count != null)
  const times = observed.flatMap(o => [o.first_seen, o.last_seen]).filter(Boolean).sort()
  const links = data?.relationships.filter(r => r.active) ?? []
  const targetOf = (r: Relationship) => r.src === id ? r.dst : r.src
  const relatedRow = (r: Relationship) => {
    const target = targetOf(r); const item = iocs.find(i => i.id === target); return <button
      key={r.id}
      onClick={() => onNavigate?.(target)}
      className="flex w-full items-center gap-3 border-b border-[var(--line)] px-3 py-3 text-left hover:bg-[var(--panel-2)]">
      <span className="min-w-0 flex-1">
        <span className="block truncate font-medium">{item ? iocName(item) : r.src === id ? r.dst_value : r.src_value}</span>
        <span className="text-[11px] text-[var(--muted)]">{r.src === id ? '→ ' : '← '}{labels[r.kind] || r.kind} · {r.evidence.length} {tr('iocWorkspace.references')}</span>
      </span>
      <ChevronRight size={14} />
    </button>
  }
  const content = <div className={`flex flex-col gap-4 text-[13px] ${embedded ? 'p-4 sm:p-5' : ''}`}>

    {object && <header className="flex flex-wrap items-start gap-3">
      <div className="min-w-0 flex-1">
        <span className="text-[11px] uppercase tracking-wide text-[var(--muted)]">{object.type}</span>
        <div className="flex items-center gap-2">
          <h2 className="min-w-0 break-all text-xl font-semibold">{iocName(object)}</h2>
          <CopyButton value={object.value} label="Copy object value" />
        </div>
        <div className="mt-2 flex items-center gap-2 text-[12px]">
          <span className={`rounded border border-current px-2 py-0.5 capitalize ${assessmentTone(object.assessment)}`}>{object.assessment}</span>
          <span className="text-[var(--muted)]">{object.assessment_manual ? 'Manually assessed' : 'Default assessment'}</span>
          <InfoDot body={descriptions['Case assessment']} />
        </div>
      </div>
      <Button type="button" onClick={() => { setAssessment(object.assessment); setAssessOpen(v => !v) }}>{tr('iocWorkspace.change_assessment')}</Button>
      <details className="relative">
        <summary className="cursor-pointer rounded-md border border-[var(--line)] px-3 py-2">{tr('iocWorkspace.opencti')}</summary>
        <div className="absolute right-0 z-20 w-[320px] max-w-[85vw] bg-[var(--panel)] shadow-xl">
          <OpenCtiToolbar
            mode="actions"
            slug={slug}
            iocs={iocs}
            selectedIds={[id, ...iocs.filter(i => i.file_ids?.includes(id)).map(i => i.id)]}
            onSelectAll={() => { }}
            onClear={() => { }}
            onSettings={() => gotoView?.('settings')} />
        </div>
      </details>
      <details>
        <summary
          className="cursor-pointer rounded-md border border-[var(--line)] px-3 py-2"
          aria-label="Object actions">…</summary>
        <div className="flex flex-wrap gap-2 py-2">
          <Button type="button" onClick={() => setEditOpen(v => !v)}>{tr('iocWorkspace.edit_object')}</Button>
          {['ip', 'domain', 'url', 'email'].includes(object.type) && <CopyButton value={defang(object.value, object.type)} label="Copy defanged" />}
          <Button
            variant="danger"
            onClick={() => { if (window.confirm('Remove this IOC and its local relationships?')) remove.mutate() }}>{tr('iocWorkspace.remove_ioc')}</Button>
        </div>
      </details>
    </header>}

    {object && assessOpen && <form
      className="space-y-3 rounded-lg border border-[var(--line)] p-3"
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
    </form>}

    {object && editOpen && <form
      key={`${id}:${object.note}`}
      className="space-y-3 rounded-lg border border-[var(--line)] p-3"
      onChange={() => setContextDirty(true)}
      onSubmit={e => { e.preventDefault(); const values = new FormData(e.currentTarget); saveContext.mutate({ type: String(values.get('type')), note: String(values.get('note')), ...(['path', 'user', 'other'].includes(String(values.get('type'))) ? { context: String(values.get('context') || ''), path_context: String(values.get('path_context') || 'unknown') } : {}) }) }}>
      <label className="block">
        {tr('iocWorkspace.type')}
        <select className={field} name="type" defaultValue={object.type}>{(object.type === 'file' ? ['file'] : ['ip', 'hash', 'url', 'domain', 'email', 'path', 'user', 'other', 'vulnerability']).map(t => <option key={t}>{t}</option>)}</select>
      </label>
      <label className="block">
        {tr('iocWorkspace.note')}
        <textarea className={field} name="note" defaultValue={object.note} />
      </label>
      <label className="block">
        {tr('iocWorkspace.system_account_context')}
        <input className={field} name="context" defaultValue={object.context} />
      </label>
      <label className="block">
        {tr('iocWorkspace.path_context')}
        <select className={field} name="path_context" defaultValue={object.path_context || 'unknown'}>{['unknown', 'http-request', 'system', 'local-evidence'].map(s => <option key={s}>{s}</option>)}</select>
      </label>
      <Button disabled={saveContext.isPending}>{tr('iocWorkspace.save_object')}</Button>
      <Button type="button" onClick={() => { setEditOpen(false); setContextDirty(false) }}>{tr('iocWorkspace.cancel')}</Button>
    </form>}

    <div
      role="tablist"
      aria-label="IOC details"
      className="flex flex-wrap gap-2 border-b border-[var(--line)] pb-3">
      {['Overview', 'Evidence', 'Relationships', 'OpenCTI'].map(name => <button
        key={name}
        role="tab"
        aria-selected={tab === name}

        onClick={() => setTab(name)}
        className={`rounded-md px-3 py-2 ${tab === name ? 'bg-[var(--panel-2)] text-[var(--accent-text)]' : 'text-[var(--muted)]'}`}>{name}</button>)}
    </div>

    {failure && <p role="alert" className="text-[var(--danger-text)]">{String(failure instanceof Error ? failure.message : failure)}</p>}

    {isPending && <p>{tr('iocWorkspace.loading_case_details')}</p>}

    {object && tab === 'Overview' && <>
      <div className="flex flex-wrap gap-2">
        {object.type === 'ip' && <><Button type="button" onClick={() => setTrace(true)}>
          <Crosshair size={14} />
          {tr('iocWorkspace.open_trace')}
        </Button><Button type="button" onClick={() => gotoView?.('logs', { search: object.value })}>{tr('iocWorkspace.access_logs')}</Button></>}
        {observed.some(o => o.kind === 'pattern-hunt') && <Button
          type="button"
          onClick={() => { const o = observed.find(o => o.kind === 'pattern-hunt'); gotoView?.('hunt', { section: o?.source_ref.match(/hunt-test:(\d+)/)?.[1] }) }}>{tr('iocWorkspace.pattern_hunt')}</Button>}
        {current?.resolved && <Button type="button" onClick={() => setViewPath(current.resolved!)}>{tr('iocWorkspace.view_file')}</Button>}
        {['ip', 'hash'].includes(object.type) && <Button type="button" onClick={() => setIntelligence(v => !v)}>{tr('iocWorkspace.stored_intelligence')}</Button>}
      </div>
      {intelligence && <EnrichPanel slug={slug} kind={object.type} value={object.value} />}
      <div className="grid grid-cols-1 gap-x-6 border-y border-[var(--line)] sm:grid-cols-2">

        <IocField name="First observed">{observationTime(times[0] || current?.first_seen)}</IocField>

        <IocField name="Last observed">{observationTime(times[times.length - 1] || current?.last_seen)}</IocField>

        <IocField name="Origin">
          <button className="text-[var(--accent-text)]" onClick={() => setTab('Evidence')}>{observed.some(o => o.kind === 'pattern-hunt') ? 'Pattern Hunt' : object.tags.includes('finding') ? 'Findings' : object.origin || 'Analyst'} →</button>
        </IocField>

        <IocField name="Matching requests">{requests.length ? <button className="text-[var(--accent-text)]" onClick={() => setTab('Evidence')}>{requests.length === 1 ? `${requests[0].count} requests` : `${requests.length} recorded groups`} →</button> : 'Not recorded'}</IocField>

        <IocField name="Evidence sources">
          <button className="text-[var(--accent-text)]" onClick={() => setTab('Evidence')}>{new Set(observed.map(o => o.evidence_id != null ? `evidence:${o.evidence_id}` : o.local_path).filter(Boolean)).size} {tr('iocWorkspace.sources')}</button>
        </IocField>

        <IocField name="Case assessment">
          <span className={`capitalize ${assessmentTone(object.assessment)}`}>{object.assessment}</span>
          <span className="ml-2 text-[var(--muted)]">{object.assessment_manual ? 'Manual' : 'Default'}</span>
        </IocField>

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
        <div className="mb-2 flex items-center gap-2 font-medium">
          {tr('iocWorkspace.relationships')}
          <InfoDot body={descriptions.Relationships} />
          <button className="ml-auto text-[12px] text-[var(--accent-text)]" onClick={() => setTab('Relationships')}>{tr('iocWorkspace.view_all')} {links.length} →</button>
        </div>
        <div className="overflow-hidden rounded-lg border border-[var(--line)]">{links.slice(0, 3).map(relatedRow)}{!links.length && <p className="p-3 text-[var(--muted)]">{tr('iocWorkspace.no_recorded_relationships')}</p>}</div>
      </div>
      <div className="rounded-lg border border-[var(--line)] p-3">
        <strong>{tr('iocWorkspace.opencti')}</strong>
        <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-3">
          <IocField name="OpenCTI match">
            <button className="text-[var(--accent-text)]" onClick={() => setTab('OpenCTI')}>{ctiLabel(lookup)} →</button>
          </IocField>
          <IocField name="Last checked">{lookup?.checked_at ? observationTime(lookup.checked_at) : 'Not checked'}</IocField>
          <IocField name="Transfer status">
            <span className={sync?.status === 'error' ? 'text-[var(--danger-text)]' : ''}>{sync?.status || 'New'}</span>
          </IocField>
        </div>
      </div>
      {object.note && <details>
        <summary className="cursor-pointer text-[var(--accent-text)]">{tr('iocWorkspace.analyst_note')}</summary>
        <p className="mt-2 whitespace-pre-wrap">{object.note}</p>
      </details>}
      <details>
        <summary className="cursor-pointer text-[var(--accent-text)]">{tr('iocWorkspace.assessment_history')}</summary>
        <div className="mt-3 space-y-2">{!data?.assessments.length && <p>{tr('iocWorkspace.default_assessment_malicious')}</p>}{data?.assessments.map(a => <Card key={a.id} className="p-3">
          <strong>{a.state}</strong> ·
          {a.created}
          <p className="whitespace-pre-wrap">{a.reason}</p>
        </Card>)}</div>
      </details>
      {crossMatches.length > 0 && <details>
        <summary className="cursor-pointer text-[var(--accent-text)]">{tr('iocWorkspace.also_seen_in')} {crossMatches.length} {tr('iocWorkspace.other_cases')}</summary>
        {crossMatches.map(m => <a
          className="mt-2 block text-[var(--accent-text)]"
          key={`${m.slug}:${m.id}`}
          href={`?view=iocbox&case=${encodeURIComponent(m.slug)}&ioc=${m.id}`}>{m.name || m.slug} · {m.reference}</a>)}
      </details>}
    </>}

    {data && tab === 'Evidence' && <>
      <div className="flex items-center gap-2">
        {tr('iocWorkspace.evidence')}
        <InfoDot body={descriptions.Evidence} />
      </div>
      {data.observations.map(o => <details key={o.id} className="space-y-2 rounded-lg border border-[var(--line)] p-3">
        <summary className="cursor-pointer">{o.kind} · {o.count != null ? `${o.count} observations` : o.path || 'Recorded source'}</summary>

        <strong>{o.kind}</strong> ·
        {o.active ? 'recorded' : 'withdrawn'}

        <p className="break-all">{o.path || o.source_ref}</p>

        {o.local_path && <p className="break-all text-[var(--muted)]">{tr('iocWorkspace.local_evidence')} {o.local_path}</p>}

        {o.local_path && (o.kind === 'file-location' || /[\\/]/.test(o.local_path)) && <Button type="button" onClick={() => setViewPath(o.local_path)}>{tr('iocWorkspace.view_evidence_file')}</Button>}

        <p>{o.evidence_id != null && `Evidence #${o.evidence_id} · `}{o.finding_id != null && `Finding #${o.finding_id} · `}{o.count != null && `${o.count} observations`}</p>

        {(o.first_seen || o.last_seen) && <p>{o.first_seen || 'Unknown start'} — {o.last_seen || 'Unknown end'} {tr('iocWorkspace.source_time')}</p>}

        <p className="whitespace-pre-wrap">{o.detail}</p>
        {o.kind === 'pattern-hunt' && <Button
          type="button"
          onClick={() => gotoView?.('hunt', { section: o.source_ref.match(/hunt-test:(\d+)/)?.[1] })}>{tr('iocWorkspace.open_pattern_hunt_test')}</Button>}

      </details>)}
      {data.sources.map(s => <p key={s.id} className="break-all">{s.active ? 'Active source' : 'Withdrawn source'} · {s.role}: {s.artifact}</p>)}
      {data.findings.map(f => <details key={f.id} className="rounded-md border border-[var(--line)] p-3">

        <summary>{tr('iocWorkspace.finding')}{f.id}: {f.rule} · {f.triage}{f.retired ? ' · retired' : ''}</summary>

        <p className="break-all">{f.artifact}</p>
        <pre className="whitespace-pre-wrap break-all">{f.evidence}</pre>

      </details>)}
      {!data.observations.length && !data.sources.length && !data.findings.length && <p>{tr('iocWorkspace.no_structured_evidence_recorded_existing_context_remains_in_the_overview')}</p>}
    </>}

    {data && tab === 'Relationships' && <>
      {Object.entries(data.relationships.reduce<Record<string, Relationship[]>>((groups, r) => { const key = r.active ? (iocs.find(i => i.id === targetOf(r))?.type || 'other') : 'withdrawn'; (groups[key] ??= []).push(r); return groups }, {})).map(([group, relations]) => <details key={group} open={group !== 'withdrawn'} className="space-y-3">
        <summary className="cursor-pointer capitalize font-medium">{group} ({relations?.length})</summary>
        {relations?.map(r => <Card key={r.id} className="space-y-2 p-3">

          <div>{relatedRow(r)}</div>

          <p>{r.origin} · {r.active ? 'active' : `withdrawn: ${r.withdrawal_reason}`}</p>

          <details>
            <summary className="cursor-pointer text-[var(--accent-text)]">{tr('iocWorkspace.evidence')} ({r.evidence.length})</summary>
            {r.evidence.map(e => <p key={e.id} className="whitespace-pre-wrap">{e.reference}{e.detail && `: ${e.detail}`}{(e.first_seen || e.last_seen) && ` (${e.first_seen} — ${e.last_seen})`}</p>)}
          </details>

          <details>
            <summary>{tr('iocWorkspace.history')}</summary>
            {r.events.map(e => <p key={e.id}>{e.created} · {e.action}: {e.reason}</p>)}
          </details>

          {r.active && <Button type="button" onClick={() => setWithdrawId(r.id)}>{tr('iocWorkspace.withdraw_relationship')}</Button>}

          {withdrawId === r.id && <form className="space-y-2" onSubmit={e => { e.preventDefault(); withdraw.mutate() }}>

            <label>
              {tr('iocWorkspace.withdrawal_reason')}
              <textarea
                required
                value={withdrawReason}
                onChange={e => setWithdrawReason(e.target.value)}
                className={field} />
            </label>

            <Button disabled={!withdrawReason.trim() || withdraw.isPending}>{tr('iocWorkspace.confirm_withdrawal')}</Button>

          </form>}

        </Card>)}
      </details>)}
      <Button type="button" onClick={() => setRelationshipOpen(v => !v)}>{tr('iocWorkspace.add_evidence_backed_relationship')}</Button>{relationshipOpen && <form
        className="space-y-2 border-t border-[var(--line)] pt-3"
        onSubmit={e => { e.preventDefault(); saveRelationship.mutate() }}>

        <strong>{tr('iocWorkspace.add_evidence_backed_relationship')}</strong>

        <label className="block">
          {tr('iocWorkspace.source')}
          <select
            value={src}
            onChange={e => { setSrc(Number(e.target.value)); setKind(''); setDst('') }}
            className={field}>
            {iocs.map(i => <option key={i.id} value={i.id}>{i.type}: {i.summary || i.value}</option>)}
          </select>
        </label>

        <label className="block">
          {tr('iocWorkspace.relationship')}
          <select required value={kind} onChange={e => { setKind(e.target.value); setDst('') }} className={field}>

            <option value="">{tr('iocWorkspace.choose_relationship')}</option>
            {relationKinds.map(([k]) => <option key={k} value={k}>{labels[k] || k}</option>)}

          </select>
        </label>

        <label className="block">
          {tr('iocWorkspace.target')}
          <select required value={dst} onChange={e => setDst(Number(e.target.value))} className={field}>

            <option value="">{tr('iocWorkspace.choose_target')}</option>
            {targets.map(i => <option key={i.id} value={i.id}>{i.type}: {i.summary || i.value}</option>)}

          </select>
        </label>


        <label className="block">
          {tr('iocWorkspace.evidence_reference')}
          <input
            required
            value={reference}
            onChange={e => setReference(e.target.value)}
            placeholder="Log source and line, finding ID, or analyst evidence reference"
            className={field} />
        </label>

        <label className="block">
          {tr('iocWorkspace.supporting_observation')}
          <select value={observation} onChange={e => setObservation(e.target.value)} className={field}>

            <option value="">{tr('iocWorkspace.use_the_reference_above')}</option>
            {data.observations.map(o => <option key={o.id} value={o.id}>{o.kind}: {o.path || o.source_ref}</option>)}

          </select>
        </label>

        <label className="block">
          {tr('iocWorkspace.evidence_explanation')}
          <textarea value={evidence} onChange={e => setEvidence(e.target.value)} className={field} />
        </label>

        <div className="grid grid-cols-2 gap-2">
          <label>
            {tr('iocWorkspace.first_observed')}
            <input type="datetime-local" value={first} onChange={e => setFirst(e.target.value)} className={field} />
          </label>

          <label>
            {tr('iocWorkspace.last_observed')}
            <input type="datetime-local" value={last} onChange={e => setLast(e.target.value)} className={field} />
          </label>
        </div>

        <Button disabled={!dst || !kind || !reference.trim() || saveRelationship.isPending}>{tr('iocWorkspace.add_relationship')}</Button>
        <Button
          type="button"
          onClick={() => { setRelationshipOpen(false); setReference(''); setEvidence(''); setFirst(''); setLast('') }}>{tr('iocWorkspace.cancel')}</Button>

      </form>}
    </>}

    {tab === 'OpenCTI' && <OpenCtiDetails lookup={cti.data?.lookups?.find(entry => entry.ioc_id === id)} />}

    {trace && object && <TraceWindow slug={slug} ips={[object.value]} onClose={() => setTrace(false)} />}

    <FileViewer slug={slug} path={viewPath} layer={1} onClose={() => setViewPath(null)} />

  </div>
  return embedded ? content : <Modal open onClose={onClose} title={object ? iocName(object) : 'IOC details'}>{content}</Modal>
}
