import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, patch, post, type Ioc } from '../api'
import { useOpenCti } from '../opencti'
import { OpenCtiDetails } from './OpenCti'
import { Button, Card, Modal } from './ui'
import { FileViewer } from './FileViewer'

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

export function IocDetails({ slug, id, iocs, onClose }: { slug: string; id: number; iocs: Ioc[]; onClose: () => void }) {
  const qc = useQueryClient()
  const { data, error, isPending } = useQuery({ queryKey: ['iocs', slug, 'detail', id],
    queryFn: () => api<Detail>(`/api/cases/${slug}/iocs/${id}/detail`) })
  const cti = useOpenCti(slug)
  const [tab, setTab] = useState('Overview')
  const [viewPath, setViewPath] = useState<string | null>(null)
  const [assessment, setAssessment] = useState<Ioc['assessment']>('unassessed')
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
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['iocs'] })
    qc.invalidateQueries({ queryKey: ['opencti', slug] })
  }
  const saveAssessment = useMutation({ mutationFn: () => post(`/api/cases/${slug}/iocs/${id}/assessments`, { state: assessment, reason }),
    onSuccess: () => { setReason(''); invalidate() } })
  const saveContext = useMutation({ mutationFn: (body: { context: string; path_context: string }) => patch(`/api/cases/${slug}/iocs/${id}`, body), onSuccess: invalidate })
  const verifyFile = useMutation({ mutationFn: () => post<{ verified_locations: number; unavailable_or_changed_locations: number }>(`/api/cases/${slug}/iocs/${id}/verify-file`, {}), onSuccess: invalidate })
  const saveRelationship = useMutation({ mutationFn: () => post(`/api/cases/${slug}/ioc-relationships`, {
    src, dst, kind, reference, detail: evidence, observation_id: observation || null, first_seen: first, last_seen: last,
  }), onSuccess: () => { setReference(''); setEvidence(''); invalidate() } })
  const withdraw = useMutation({ mutationFn: () => post(`/api/cases/${slug}/ioc-relationships/${withdrawId}/withdraw`, { reason: withdrawReason }),
    onSuccess: () => { setWithdrawId(null); setWithdrawReason(''); invalidate() } })
  const object = data?.object
  const source = iocs.find(i => i.id === src)
  const relationKinds = Object.entries(data?.relationship_types ?? {}).filter(([, types]) => types.sources.includes(source?.type ?? ''))
  const targets = iocs.filter(i => i.id !== src && data?.relationship_types[kind]?.targets.includes(i.type))
  const failure = error || saveAssessment.error || saveRelationship.error || withdraw.error || saveContext.error || verifyFile.error
  return <Modal open onClose={onClose} title={object?.summary || object?.value || 'IOC details'}>
    <div className="flex flex-col gap-4 text-[13px]">
      <div role="tablist" aria-label="IOC details" className="flex flex-wrap gap-2 border-b border-[var(--line)] pb-3">
        {['Overview', 'Observations', 'Relationships', 'OpenCTI'].map(name => <button key={name} role="tab" aria-selected={tab === name}
          onClick={() => setTab(name)} className={`rounded-md px-3 py-2 ${tab === name ? 'bg-[var(--panel-2)] text-[var(--accent-text)]' : 'text-[var(--muted)]'}`}>{name}</button>)}
      </div>
      {failure && <p role="alert" className="text-[var(--danger)]">{String(failure instanceof Error ? failure.message : failure)}</p>}
      {isPending && <p>Loading case details…</p>}
      {object && tab === 'Overview' && <>
        <div><span className="uppercase text-[var(--muted)]">{object.type}</span><p className="mono break-all">{object.value}</p></div>
        {object.legacy_warning && <p className="text-[var(--warn)]">{object.legacy_warning}</p>}
        {object.file && <Card className="space-y-2 p-3">
          <p>{object.file.names.join(', ') || 'File content'}</p>
          <p>Size: {object.file.size == null ? 'Not verified' : `${object.file.size} bytes`}</p>
          <p>Recorded classification: {object.file.classification || 'Not classified'} · independent of case assessment</p>
          {Object.entries(object.file.hashes).map(([algorithm, value]) => <p key={algorithm} className="break-all"><strong>{algorithm}:</strong> <span className="mono">{value}</span></p>)}
          <Button disabled={verifyFile.isPending} onClick={() => verifyFile.mutate()}>Verify available file metadata</Button>
          {verifyFile.data && <p role="status">{verifyFile.data.verified_locations} matching locations verified; {verifyFile.data.unavailable_or_changed_locations} unavailable or changed.</p>}
        </Card>}
        {['path', 'user', 'other'].includes(object.type) && <form key={`${object.context}-${object.path_context}`} className="space-y-2" onSubmit={event => {
          event.preventDefault(); const values = new FormData(event.currentTarget)
          saveContext.mutate({ context: String(values.get('context') ?? ''), path_context: String(values.get('path_context') ?? object.path_context ?? 'unknown') })
        }}>
          <label className="block">System / account context<input name="context" defaultValue={object.context} className={field} /></label>
          {object.type === 'path' && <label className="block">Path context<select name="path_context" defaultValue={object.path_context} className={field}>
            <option value="unknown">Unspecified — review required</option><option value="http-request">HTTP request path</option>
            <option value="system">Path in the investigated system</option><option value="local-evidence">Local evidence path — never exported</option>
          </select></label>}
          <Button disabled={saveContext.isPending}>Save context</Button>
        </form>}
        {object.note && <p className="whitespace-pre-wrap">{object.note}</p>}
        <form className="space-y-2 border-t border-[var(--line)] pt-3" onSubmit={e => { e.preventDefault(); saveAssessment.mutate() }}>
          <p>Case assessment: <strong>{object.assessment ?? 'unassessed'}</strong></p>
          <p className="text-[var(--muted)]">Finding status and OpenCTI knowledge do not change this assessment.</p>
          <label className="block">New assessment<select aria-label="New assessment" value={assessment} onChange={e => setAssessment(e.target.value as Ioc['assessment'])} className={field}>
            {states.map(s => <option key={s} value={s}>{s}</option>)}
          </select></label>
          <label className="block">Assessment reason<textarea required value={reason} onChange={e => setReason(e.target.value)} className={field} /></label>
          <Button disabled={!reason.trim() || saveAssessment.isPending}>Save assessment</Button>
        </form>
        <div className="space-y-2"><strong>Assessment history</strong>{!data?.assessments.length && <p>No analyst assessment yet.</p>}
          {data?.assessments.map(a => <Card key={a.id} className="p-3"><strong>{a.state}</strong> · {a.created}<p className="whitespace-pre-wrap">{a.reason}</p></Card>)}
        </div>
      </>}
      {data && tab === 'Observations' && <>
        <p className="text-[var(--muted)]">Evidence paths below are local. Export previews remove local paths and respect evidence exclusions.</p>
        {data.observations.map(o => <Card key={o.id} className="space-y-1 p-3">
          <strong>{o.kind}</strong> · {o.active ? 'recorded' : 'withdrawn'}
          <p className="break-all">{o.path || o.source_ref}</p>
          {o.local_path && <p className="break-all text-[var(--muted)]">Local evidence: {o.local_path}</p>}
          {o.kind === 'file-location' && o.local_path && <Button onClick={() => setViewPath(o.local_path)}>View evidence file</Button>}
          <p>{o.evidence_id != null && `Evidence #${o.evidence_id} · `}{o.finding_id != null && `Finding #${o.finding_id} · `}{o.count != null && `${o.count} observations`}</p>
          {(o.first_seen || o.last_seen) && <p>{o.first_seen || 'Unknown start'} — {o.last_seen || 'Unknown end'} (source time)</p>}
          <p className="whitespace-pre-wrap">{o.detail}</p>
        </Card>)}
        {data.sources.map(s => <p key={s.id} className="break-all">{s.active ? 'Active source' : 'Withdrawn source'} · {s.role}: {s.artifact}</p>)}
        {data.findings.map(f => <details key={f.id} className="rounded-md border border-[var(--line)] p-3">
          <summary>Finding #{f.id}: {f.rule} · {f.triage}{f.retired ? ' · retired' : ''}</summary>
          <p className="break-all">{f.artifact}</p><pre className="whitespace-pre-wrap break-all">{f.evidence}</pre>
        </details>)}
        {!data.observations.length && !data.sources.length && !data.findings.length && <p>No structured evidence recorded. Existing context remains in the overview.</p>}
      </>}
      {data && tab === 'Relationships' && <>
        {data.relationships.map(r => <Card key={r.id} className="space-y-2 p-3">
          <p className="break-all">{r.src_value} → <strong>{labels[r.kind] || r.kind}</strong> → {r.dst_value}</p>
          <p>{r.origin} · {r.active ? 'active' : `withdrawn: ${r.withdrawal_reason}`}</p>
          {r.evidence.map(e => <p key={e.id} className="whitespace-pre-wrap">{e.reference}{e.detail && `: ${e.detail}`}{(e.first_seen || e.last_seen) && ` (${e.first_seen} — ${e.last_seen})`}</p>)}
          <details><summary>History</summary>{r.events.map(e => <p key={e.id}>{e.created} · {e.action}: {e.reason}</p>)}</details>
          {r.active && <Button onClick={() => setWithdrawId(r.id)}>Withdraw relationship</Button>}
          {withdrawId === r.id && <form className="space-y-2" onSubmit={e => { e.preventDefault(); withdraw.mutate() }}>
            <label>Withdrawal reason<textarea required value={withdrawReason} onChange={e => setWithdrawReason(e.target.value)} className={field} /></label>
            <Button disabled={!withdrawReason.trim() || withdraw.isPending}>Confirm withdrawal</Button>
          </form>}
        </Card>)}
        <form className="space-y-2 border-t border-[var(--line)] pt-3" onSubmit={e => { e.preventDefault(); saveRelationship.mutate() }}>
          <strong>Add evidence-backed relationship</strong>
          <label className="block">Source<select value={src} onChange={e => { setSrc(Number(e.target.value)); setKind(''); setDst('') }} className={field}>
            {iocs.map(i => <option key={i.id} value={i.id}>{i.type}: {i.summary || i.value}</option>)}
          </select></label>
          <label className="block">Relationship<select required value={kind} onChange={e => { setKind(e.target.value); setDst('') }} className={field}>
            <option value="">Choose relationship</option>{relationKinds.map(([k]) => <option key={k} value={k}>{labels[k] || k}</option>)}
          </select></label>
          <label className="block">Target<select required value={dst} onChange={e => setDst(Number(e.target.value))} className={field}>
            <option value="">Choose target</option>{targets.map(i => <option key={i.id} value={i.id}>{i.type}: {i.summary || i.value}</option>)}
          </select></label>
          <p className="text-[var(--muted)]">Add a CVE identifier to the IOC box to use it as a target. An HTTP response alone does not prove execution or exploitation.</p>
          <label className="block">Evidence reference<input required value={reference} onChange={e => setReference(e.target.value)} placeholder="Log source and line, finding ID, or analyst evidence reference" className={field} /></label>
          <label className="block">Supporting observation<select value={observation} onChange={e => setObservation(e.target.value)} className={field}>
            <option value="">Use the reference above</option>{data.observations.map(o => <option key={o.id} value={o.id}>{o.kind}: {o.path || o.source_ref}</option>)}
          </select></label>
          <label className="block">Evidence explanation<textarea value={evidence} onChange={e => setEvidence(e.target.value)} className={field} /></label>
          <div className="grid grid-cols-2 gap-2"><label>First observed<input type="datetime-local" value={first} onChange={e => setFirst(e.target.value)} className={field} /></label>
            <label>Last observed<input type="datetime-local" value={last} onChange={e => setLast(e.target.value)} className={field} /></label></div>
          <Button disabled={!dst || !kind || !reference.trim() || saveRelationship.isPending}>Add relationship</Button>
        </form>
      </>}
      {tab === 'OpenCTI' && <OpenCtiDetails lookup={cti.data?.lookups?.find(entry => entry.ioc_id === id)} />}
      <FileViewer slug={slug} path={viewPath} layer={1} onClose={() => setViewPath(null)} />
    </div>
  </Modal>
}
