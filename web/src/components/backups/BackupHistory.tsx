import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, post } from '../../api'
import type { BackupDiff, BackupEntry, BackupHistoryData } from '../../backupApi'
import { useT } from '../../i18n'
import { formatBytes } from '../../format'
import { Button, Card, Modal, Tag, TriageBadge } from '../ui/ui'
import { sourceInput } from '../SourceTimezone'

export function BackupStatus({ entry }: { entry: BackupEntry }) {
  const tr = useT()
  if (!entry.file) return <span className="text-[var(--muted)]">{tr(entry.status === 'not_present' ? 'backups.not_present' : 'backups.unavailable')}</span>
  if (entry.stale) return <span className="text-[var(--review-text)]">{tr('backups.stale')}</span>
  if (entry.file.state !== 'ready') return <span className="text-[var(--review-text)]">{tr('backups.unavailable')}</span>
  if (entry.finding && ['new', 'reviewed'].includes(entry.finding.triage)) return <Tag tone="warn">{tr('backups.detections')}</Tag>
  if (entry.finding) return <TriageBadge state={entry.finding.triage} label={tr(`triage.${entry.finding.triage}`)} />
  if (entry.assessment?.state === 'dismissed') return <TriageBadge state="dismissed" label={tr('triage.dismissed')} />
  return <span className="text-[var(--muted)]">{tr(`backups.${entry.scan_state || 'not_analyzed'}`)}</span>
}

export function BackupHistory({ slug, data, onOpenFile, persist = false }: {
  slug: string; data: BackupHistoryData; onOpenFile?: (path: string) => void; persist?: boolean
}) {
  const tr = useT()
  const qc = useQueryClient()
  const chosen = (key: string, fallback: number) => {
    const id = persist ? Number(new URLSearchParams(location.search).get(key)) : 0
    return data.entries.some(e => e.snapshot.id === id) ? id : fallback
  }
  const [left, setLeft] = useState(() => chosen('backup_left', data.entries[0]?.snapshot.id ?? 0))
  const [right, setRight] = useState(() => chosen('backup_right', data.entries[1]?.snapshot.id ?? 0))
  const [showDiff, setShowDiff] = useState(false)
  const [note, setNote] = useState('')
  const diff = useQuery({ queryKey: ['backup-diff', slug, left, right, data.path], enabled: showDiff && !!left && !!right && left !== right,
    queryFn: () => api<BackupDiff>(`/api/cases/${slug}/backups/diff?${new URLSearchParams({ left: String(left), right: String(right), path: data.path })}`), retry: false })
  useEffect(() => {
    if (!persist) return
    const url = new URL(location.href)
    url.searchParams.set('backup_left', String(left)); url.searchParams.set('backup_right', String(right))
    history.replaceState(null, '', url)
  }, [left, right, persist])
  const add = useMutation({ mutationFn: (snapshot_id: number) => post(`/api/cases/${slug}/backups/findings`, { snapshot_id, path: data.path, note }),
    onSuccess: () => { for (const key of ['backups', 'backup-history', 'findings', 'dashboard', 'artifact']) qc.invalidateQueries({ queryKey: [key] }) } })
  return <div className="space-y-4">
    <p className="mono break-all text-sm">{data.path}</p>
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">{data.entries.map(entry => <Card key={entry.snapshot.id} className="min-w-0 space-y-2 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><strong className="text-sm">{entry.snapshot.label}</strong><BackupStatus entry={entry} /></div>
      <p className="text-xs text-[var(--muted)]">{entry.snapshot.captured_at || tr('sourceTime.unknown')} · {tr(`backups.${entry.snapshot.completeness}`)}</p>
      {entry.file && <>
        <p className="mono break-all text-[11px]">SHA-256: {entry.file.sha256 || '—'}</p>
        <p className="text-xs text-[var(--muted)]">{formatBytes(entry.file.size)}</p>
        <details className="text-xs"><summary className="cursor-pointer">{tr('backups.source')}</summary><p className="mono mt-2 break-all">{entry.file.artifact}</p></details>
        {entry.inheritance && entry.inheritance.origin !== entry.file.artifact && <p className="text-[11px] text-[var(--review-text)]">{tr('backups.inherited')}</p>}
        {entry.assessment && <p className="text-xs text-[var(--muted)]">{tr('backups.hashAssessment')}: {tr(`triage.${entry.assessment.state}`)}{entry.assessment.note && ` · ${entry.assessment.note}`}</p>}
        <div className="flex flex-wrap gap-2">{onOpenFile && <Button disabled={!entry.available || entry.stale} onClick={() => onOpenFile(entry.file!.artifact)}>{tr('artifact.openFile')}</Button>}
          {!entry.finding && <Button disabled={!entry.available || entry.stale || add.isPending} onClick={() => add.mutate(entry.snapshot.id)}>{tr('backups.addFinding')}</Button>}</div>
      </>}
    </Card>)}</div>
    <p className="text-xs text-[var(--muted)]">{tr('backups.missingHelp')}</p>
    <label className="flex flex-col gap-1 text-xs">{tr('backups.note')}<input value={note} onChange={event => setNote(event.target.value)} className={sourceInput} maxLength={4000} /></label>
    {add.error && <p role="alert" className="text-sm text-[var(--danger-text)]">{add.error.message}</p>}
    {add.isSuccess && <Tag tone="ok">{tr('backups.addedFinding')}</Tag>}
    {data.entries.length > 1 && <div className="space-y-3 border-t border-[var(--line)] pt-4">
      <div className="flex flex-wrap items-end gap-3">{([{ value: left, set: setLeft, label: 'backups.left' }, { value: right, set: setRight, label: 'backups.right' }]).map(field => <label key={field.label} className="flex min-w-40 flex-1 flex-col gap-1 text-xs">{tr(field.label)}<select className={sourceInput} value={field.value} onChange={event => { field.set(Number(event.target.value)); setShowDiff(false) }}>{data.entries.map(entry => <option key={entry.snapshot.id} value={entry.snapshot.id}>{entry.snapshot.label}</option>)}</select></label>)}
        <Button variant="primary" disabled={left === right || diff.isFetching} onClick={() => setShowDiff(true)}>{tr('backups.diff')}</Button></div>
      {showDiff && diff.isPending && <p role="status">{tr('common.loading')}</p>}
      {diff.error && <p role="alert" className="text-sm text-[var(--danger-text)]">{diff.error.message}</p>}
      {showDiff && diff.data && !diff.error && !diff.isFetching && <>
        {diff.data.sides.map((side, index) => side.limited && <p key={index} className="text-sm text-[var(--review-text)]">{side.label}: {side.limited}</p>)}
        {!!diff.data.lines.length && <pre tabIndex={0} aria-label={tr('backups.diff')} className="max-h-96 overflow-auto rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 text-xs">{diff.data.lines.map((line, index) => <span key={index} className={`block ${line.startsWith('+') ? 'text-[var(--ok)]' : line.startsWith('-') ? 'text-[var(--danger-text)]' : ''}`}>{line || ' '}</span>)}</pre>}
        {!diff.data.lines.length && !diff.data.sides.some(side => side.limited) && <p className="text-sm">{tr('backups.identical')}</p>}
        {diff.data.truncated && <p role="status" className="text-xs text-[var(--review-text)]">{tr('backups.diffLimited')}</p>}
      </>}
    </div>}
  </div>
}

export function ArtifactBackups({ slug, artifact, onOpenFile }: { slug: string; artifact: string; onOpenFile: (path: string) => void }) {
  const tr = useT()
  const [open, setOpen] = useState(false)
  const query = useQuery({ queryKey: ['backup-history', slug, artifact], queryFn: () => api<BackupHistoryData>(`/api/cases/${slug}/backups/artifact?${new URLSearchParams({ artifact })}`) })
  useEffect(() => setOpen(false), [slug, artifact])
  if (!query.data?.entries?.length && !query.error) return null
  return <>
    <Button className="shrink-0 self-start" onClick={() => setOpen(true)}>{tr('backups.history')} · {query.data?.entries.length ?? 0}</Button>
    {open && createPortal(<Modal open onClose={() => setOpen(false)} title={tr('backups.history')} layer={1}>
      {query.error ? <p role="alert">{query.error.message}</p> : query.data && <BackupHistory key={artifact} slug={slug} data={query.data} onOpenFile={onOpenFile} />}
    </Modal>, document.body)}
  </>
}
