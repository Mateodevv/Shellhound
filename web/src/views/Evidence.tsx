// Evidence.tsx — register evidence paths, auto-detect, analyze, watch jobs.
import { useT } from '../i18n'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Archive, CheckCircle2, ChevronRight, FileText, FolderOpen, FolderSearch,
  HardDrive, Pencil, Play, Server, Trash2, TriangleAlert, XCircle,
} from 'lucide-react'
import {
  api, del, patch, post, type CaseDetail, type CaseSummary, type DetectResult,
  type EvidenceItem, type Job, type PickPath,
} from '../api'
import { absoluteTime, evidenceName, formatBytes, formatCount, relativeTime } from '../format'
import { Button, Card, EmptyState, ProgressBar, Section, Tag } from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { explain } from '../explain'
import type { ViewId } from '../App'

const KIND_ICON: Record<string, typeof HardDrive> = {
  webroot: Server,
  access_logs: FileText,
  sql_dump: HardDrive,
  reference: Server,
}

export function Evidence({ slug, onClosed }: {
  slug: string
  gotoView: (v: ViewId) => void
  onClosed?: () => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const { data: jobs } = useQuery({
    queryKey: ['jobs', slug],
    queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`),
    refetchInterval: 4000,
  })

  const [browsing, setBrowsing] = useState<null | 'webroot' | 'access_logs' | 'sql_dump' | 'reference'>(null)
  const [detectFolder, setDetectFolder] = useState('')
  const [detected, setDetected] = useState<DetectResult | null>(null)

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['case', slug] })
    qc.invalidateQueries({ queryKey: ['jobs', slug] })
  }

  const addEvidence = useMutation({
    mutationFn: (v: { kind: string; path: string }) =>
      post(`/api/cases/${slug}/evidence`, v),
    onSuccess: invalidate,
  })
  const removeEvidence = useMutation({
    mutationFn: (id: number) => del(`/api/cases/${slug}/evidence/${id}`),
    onSuccess: invalidate,
  })
  const renameEvidence = useMutation({
    mutationFn: (v: { id: number; label: string }) =>
      patch(`/api/cases/${slug}/evidence/${v.id}`, { label: v.label }),
    onSuccess: invalidate,
  })
  const analyze = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/analyze`),
    onSuccess: invalidate,
  })
  const detect = useMutation({
    mutationFn: () => post<DetectResult>('/api/detect', { folder: detectFolder }),
    onSuccess: setDetected,
  })

  const evidence = caseInfo?.evidence_items ?? []
  const index = caseInfo?.log_index

  return (
    <div className="flex flex-col gap-6">
      <Section
        title="Evidence"
        sub={tr('evidence.sub')}
        right={
          <Button variant="primary" disabled={!evidence.length || analyze.isPending}
            onClick={() => analyze.mutate()}>
            <Play size={14} /> {tr('evidence.analyze')}
          </Button>
        }
      >
        <div className="flex flex-col gap-2">
          {evidence.map((e) => (
            <EvidenceCard
              key={e.id}
              item={e}
              onRename={(label) => renameEvidence.mutate({ id: e.id, label })}
              onRemove={() => removeEvidence.mutate(e.id)}
            />
          ))}
          {!evidence.length && (
            <EmptyState
              icon={<FolderOpen size={36} />}
              title={tr('evidence.empty.title')}
              sub={tr('evidence.empty.sub')}
            />
          )}
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          {(['webroot', 'access_logs', 'sql_dump', 'reference'] as const).map((kind) => (
            <Tooltip key={kind} title={explain(tr, `evidence.${kind}`)?.what}
              hint={explain(tr, `evidence.${kind}`)?.why} wide>
              <Button onClick={() => setBrowsing(kind)}>
                <FolderOpen size={14} /> {tr('evidence.add', { what: tr(`evidence.${kind}`) })}
              </Button>
            </Tooltip>
          ))}
        </div>

        {index && evidence.some((e) => e.kind === 'access_logs') && (
          <Card className="mt-3 px-4 py-3">
            <div className="flex items-center gap-2 text-[13px]">
              {index.fresh
                ? <CheckCircle2 size={15} className="text-[var(--ok)]" />
                : <TriangleAlert size={15} className="text-[var(--sev-low)]" />}
              <span className="font-medium">{tr('evidence.logIndex')}</span>
              <InfoDot body={tr('field.log_index')} wide />
              {index.fresh ? (
                <span className="text-[var(--muted)]">
                  {tr('evidence.logIndex.fresh', {
                    lines: formatCount(index.lines),
                    clients: formatCount(index.clients),
                    size: formatBytes(index.size),
                  })}
                </span>
              ) : (
                <span className="text-[var(--muted)]">{index.reason}</span>
              )}
            </div>
          </Card>
        )}
      </Section>

      <Section
        title={tr('evidence.detect')}
        sub={tr('evidence.detect.hint')}
      >
        <div className="flex gap-2">
          <input
            value={detectFolder}
            onChange={(e) => setDetectFolder(e.target.value)}
            placeholder={tr('evidence.detect.placeholder')}
            className="mono flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
          <Button onClick={() => detect.mutate()} disabled={!detectFolder.trim() || detect.isPending}>
            <FolderSearch size={14} /> {tr('evidence.scan')}
          </Button>
        </div>
        {detected && (
          <div className="mt-3 flex flex-col gap-2 animate-fade-up">
            {detected.error && <div className="text-[13px] text-[var(--danger-text)]">{detected.error}</div>}
            {(['webroot', 'access_logs', 'sql_dump'] as const).map((kind) =>
              detected.candidates[kind]?.slice(0, 4).map((c) => (
                <Card key={kind + c.path} className="flex items-center gap-3 px-4 py-2.5">
                  <Tag tone="accent">{tr(`evidence.${kind}`)}</Tag>
                  <div className="min-w-0 flex-1">
                    <div className="mono truncate text-[12px]">{c.path}</div>
                    <div className="truncate text-[11px] text-[var(--muted)]">{c.why}</div>
                  </div>
                  <Button onClick={() => addEvidence.mutate({ kind, path: c.path })}>
                    {tr('common.apply')}
                  </Button>
                </Card>
              )))}
            {!detected.error &&
              Object.values(detected.candidates).every((c) => !c.length) && (
                <div className="text-[13px] text-[var(--muted)]">
                  {tr('evidence.noCandidates', { n: detected.scanned })}
                </div>
              )}
          </div>
        )}
      </Section>

      <Section title="Jobs" sub={tr('evidence.jobs.sub')}>
        <div className="flex flex-col gap-2">
          {(jobs ?? []).map((j) => <JobRow key={j.id} job={j} slug={slug} />)}
          {jobs && !jobs.length && (
            <div className="text-[13px] text-[var(--muted)]">{tr('evidence.noJobs')}</div>
          )}
        </div>
      </Section>

      <CloseCase slug={slug} caseName={caseInfo?.name ?? slug} onClosed={onClosed} />

      {browsing && (
        <PathBrowser
          kind={browsing}
          onClose={() => setBrowsing(null)}
          onPick={(path) => {
            addEvidence.mutate({ kind: browsing, path })
            setBrowsing(null)
          }}
        />
      )}
      {addEvidence.isError && (
        <div className="text-[13px] text-[var(--danger-text)]">{String(addEvidence.error)}</div>
      )}
    </div>
  )
}

function EvidenceCard({ item, onRename, onRemove }: {
  item: EvidenceItem
  onRename: (label: string) => void
  onRemove: () => void
}) {
  const tr = useT()
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState('')
  const Icon = KIND_ICON[item.kind] ?? HardDrive
  const displayName = evidenceName(item)

  return (
    <Card className="flex items-center gap-3 px-4 py-3">
      <Tooltip title={explain(tr, `evidence.${item.kind}`)?.what} hint={explain(tr, `evidence.${item.kind}`)?.why} wide>
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--panel-2)]">
          <Icon size={16} className="text-[var(--muted)]" />
        </div>
      </Tooltip>
      <div className="min-w-0 flex-1">
        {editing ? (
          <input
            autoFocus
            defaultValue={displayName}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') { onRename(name); setEditing(false) }
              if (e.key === 'Escape') setEditing(false)
            }}
            onBlur={() => { if (name.trim()) onRename(name); setEditing(false) }}
            className="w-full rounded-md border border-[var(--accent)]/60 bg-[var(--panel-2)] px-2 py-0.5 text-[14px] font-semibold outline-none"
          />
        ) : (
          <div className="flex items-center gap-2">
            <span className="truncate text-[14px] font-semibold">{displayName}</span>
            <button onClick={() => { setName(''); setEditing(true) }}
              className="shrink-0 cursor-pointer text-[var(--muted)] opacity-60 transition-opacity hover:opacity-100"
              title={tr('common.rename')}>
              <Pencil size={12} />
            </button>
            <Tag explain={explain(tr, `evidence.${item.kind}`)?.what}>{tr(`evidence.${item.kind}`)}</Tag>
            {!item.exists && <Tag tone="danger">{tr('evidence.pathMissing')}</Tag>}
          </div>
        )}
        <div className="mono mt-1 truncate text-[11.5px] text-[var(--muted)]" title={item.path}>
          {item.path}
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-4 text-[12px] text-[var(--muted)]">
        {item.exists && (item.files ?? 0) > 0 && (
          <Tooltip title={tr('evidence.scope')}
            body={`${tr('evidence.fileCount', { n: formatCount(item.files) })}, ${formatBytes(item.bytes)}${item.meta_partial ? ` (${tr('evidence.partialCount')})` : ''}`}>
            <span className="tabular whitespace-nowrap">
              {formatBytes(item.bytes)}
              <span className="ml-1 opacity-70">· {tr('evidence.fileCount', { n: formatCount(item.files) })}</span>
            </span>
          </Tooltip>
        )}
        {item.scanned_at ? (
          <Tooltip title={tr('evidence.lastAnalyzed')} body={absoluteTime(item.scanned_at)}>
            <span className="flex items-center gap-1 whitespace-nowrap text-[var(--ok)]">
              <CheckCircle2 size={13} /> {relativeTime(item.scanned_at)}
            </span>
          </Tooltip>
        ) : (
          <Tag tone="warn">{tr('evidence.notAnalyzed')}</Tag>
        )}
      </div>

      <Button variant="ghost" title={tr('evidence.remove')}
        onClick={onRemove}>
        <Trash2 size={14} />
      </Button>
    </Card>
  )
}

function CloseCase({ slug, caseName, onClosed }: {
  slug: string; caseName: string; onClosed?: () => void
}) {
  const tr = useT()
  const [asking, setAsking] = useState(false)
  const [typed, setTyped] = useState('')

  const { data: summary } = useQuery({
    queryKey: ['close-summary', slug],
    queryFn: () => api<CaseSummary>(`/api/cases/${slug}/summary`),
    enabled: asking,
  })

  const close = useMutation({
    mutationFn: () => post<{ file: string; archive: string; summary: CaseSummary }>(
      `/api/cases/${slug}/archive`),
    // After closing, the case no longer exists -- straight back to the start
    // page, where it appears under "closed cases".
    onSuccess: () => onClosed?.(),
  })

  return (
    <Section
      title={tr('evidence.close')}
      sub={tr('evidence.close.sub')}
    >
      {!asking ? (
        <Button variant="danger" onClick={() => { setAsking(true); setTyped('') }}>
          <Archive size={14} /> {tr('evidence.close.cta')}
        </Button>
      ) : (
        <Card className="flex flex-col gap-3 border-[var(--sev-high)]/40 p-4 animate-fade-up">
          <div className="flex items-start gap-2">
            <TriangleAlert size={16} className="mt-0.5 shrink-0 text-[var(--sev-high)]" />
            <div className="text-[13px]">
              <div className="font-semibold">{tr('evidence.workingCopyDeleted')}</div>
              <div className="mt-0.5 text-[var(--muted)]">
                {tr('evidence.close.body.a')}{' '}
                {tr('evidence.close.body.b')} <em>{tr('common.not')}</em>{' '}
                {tr('evidence.close.body.c')}
              </div>
            </div>
          </div>

          {summary && (
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
              {[
                ['Findings', formatCount(summary.findings)],
                [tr('triage.confirmed'), formatCount(summary.confirmed)],
                ['False Positives', formatCount(summary.dismissed)],
                ['IOCs', formatCount(summary.iocs)],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg bg-[var(--panel-2)] px-3 py-2">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                    {label}
                  </div>
                  <div className="mt-0.5 text-[15px] font-semibold tabular">{value}</div>
                </div>
              ))}
            </div>
          )}

          <div>
            <label className="text-[12px] text-[var(--muted)]">
              {tr('evidence.close.typeName')}: <span className="mono text-[var(--fg)]">{caseName}</span>
            </label>
            <input
              autoFocus
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && typed.trim() === caseName.trim()) close.mutate()
              }}
              className="mt-1 w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] outline-none focus:border-[var(--accent)]/70"
            />
          </div>

          <div className="flex gap-2">
            <Button variant="danger"
              disabled={typed.trim() !== caseName.trim() || close.isPending}
              onClick={() => close.mutate()}>
              <Archive size={14} /> {close.isPending ? 'Archiviere…' : tr('evidence.closeFinal')}
            </Button>
            <Button variant="ghost" onClick={() => setAsking(false)}>{tr('common.cancel')}</Button>
          </div>
          {close.isError && (
            <div className="text-[12px] text-[var(--danger-text)]">
              {String((close.error as Error)?.message ?? close.error)}
            </div>
          )}
        </Card>
      )}
    </Section>
  )
}

// Every kind the analysis can start. A kind without an entry here would fall
// back to its raw identifier, which is how `errorlog` and `yara` ended up in
// the job list under their internal names.
const JOB_KINDS = ['index_logs', 'webshell', 'cms', 'sqldb', 'errorlog', 'yara']

function JobRow({ job, slug }: { job: Job; slug: string }) {
  const tr = useT()
  const cancel = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/jobs/${job.id}/cancel`),
  })
  const stats = job.stats ?? {}
  const summary = Object.entries(stats)
    .filter(([, v]) => typeof v === 'number' && (v as number) > 0)
    .slice(0, 5)
    .map(([k, v]) => `${k}: ${formatCount(v as number)}`)
    .join(' · ')
  return (
    <Card className="px-4 py-3">
      <div className="flex items-center gap-3">
        {job.state === 'done' && <CheckCircle2 size={15} className="text-[var(--ok)]" />}
        {job.state === 'failed' && <XCircle size={15} className="text-[var(--sev-high)]" />}
        {job.state === 'cancelled' && <XCircle size={15} className="text-[var(--muted)]" />}
        {(job.state === 'running' || job.state === 'queued') && (
          <span className="h-2 w-2 shrink-0 animate-pulse-soft rounded-full bg-[var(--accent)]" />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="text-[13px] font-semibold">
              {JOB_KINDS.includes(job.kind) ? tr(`job.${job.kind}`) : job.kind}
            </span>
            <span className="text-[11px] text-[var(--muted)]">
              #{job.id} · {job.created?.slice(0, 16).replace('T', ' ')}
            </span>
          </div>
          {job.state === 'running' && (
            <div className="mt-1.5 flex items-center gap-2">
              <div className="flex-1"><ProgressBar value={job.progress} /></div>
              <span className="w-10 text-right text-[11px] text-[var(--muted)] tabular">
                {Math.round(job.progress * 100)}%
              </span>
            </div>
          )}
          {job.message && job.state === 'running' && (
            <div className="mt-1 truncate text-[11px] text-[var(--muted)]">{job.message}</div>
          )}
          {job.state === 'done' && summary && (
            <div className="mt-0.5 truncate text-[11px] text-[var(--muted)]">{summary}</div>
          )}
          {job.state === 'failed' && (
            <pre className="mono mt-1 max-h-24 overflow-auto whitespace-pre-wrap text-[11px] text-[var(--danger-text)]">
              {job.error}
            </pre>
          )}
        </div>
        {(job.state === 'running' || job.state === 'queued') && (
          <Button variant="ghost" onClick={() => cancel.mutate()}>{tr('common.cancel')}</Button>
        )}
      </div>
    </Card>
  )
}

function PathBrowser({ kind, onClose, onPick }: {
  kind: string
  onClose: () => void
  onPick: (path: string) => void
}) {
  const tr = useT()
  const [path, setPath] = useState('')
  // A clicked file wins against the directory it sits in -- otherwise one
  // would have to type the path for a SQL dump after all.
  const [picked, setPicked] = useState('')
  useEffect(() => { setPicked('') }, [path])
  const { data, isError, error } = useQuery({
    queryKey: ['pickpath', path],
    queryFn: () => api<PickPath>(`/api/pickpath?path=${encodeURIComponent(path)}`),
  })
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50 animate-fade-in" onClick={onClose} />
      <Card className="relative z-10 flex max-h-[80vh] w-[min(640px,92vw)] flex-col animate-fade-up">
        <div className="border-b border-[var(--line)] px-4 py-3">
          <div className="text-[14px] font-semibold">{tr('evidence.pick', { what: tr(`evidence.${kind}`) })}</div>
          <div className="mono mt-1 truncate text-[12px] text-[var(--muted)]">
            {data?.path || tr('evidence.drives')}
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {data?.parent != null && (
            <button
              className="flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-left text-[13px] text-[var(--muted)] hover:bg-[var(--panel-2)] cursor-pointer"
              onClick={() => setPath(data.parent!)}
            >
              {tr('evidence.parentDir')}
            </button>
          )}
          {isError && <div className="px-3 py-2 text-[13px] text-[var(--danger-text)]">{String(error)}</div>}
          {data?.dirs.map((d) => (
            <button
              key={d.path}
              className="group flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-left text-[13px] hover:bg-[var(--panel-2)] cursor-pointer"
              onClick={() => setPath(d.path)}
            >
              <FolderOpen size={14} className="text-[var(--muted)]" />
              <span className="min-w-0 flex-1 truncate">{d.name}</span>
              <ChevronRight size={14} className="text-[var(--muted)] opacity-0 transition-opacity group-hover:opacity-100" />
            </button>
          ))}
          {/* Files are selectable, not just decoration: a SQL dump IS a file,
              and whoever cannot see it cannot register it. */}
          {data?.files.map((f) => (
            <button
              key={f.path}
              className={clsx(
                'group flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-left text-[13px] cursor-pointer',
                picked === f.path
                  ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                  : 'hover:bg-[var(--panel-2)]')}
              onClick={() => setPicked(picked === f.path ? '' : f.path)}
            >
              <FileText size={14} className="shrink-0 text-[var(--muted)]" />
              <span className="min-w-0 flex-1 truncate">{f.name}</span>
              <span className="shrink-0 tabular text-[11px] text-[var(--muted)]">
                {formatBytes(f.size)}
              </span>
            </button>
          ))}
          {data?.truncated && (
            <div className="px-3 py-2 text-[12px] text-[var(--sev-low)]">
              {tr('evidence.truncated')}
            </div>
          )}
        </div>
        <div className="flex items-center justify-between gap-2 border-t border-[var(--line)] px-4 py-3">
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder={tr('evidence.typePath')}
            className="mono min-w-0 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] outline-none focus:border-[var(--accent)]/70"
          />
          <Button variant="ghost" onClick={onClose}>{tr('common.cancel')}</Button>
          <Button variant="primary" disabled={!picked && !data?.path && !path.trim()}
            onClick={() => onPick(picked || path || data!.path)}>
            {picked ? tr('evidence.useFile') : tr('evidence.useFolder')}
          </Button>
        </div>
      </Card>
    </div>
  )
}
