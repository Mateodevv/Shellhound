// ArtifactWindow.tsx -- one bounded evidence workspace and an explicit save.
//
// Hostile files are only ever rendered as inert JSON text. VirusTotal remains
// manual and receives only SHA-256; "show in file manager" selects the file
// and never executes it. The same review window is shared by every view.
import { plural, useT } from '../i18n'
import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowLeft, Bug, Check, Crosshair, Eye, Expand, FileSearch, FolderOpen,
  LoaderCircle, ShieldCheck, ShieldOff, X,
} from 'lucide-react'
import { KIND_ICON } from '../artifactKinds'
import {
  api, post, type ArtifactContext, type Finding, type TriageResult, type TriageState,
} from '../api'
import {
  SEVERITY_VAR, absoluteTime, formatBytes, formatCount,
  formatDay, relativeTime, relativeToRoot, type EvidenceRoot,
} from '../format'
import { Button, CopyButton, Modal, SeverityBadge, Tag, TriageBadge } from './ui'
import { InfoDot, Tooltip } from './Tooltip'
import { IpFlag } from './IpFlag'
import type { TraceMarks } from './TraceWindow'
import { explainRule } from '../explain'
import { EnrichPanel } from './Enrich'
import { FileContentPane } from './FileViewer'

const KIND_THIS: Record<string, string> = {
  file: 'artifact.this.file', table: 'artifact.this.table',
  client: 'artifact.this.client', dump: 'artifact.this.dump',
}

type Decision = Exclude<TriageState, 'new'>

/** The minimum the window can be opened with. The authoritative context and
 * note are always fetched before any decision control becomes usable. */
export interface ArtifactStub {
  artifact: string
  artifact_kind: 'file' | 'table' | 'client' | 'dump'
  worst: number
  triage: TriageState
  triage_note: string
  items?: Finding[]
}

function MetaCell({ label, children, explain }: {
  label: string; children: React.ReactNode; explain?: string
}) {
  return (
    <div className="rounded-lg bg-[var(--panel-2)] px-3 py-2">
      <div className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
        {label}{explain && <InfoDot body={explain} />}
      </div>
      <div className="mt-0.5 text-[12px]">{children}</div>
    </div>
  )
}

function Block({ title, children, right, className }: {
  title: React.ReactNode; children: React.ReactNode; right?: React.ReactNode; className?: string
}) {
  return (
    <div className={className}>
      <div className="mb-1 flex shrink-0 items-center justify-between gap-2">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
          {title}
        </div>
        {right}
      </div>
      {children}
    </div>
  )
}

function Reasons({ findings, artifact, onView, bounded = false }: {
  findings: Finding[]
  artifact: string
  onView: (path: string, line: number | null) => void
  bounded?: boolean
}) {
  const tr = useT()
  return (
    <Block title={tr('artifact.whyFlagged', { n: formatCount(findings.length) })}
      className={clsx('flex min-h-0 flex-col', bounded && 'max-h-[42%]')}>
      <div className={clsx('flex flex-col gap-1.5', bounded && 'min-h-0 overflow-y-auto pr-1')}>
        {findings.map((finding) => {
          const explanation = explainRule(tr, finding.rule)
          return (
            <div key={finding.fingerprint}
              className={clsx('rounded-lg border-l-2 bg-[var(--panel-2)] px-3 py-2',
                finding.retired === 1 && 'opacity-60')}
              style={{ borderLeftColor: SEVERITY_VAR[finding.severity] }}>
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <span className="text-[12.5px] font-semibold">{finding.rule}</span>
                {finding.retired !== 1 && finding.line != null && finding.line !== 0 && (
                  <button className="cursor-pointer text-[11px] text-[var(--accent-text)] hover:underline"
                    onClick={() => onView(artifact, finding.line)}>
                    {tr('artifact.line')} {finding.line}
                  </button>
                )}
                {finding.retired === 1 && (
                  <span className="text-[11px] text-[var(--muted)]">
                    {tr('artifact.retired', { date: finding.last_seen })}
                  </span>
                )}
              </div>
              {explanation && (
                <div className="mt-1 text-[12px] leading-snug">
                  {explanation.what}
                  {explanation.why && <span className="text-[var(--muted)]"> {explanation.why}</span>}
                </div>
              )}
              {finding.evidence && (
                <pre className="mono mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-[var(--code-bg)] px-2 py-1 text-[11px] leading-relaxed text-[#e6edf3]">
                  {finding.evidence}
                </pre>
              )}
            </div>
          )
        })}
      </div>
    </Block>
  )
}

function Clients({ ips, marks, onTrace }: {
  ips: ArtifactContext['related_ips']
  marks: TraceMarks
  onTrace: (ips: string[], marks?: TraceMarks) => void
}) {
  const tr = useT()
  return (
    <Block title={<span className="flex items-center gap-1.5">
      <Crosshair size={12} /> {tr('artifact.clientsHere')} ({ips.length})
    </span>} right={ips.length > 1 && (
      <button className="cursor-pointer text-[11px] text-[var(--accent-text)] hover:underline"
        onClick={() => onTrace(ips.map((entry) => entry.ip), marks)}>
        {tr('artifact.traceAll')}
      </button>
    )}>
      {ips.length ? (
        <div className="flex max-h-64 flex-col gap-1 overflow-y-auto">
          {ips.map((entry) => (
            <div key={entry.ip}
              className="flex items-center gap-2 rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[12px]">
              <IpFlag ip={entry.ip} />
              <span className="mono font-medium">{entry.ip}</span>
              {entry.in_box && <Tag tone="accent" explain={tr('artifact.ipInBox')}>IOC</Tag>}
              <span className="min-w-0 flex-1 truncate text-[11.5px] text-[var(--muted)]"
                title={entry.why}>{entry.why}</span>
              {entry.hits != null && (
                <span className="shrink-0 text-[var(--muted)] tabular">
                  {formatCount(entry.hits)}× · {formatCount(entry.ok_hits)}× 2xx
                </span>
              )}
              <Button variant="ghost" className="shrink-0"
                onClick={() => onTrace([entry.ip], marks)}>
                <Crosshair size={12} /> Trace
              </Button>
            </div>
          ))}
        </div>
      ) : <div className="text-[12px] text-[var(--muted)]">{tr('artifact.noClients')}</div>}
    </Block>
  )
}

function ContextPreview({ preview, onExpand }: {
  preview: NonNullable<ArtifactContext['file']>['preview'] | undefined
  onExpand: () => void
}) {
  const tr = useT()
  return (
    <Block className="flex min-h-[12rem] flex-1 flex-col"
      title={<>{tr('artifact.fileContent')}{' '}
        {preview?.focus
          ? tr('artifact.aroundLine', { n: preview.focus })
          : tr('artifact.fromStart')}
        {preview?.truncated && ` — ${tr('artifact.readTruncated')}`}</>}
      right={<Button variant="default" onClick={onExpand}>
        <Expand size={13} /> {tr('artifact.expandFile')}
      </Button>}>
      {preview && !preview.error && !preview.binary && preview.lines ? (
        <div className="mono min-h-0 flex-1 overflow-auto rounded-lg bg-[var(--code-bg)] py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
          {preview.lines.map((line, index) => {
            const number = (preview.from_line ?? 1) + index
            const hit = number === preview.focus
            return (
              <div key={number} className={clsx('flex px-3', hit && 'bg-[rgba(208,59,59,0.18)]')}>
                <span className={clsx('w-10 shrink-0 select-none pr-3 text-right',
                  hit ? 'text-[#ff8b8b]' : 'text-[#4b5566]')}>{number}</span>
                <span className="whitespace-pre-wrap break-all">{line || ' '}</span>
              </div>
            )
          })}
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 items-center justify-center rounded-lg bg-[var(--panel-2)] px-4 text-center text-[12px] text-[var(--muted)]">
          {preview?.binary ? tr('artifact.binaryNoPreview')
            : preview?.error || tr('artifact.previewUnavailable')}
        </div>
      )}
    </Block>
  )
}

export function ArtifactWindow({ slug, artifact, roots, collected, onClose,
                                 onSave, onSavedNext, onView, onTrace }: {
  slug: string
  artifact: ArtifactStub | null
  roots: EvidenceRoot[]
  collected: TriageResult['collected']
  onClose: () => void
  onSave: (state: Decision, note: string) => Promise<TriageResult>
  /** Present only when the caller owns a meaningful filtered Findings queue. */
  onSavedNext?: (result: TriageResult) => void
  onView: (path: string, line: number | null) => void
  onTrace: (ips: string[], marks?: TraceMarks) => void
}) {
  const tr = useT()
  const [note, setNote] = useState('')
  const [noteLoadedFor, setNoteLoadedFor] = useState<string | null>(null)
  const [draftDecision, setDraftDecision] = useState<Decision | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [expanded, setExpanded] = useState(false)
  const [revealError, setRevealError] = useState('')

  const { data: ctx, isError: contextError } = useQuery({
    queryKey: ['artifact', slug, artifact?.artifact],
    queryFn: () => api<ArtifactContext>(
      `/api/cases/${slug}/artifact?artifact=${encodeURIComponent(artifact!.artifact)}`),
    enabled: !!artifact,
  })

  const reveal = useMutation({
    mutationFn: (path: string) => post(`/api/cases/${slug}/reveal-file`, { path }),
    onMutate: () => setRevealError(''),
    onError: (error) => setRevealError(String((error as Error)?.message ?? error)),
  })

  // The server note is authoritative. It seeds once per matching artifact;
  // refetches never overwrite reasoning that is currently being typed.
  const noteFor = useRef<string | null>(null)
  useEffect(() => {
    if (!artifact) {
      noteFor.current = null
      setNoteLoadedFor(null)
      return
    }
    setDraftDecision(null)
    setSaveError('')
    setExpanded(false)
    setRevealError('')
    if (noteFor.current === artifact.artifact) return
    if (ctx?.artifact === artifact.artifact) {
      noteFor.current = artifact.artifact
      setNote(ctx.triage_note ?? '')
      setNoteLoadedFor(artifact.artifact)
    } else {
      setNote('')
      setNoteLoadedFor(null)
    }
  }, [artifact, ctx])

  if (!artifact) return null
  const kind = artifact.artifact_kind
  const file = ctx?.file
  const fileHashes = file?.hashes ?? (file?.sha256 ? { sha256: file.sha256 } : {})
  const actor = ctx?.actor
  const findings = ctx?.findings ?? artifact.items ?? []
  const state: TriageState = ctx?.triage ?? artifact.triage
  const worst = ctx?.worst ?? artifact.worst
  const ips = ctx?.related_ips ?? []
  const { root, rel } = relativeToRoot(artifact.artifact, roots)
  const rootName = root && (root.label?.trim() ||
    root.path.replace(/\\/g, '/').replace(/\/+$/, '').split('/').pop())
  const displayedIdentity = kind === 'file' && root
    ? `${rootName} · ${rel}`
    : artifact.artifact
  const contextReady = ctx?.artifact === artifact.artifact && noteLoadedFor === artifact.artifact
  const controlsDisabled = !contextReady || saving
  const Icon = KIND_ICON[kind] ?? Bug
  const focusLine = findings.find((finding) => finding.line)?.line ?? null

  const marks: TraceMarks = kind === 'file'
    ? { contains: [root ? rel : artifact.artifact.replace(/\\/g, '/')],
        reason: tr('marks.fileFetched') }
    : { exact: (actor?.alerts ?? []).map((alert) => alert.example).filter(Boolean),
        reason: tr('marks.alertTrigger') }

  const save = async (intent: 'stay' | 'next' | 'close') => {
    if (!draftDecision || controlsDisabled) return
    setSaving(true)
    setSaveError('')
    try {
      const result = await onSave(draftDecision, note)
      if (result.updated === 0) return
      setDraftDecision(null)
      if (intent === 'next' && onSavedNext) onSavedNext(result)
      else if (intent === 'close') onClose()
    } catch (error) {
      setSaveError(String((error as Error)?.message ?? error))
    } finally {
      setSaving(false)
    }
  }

  const identity = (
    <Block title={tr(`kind.${kind}`)}>
      <div className="mono flex items-center gap-2 break-all rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[12px]">
        <span className="min-w-0 flex-1" title={artifact.artifact}>{displayedIdentity}</span>
        <CopyButton value={artifact.artifact} label={tr('copy.path')} className="shrink-0" />
      </div>
      <div className="mt-2 flex flex-wrap gap-2">
        {kind === 'file' && file?.exists && <>
          <Button onClick={() => setExpanded(true)}>
            <FileSearch size={14} /> {tr('artifact.expandFile')}
          </Button>
          <Button onClick={() => reveal.mutate(artifact.artifact)} disabled={reveal.isPending}>
            <FolderOpen size={14} /> {tr('artifact.showInFileManager')}
          </Button>
        </>}
        {kind === 'client' && (
          <Button onClick={() => onTrace([artifact.artifact], marks)}>
            <Crosshair size={14} /> {tr('artifact.openTrace')}
          </Button>
        )}
      </div>
      {revealError && (
        <div role="alert" className="mt-2 text-[12px] text-[var(--danger-text)]">
          {tr('artifact.revealError')}: {revealError}
        </div>
      )}
    </Block>
  )

  const fileFacts = file && (
    <div className="grid grid-cols-2 gap-2">
      <MetaCell label={tr('artifact.size')}>
        {file.exists ? formatBytes(file.size) : tr('artifact.fileMissing')}
      </MetaCell>
      <MetaCell label={tr('artifact.modified')} explain={tr('artifact.mtime.hint')}>
        <Tooltip title={absoluteTime(file.mtime)}><span>{relativeTime(file.mtime)}</span></Tooltip>
      </MetaCell>
      <MetaCell label={tr('artifact.cmsGuard')} explain={tr('field.cms_guard')}>
        {file.cms_guard == null ? '—' : file.cms_guard ? (
          <span className="flex items-center gap-1 text-[var(--ok)]">
            <ShieldCheck size={12} /> {tr('artifact.guard.present')}
          </span>
        ) : (
          <span className="flex items-center gap-1 text-[var(--sev-high)]">
            <ShieldOff size={12} /> {tr('artifact.guard.missing')}
          </span>
        )}
      </MetaCell>
      <MetaCell label={tr('artifact.uploadDir')} explain={tr('field.upload_dir')}>
        {file.in_upload_dir
          ? <span className="text-[var(--sev-medium)]">{tr('artifact.uploadDirYes')}</span>
          : tr('artifact.uploadDirNo')}
      </MetaCell>
      {Object.values(fileHashes).some(Boolean) && (
        <div className="col-span-2 flex flex-col gap-2">
          {([
            ['MD5', fileHashes.md5], ['SHA-1', fileHashes.sha1], ['SHA-256', fileHashes.sha256],
          ] as const).filter(([, value]) => value).map(([label, value]) => (
            <MetaCell key={label} label={label}
              explain={label === 'SHA-256' ? tr('field.sha256') : tr('files.hashes.compatibility')}>
              <span className="mono flex items-center gap-2 break-all text-[11px]">
                <span className="min-w-0 flex-1">{value}</span>
                <CopyButton value={value!} label={tr('copy.hash')} className="shrink-0" />
              </span>
            </MetaCell>
          ))}
          <p className="text-[9.5px] text-[var(--muted)]">{tr('files.hashes.caution')}</p>
          {fileHashes.sha256 && (
            <EnrichPanel slug={slug} kind="hash" value={fileHashes.sha256} prominent />
          )}
        </div>
      )}
    </div>
  )

  const nonFileContext = <>
    {kind === 'client' && actor && (
      <div className="flex flex-col gap-2">
        <EnrichPanel slug={slug} kind="ip" value={artifact.artifact} />
        <div className="grid grid-cols-2 gap-2">
          <MetaCell label={tr('table.requests')}>{formatCount(actor.actor.requests)}</MetaCell>
          <MetaCell label={tr('field.period')}>
            {formatDay(actor.actor.first_epoch, actor.actor.tz)} → {formatDay(actor.actor.last_epoch, actor.actor.tz)}
          </MetaCell>
          <MetaCell label={tr('artifact.errors')}>{formatCount(actor.actor.err4 + actor.actor.err5)}</MetaCell>
          <MetaCell label={tr('artifact.loginPosts')}>
            {formatCount(actor.actor.login_posts)}
            {actor.actor.login_redirects > 0 &&
              <span className="text-[var(--sev-high)]"> · {actor.actor.login_redirects} Redirects!</span>}
          </MetaCell>
        </div>
        {actor.alerts.length > 0 && (
          <div className="flex flex-col gap-1">
            {actor.alerts.map((alert, index) => (
              <div key={index} className="rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[12px]">
                <SeverityBadge severity={alert.severity} /> <span className="ml-1">{alert.detail}</span>
                {alert.example && <div className="mono mt-0.5 truncate text-[11px] text-[var(--muted)]">{alert.example}</div>}
              </div>
            ))}
          </div>
        )}
        <Block title={tr('artifact.topUris')}>
          <div className="flex flex-col gap-0.5">
            {actor.top_paths.map((path) => (
              <div key={path.uri} className="flex items-center gap-2 text-[12px]">
                <span className="mono min-w-0 flex-1 truncate" title={path.uri}>{path.uri}</span>
                <span className="shrink-0 text-[var(--muted)] tabular">{path.n}× · {path.ok}× 2xx</span>
              </div>
            ))}
          </div>
        </Block>
        {actor.top_agents.length > 0 && (
          <div className="text-[11px] text-[var(--muted)]">
            {tr('artifact.userAgents')} {actor.top_agents.map((entry) =>
              `${entry.agent || tr('artifact.emptyAgent')} (${entry.n}×)`).join(' · ')}
          </div>
        )}
      </div>
    )}
    {ctx?.table && (
      <div className="grid grid-cols-2 gap-2">
        <MetaCell label={tr('artifact.rowsInDump')}>{formatCount(ctx.table.rows)}</MetaCell>
        <MetaCell label={tr('artifact.columns')}>{ctx.table.columns}</MetaCell>
        <MetaCell label={tr('artifact.dumpBytes')}>{formatBytes(ctx.table.bytes)}</MetaCell>
        <MetaCell label="CMS">{ctx.table.cms || '—'}</MetaCell>
        {ctx.table.col_list && <div className="col-span-2">
          <MetaCell label={tr('artifact.columnsInDump')}>
            <span className="mono break-all text-[11px]">{ctx.table.col_list}</span>
          </MetaCell>
        </div>}
      </div>
    )}
    {ctx?.dump && (
      <div className="grid grid-cols-2 gap-2">
        <MetaCell label={tr('database.statements')}>{formatCount(ctx.dump.statements)}</MetaCell>
        <MetaCell label={tr('artifact.size')}>{formatBytes(ctx.dump.size)}</MetaCell>
        <MetaCell label="CMS">{ctx.dump.cms || '—'}</MetaCell>
        <MetaCell label={tr('database.fact.created')}>{ctx.dump.meta?.created || '—'}</MetaCell>
      </div>
    )}
  </>

  const decisions: Array<{ state: Decision; label: string; icon: typeof Check; selected: string }> = [
    { state: 'confirmed', label: tr('artifact.truePositiveCollect'), icon: Check,
      selected: 'border-[var(--incident)] bg-[var(--danger-soft)] text-[var(--danger-text)]' },
    { state: 'reviewed', label: tr('artifact.reviewedAction'), icon: Eye,
      selected: 'border-[var(--sev-low)] bg-[var(--review-soft)] text-[var(--review-text)]' },
    { state: 'dismissed', label: tr('artifact.falsePositiveAction'), icon: X,
      selected: 'border-[var(--accent)] bg-[var(--panel-raised)] text-[var(--fg)]' },
  ]

  return (
    <Modal open onClose={() => { if (!saving) onClose() }} contained bodyClassName="overflow-hidden"
      title={<span className="flex min-w-0 items-center gap-2">
        <SeverityBadge severity={worst} />
        <Icon size={15} className="shrink-0 text-[var(--muted)]" />
        <span className="mono truncate">{kind === 'file' && root ? rel : artifact.artifact}</span>
        <TriageBadge state={state} label={tr(`triage.${state}`)} />
      </span>}>
      <div className="flex h-full min-h-0 flex-col">
        {collected.length > 0 && (
          <div className="m-4 mb-0 shrink-0 rounded-lg border border-[var(--ok)]/40 bg-[rgba(12,163,12,0.08)] px-3 py-2 animate-fade-up">
            <div className="mb-1 text-[12px] font-semibold text-[var(--ok)]">{tr('artifact.collected')}</div>
            <div className="flex flex-wrap gap-1.5">
              {collected.map((entry, index) => (
                <Tag key={index} tone="accent">
                  {entry.type}: {entry.value.length > 40 ? `…${entry.value.slice(-38)}` : entry.value}
                  {entry.hits != null && ` (${entry.hits}×)`}
                </Tag>
              ))}
            </div>
          </div>
        )}

        {expanded && kind === 'file' ? (
          <div className="flex min-h-0 flex-1 flex-col gap-3 p-4">
            <div className="shrink-0">
              <Button onClick={() => setExpanded(false)}>
                <ArrowLeft size={14} /> {tr('artifact.backToEvidence')}
              </Button>
            </div>
            <FileContentPane slug={slug} path={artifact.artifact} focusLine={focusLine}
              className="min-h-0 flex-1" />
          </div>
        ) : kind === 'file' ? (
          <div className="grid min-h-0 flex-1 gap-4 overflow-y-auto p-4 lg:grid-cols-[minmax(19rem,0.86fr)_minmax(0,1.35fr)] lg:overflow-hidden">
            <div className="flex flex-col gap-4 lg:min-h-0 lg:overflow-y-auto lg:pr-1">
              {identity}
              {fileFacts}
              <Clients ips={ips} marks={marks} onTrace={onTrace} />
            </div>
            <div className="flex min-h-[28rem] flex-col gap-4 lg:min-h-0">
              <Reasons findings={findings} artifact={artifact.artifact} onView={onView} bounded />
              <ContextPreview preview={file?.preview} onExpand={() => setExpanded(true)} />
            </div>
          </div>
        ) : (
          <div className="min-h-0 flex-1 overflow-y-auto p-4">
            <div className="mx-auto flex max-w-4xl flex-col gap-4">
              <Reasons findings={findings} artifact={artifact.artifact} onView={onView} />
              {identity}
              {nonFileContext}
              <Clients ips={ips} marks={marks} onTrace={onTrace} />
            </div>
          </div>
        )}

        <div className="shrink-0 border-t border-[var(--line-strong)] bg-[var(--panel)] px-4 py-3 shadow-[0_-12px_30px_rgba(0,0,0,0.24)]">
          <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                {tr('artifact.decision.title')}
              </div>
              <div className="mt-0.5 text-[12.5px]">
                {tr('artifact.question', { what: tr(KIND_THIS[kind] ?? 'artifact.this.generic') })}{' '}
                <span className="font-semibold">{tr('artifact.question.tail')}</span>{' '}
                <span className="text-[var(--muted)]">
                  {tr('artifact.question.scope', {
                    n: formatCount(findings.length),
                    findings: plural(tr, findings.length, 'artifact.finding.one', 'artifact.finding.many'),
                  })}
                </span>
              </div>
            </div>
            {ctx?.triaged_at && (
              <span className="text-[11px] text-[var(--muted)]">
                {tr('artifact.lastDecided')}: {absoluteTime(ctx.triaged_at)}
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div role="radiogroup" aria-label={tr('artifact.decision.title')}
              className="flex flex-1 flex-wrap gap-2">
              {decisions.map(({ state: option, label, icon: DecisionIcon, selected }) => (
                <label key={option} className={clsx(
                  'flex min-w-[9rem] flex-1 cursor-pointer items-center gap-2 rounded-xl border px-3 py-2 text-[12.5px] font-semibold transition-colors',
                  draftDecision === option
                    ? selected
                    : 'border-[var(--line-strong)] bg-[var(--panel-2)] text-[var(--muted)] hover:text-[var(--fg)]',
                  controlsDisabled && 'cursor-not-allowed opacity-50')}>
                  <input type="radio" name={`artifact-decision-${artifact.artifact}`}
                    value={option} checked={draftDecision === option}
                    disabled={controlsDisabled}
                    onChange={() => setDraftDecision(option)}
                    className="h-4 w-4 shrink-0 accent-[var(--accent)]" />
                  <DecisionIcon size={14} /> {label}
                </label>
              ))}
            </div>
            <div className="ml-auto flex shrink-0 flex-wrap gap-2">
              <Button variant="primary" disabled={controlsDisabled || !draftDecision}
                onClick={() => save(onSavedNext ? 'next' : 'stay')}>
                {saving && <LoaderCircle size={14} className="animate-spin" />}
                {tr(onSavedNext ? 'artifact.saveNext' : 'artifact.saveDecision')}
              </Button>
              <Button disabled={controlsDisabled || !draftDecision} onClick={() => save('close')}>
                {tr('artifact.saveClose')}
              </Button>
            </div>
          </div>

          <label className="mt-2 block text-[10.5px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('artifact.reasoning.optional')}
            <textarea value={note} onChange={(event) => setNote(event.target.value)} rows={2}
              disabled={controlsDisabled} aria-busy={!contextReady}
              placeholder={tr('artifact.note.placeholder')}
              className="mt-1 w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] font-normal normal-case tracking-normal text-[var(--fg)] outline-none focus:border-[var(--accent)]/70 disabled:cursor-wait disabled:opacity-60" />
          </label>
          <div role={contextError || saveError ? 'alert' : undefined}
            className={clsx('mt-1 text-[11px]',
            contextError || saveError ? 'text-[var(--danger-text)]' : 'text-[var(--muted)]')}>
            {saveError ? `${tr('artifact.saveError')}: ${saveError}`
              : contextError ? tr('artifact.contextError')
                : contextReady ? tr('artifact.triage.explain') : tr('artifact.contextLoading')}
          </div>
        </div>
      </div>
    </Modal>
  )
}
