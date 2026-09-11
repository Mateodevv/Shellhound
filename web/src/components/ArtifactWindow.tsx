// ArtifactWindow.tsx -- one bounded evidence workspace and an explicit save.
//
// Hostile files are only ever rendered as inert JSON text. Intelligence
// panels read stored results; "show in file manager" selects the file
// and never executes it. The same review window is shared by every view.
import { plural, useT } from '../i18n'
import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowLeft, Bug, Check, ChevronRight, Clock3, Crosshair, Expand, FileSearch, FolderOpen,
  LoaderCircle, ShieldCheck, ShieldOff,
} from 'lucide-react'
import { KIND_ICON } from '../artifactKinds'
import {
  api, post, type ArtifactContext, type FilePreview, type Finding, type TriageResult, type TriageState,
} from '../api'
import {
  SEVERITY_VAR, absoluteTime, formatBytes, formatCount,
  formatDay, relativeTime, relativeToRoot, type EvidenceRoot,
} from '../format'
import { Button, CopyButton, Modal, SeverityBadge, Tabs, Tag, TriageBadge } from './ui'
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
const FILE_CLASSES = ['webshell', 'dropper', 'backdoor', 'seo-spam', 'malware', 'phishing', 'injected-code', 'modified-file'] as const
const SCROLL_AREA = '[data-artifact-scroll], [data-file-content-scroll]'
function KeyHint({ children }: { children: React.ReactNode }) {
  return <kbd aria-hidden="true" className="ml-1 rounded border border-current/20 px-1 text-[10px] font-normal opacity-65">{children}</kbd>
}

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

function FindingList({ findings, selected, onSelect, preview, loading }: {
  findings: Finding[]; selected: string | null; onSelect: (finding: Finding) => void
  preview?: FilePreview; loading: boolean
}) {
  const tr = useT()
  const [opened, setOpened] = useState<string | null>(null)
  return <div data-artifact-scroll tabIndex={0} className="max-h-[35%] shrink-0 overflow-y-auto rounded-lg border border-[var(--line)]"
    aria-label={tr('artifact.whyFlagged', { n: formatCount(findings.length) })}>
    {findings.map(finding => {
      const explanation = explainRule(tr, finding.rule)
      const open = opened === finding.fingerprint
      return <div key={finding.fingerprint} className={clsx('border-b border-[var(--line-soft)] last:border-0', finding.retired === 1 && 'opacity-60')}>
        <button type="button" aria-expanded={open} onClick={() => {
          onSelect(finding)
          setOpened(open ? null : finding.fingerprint)
        }} className={clsx('ui-press flex w-full cursor-pointer items-center gap-2 px-3 py-2 text-left hover:bg-[var(--panel-2)]',
          selected === finding.fingerprint && 'bg-[var(--accent-soft)]')}>
          <ChevronRight size={13} className={clsx('shrink-0 transition-transform', open && 'rotate-90')} />
          <SeverityBadge severity={finding.severity} />
          <span className="min-w-0 flex-1 truncate text-[12px] font-semibold" title={finding.rule}>{finding.rule}</span>
          <span className="shrink-0 text-[11px] text-[var(--muted)]">
            {finding.retired === 1 ? tr('artifact.retired', { date: finding.last_seen })
              : finding.line ? `${tr('artifact.line')} ${finding.line}` : tr('artifact.wholeFile')}
          </span>
        </button>
        {open && <div className="border-t border-[var(--line-soft)] px-3 py-2 text-[12px] leading-relaxed">
          <p>{explanation?.what ?? tr('artifact.ruleMatched')}</p>
          {finding.retired === 1 ? <pre className="mono mt-2 max-h-24 overflow-auto whitespace-pre-wrap break-all text-[11px]">{finding.evidence}</pre>
            : loading ? <LoaderCircle size={14} className="mt-2 animate-spin" />
            : preview?.lines ? <div className="mono mt-2 max-h-28 overflow-auto rounded bg-[var(--code-bg)] py-1 text-[11px] text-[#e6edf3]">
              {preview.lines.map((line, index) => ({ line, number: (preview.from_line ?? 1) + index }))
                .filter(({ number }) => finding.line ? Math.abs(number - finding.line) <= 2 : number < (preview.from_line ?? 1) + 8)
                .map(({ line, number }) => <div key={number} className={clsx('flex gap-3 px-2', number === finding.line && 'bg-[rgba(208,59,59,0.18)]')}>
                  <span className="shrink-0 select-none text-[var(--muted)]">{number}</span><span className="whitespace-pre-wrap break-all">{line || ' '}</span>
                </div>)}
            </div> : <p className="mt-1 text-[var(--muted)]">{preview?.error ?? tr('artifact.previewUnavailable')}</p>}
        </div>}
      </div>
    })}
  </div>
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
      <Button variant="special"
        onClick={() => onTrace(ips.map((entry) => entry.ip), marks)}>
        {tr('artifact.traceAll')}
      </Button>
    )}>
      {ips.length ? (
        <div className="flex flex-col divide-y divide-[var(--line-soft)] rounded-lg border border-[var(--line)]">
          {ips.map((entry) => (
            <div key={entry.ip}
              className="flex flex-wrap items-center gap-2 px-3 py-2 text-[12px]">
              <IpFlag ip={entry.ip} />
              <span className="mono font-medium">{entry.ip}</span>
              {entry.in_box && <Tag tone="accent" explain={tr('artifact.ipInBox')}>IOC</Tag>}
              <InfoDot body={entry.why} />
              {entry.hits != null && (
                <span className="ml-auto text-[var(--muted)] tabular">
                  {tr('artifact.matchingRequests', { n: formatCount(entry.hits) })}
                </span>
              )}
              <Button variant="special" className="ml-auto shrink-0"
                onClick={() => onTrace([entry.ip], marks)}>
                <Crosshair size={12} /> Trace
              </Button>
              {(entry.first_epoch != null || entry.last_epoch != null) && <div className="w-full text-[11px] text-[var(--muted)]">
                {tr('artifact.firstRequest')}: {entry.first_epoch != null ? `${absoluteTime(new Date(entry.first_epoch * 1000).toISOString())} UTC` : '—'}
                {' · '}{tr('artifact.lastRequest')}: {entry.last_epoch != null ? `${absoluteTime(new Date(entry.last_epoch * 1000).toISOString())} UTC` : '—'}
              </div>}
            </div>
          ))}
        </div>
      ) : <div className="text-[12px] text-[var(--muted)]">{tr('artifact.noClients')}</div>}
    </Block>
  )
}

function ContextPreview({ preview, onExpand, loading = false }: {
  preview: NonNullable<ArtifactContext['file']>['preview'] | undefined
  onExpand: () => void
  loading?: boolean
}) {
  const tr = useT()
  const hitRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const row = hitRef.current
    if (row?.parentElement) row.parentElement.scrollTop = Math.max(0, row.offsetTop - row.parentElement.offsetTop - 48)
  }, [preview])
  return (
    <Block className="flex min-h-[12rem] flex-1 flex-col"
      title={<>{tr('artifact.fileContent')}{' '}
        {preview?.focus
          ? tr('artifact.aroundLine', { n: preview.focus })
          : tr('artifact.fromStart')}
        {preview?.truncated && ` — ${tr('artifact.readTruncated')}`}</>}
      right={<Button variant="default" onClick={onExpand}>
        <Expand size={13} /> {tr('artifact.expandFile')} <KeyHint>F</KeyHint>
      </Button>}>
      {loading ? <div role="status" className="flex flex-1 items-center justify-center"><LoaderCircle size={18} className="animate-spin" /></div>
      : preview && !preview.error && !preview.binary && preview.lines ? (
        <div data-artifact-scroll="primary" tabIndex={0} role="region" aria-label={tr('artifact.fileContent')}
          className="mono min-h-0 flex-1 overflow-auto rounded-lg bg-[var(--code-bg)] py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
          {preview.lines.map((line, index) => {
            const number = (preview.from_line ?? 1) + index
            const hit = number === preview.focus
            return (
              <div key={number} ref={hit ? hitRef : undefined} data-focus-line={hit ? number : undefined} className={clsx('flex px-3', hit && 'bg-[rgba(208,59,59,0.18)]')}>
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
  onSave: (state: Decision, note: string, classifications?: string[]) => Promise<TriageResult>
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
  const [evidenceTab, setEvidenceTab] = useState<'findings' | 'ips'>('findings')
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null)
  const [classifications, setClassifications] = useState<string[]>(['webshell'])
  const workspaceRef = useRef<HTMLDivElement>(null)
  const activeScrollRef = useRef<HTMLElement | null>(null)
  const shortcutRef = useRef<(event: KeyboardEvent) => void>(() => {})
  const saveInProgress = useRef(false)
  useEffect(() => {
    const handler = (event: KeyboardEvent) => shortcutRef.current(event)
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  const { data: ctx, isError: contextError } = useQuery({
    queryKey: ['artifact', slug, artifact?.artifact],
    queryFn: () => api<ArtifactContext>(
      `/api/cases/${slug}/artifact?artifact=${encodeURIComponent(artifact!.artifact)}`),
    enabled: !!artifact,
  })
  const selectedLine = selectedFinding?.artifact === artifact?.artifact && selectedFinding?.retired !== 1 ? selectedFinding?.line ?? null : null
  const initialPreview = ctx?.file?.preview
  const previewLine = selectedFinding?.retired !== 1 ? selectedLine ?? 1 : null
  const inPreview = previewLine != null && initialPreview?.lines != null &&
    previewLine >= (initialPreview.from_line ?? 1) &&
    previewLine < (initialPreview.from_line ?? 1) + initialPreview.lines.length
  const needsPreview = !!artifact && selectedFinding?.artifact === artifact.artifact && !!previewLine && !inPreview
  const { data: linePreview, isFetching: previewLoading, error: previewError } = useQuery({
    queryKey: ['artifact-line-preview', slug, artifact?.artifact, previewLine],
    queryFn: () => api<FilePreview>(`/api/cases/${slug}/file-preview?path=${encodeURIComponent(artifact!.artifact)}&line=${previewLine}`),
    enabled: needsPreview,
  })

  const reveal = useMutation({
    mutationFn: (path: string) => post(`/api/cases/${slug}/reveal-file`, { path }),
    onMutate: () => setRevealError(''),
    onError: (error) => setRevealError(String((error as Error)?.message ?? error)),
  })

  // The server note is authoritative. It seeds once per matching artifact;
  // refetches never overwrite reasoning that is currently being typed.
  const noteFor = useRef<string | null>(null)
  const artifactKey = artifact ? JSON.stringify([slug, artifact.artifact]) : null
  const artifactPath = artifact?.artifact
  // Reset only when the identity changes, not when the query or caller's
  // stub refreshes. Those updates must preserve every unsaved control.
  useEffect(() => {
    noteFor.current = null
    setNoteLoadedFor(null)
    setNote('')
    setDraftDecision(null)
    setSaveError('')
    setExpanded(false)
    setRevealError('')
    setEvidenceTab('findings')
    setSelectedFinding(null)
    setClassifications(['webshell'])
  }, [artifactKey])
  useEffect(() => {
    if (!artifactKey || noteFor.current === artifactKey) return
    if (ctx && ctx.artifact === artifactPath) {
      noteFor.current = artifactKey
      setNote(ctx.triage_note ?? '')
      setClassifications(ctx.file?.classifications ?? ['webshell'])
      setNoteLoadedFor(artifactKey)
    }
  }, [artifactKey, artifactPath, ctx])

  shortcutRef.current = () => {}
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
  const contextReady = ctx?.artifact === artifact.artifact && noteLoadedFor === artifactKey
  const controlsDisabled = !contextReady || saving
  const Icon = KIND_ICON[kind] ?? Bug
  const focusLine = selectedFinding ? selectedLine : findings.find((finding) => finding.retired !== 1 && finding.line)?.line ?? null
  const preview = needsPreview ? (previewError ? { error: String(previewError) } : linePreview)
    : selectedFinding && initialPreview ? { ...initialPreview, focus: selectedLine } : initialPreview

  const marks: TraceMarks = kind === 'file'
    ? { contains: [root ? rel : artifact.artifact.replace(/\\/g, '/')],
        reason: tr('marks.fileFetched') }
    : { exact: (actor?.alerts ?? []).map((alert) => alert.example).filter(Boolean),
        reason: tr('marks.alertTrigger') }

  const save = async (intent: 'stay' | 'next' | 'close') => {
    if (!draftDecision || controlsDisabled || saveInProgress.current) return
    saveInProgress.current = true
    setSaving(true)
    setSaveError('')
    try {
      const result = kind === 'file' ? await onSave(draftDecision, note, classifications) : await onSave(draftDecision, note)
      if (result.updated === 0) return
      setDraftDecision(null)
      if (intent === 'next' && onSavedNext) onSavedNext(result)
      else if (intent === 'close') onClose()
    } catch (error) {
      setSaveError(String((error as Error)?.message ?? error))
    } finally {
      saveInProgress.current = false
      setSaving(false)
    }
  }
  shortcutRef.current = event => {
    const arrow = event.key.startsWith('Arrow')
    if (event.defaultPrevented || (event.repeat && !arrow) || event.isComposing || event.altKey || saving) return
    const dialog = workspaceRef.current?.closest('[role="dialog"]')
    const dialogs = document.querySelectorAll('[role="dialog"]')
    if (!dialog || dialogs[dialogs.length - 1] !== dialog) return
    const target = event.target instanceof HTMLElement ? event.target : document.activeElement as HTMLElement | null
    const editing = target?.closest('textarea,select,[contenteditable="true"],input:not([type="radio"]):not([type="checkbox"])')
    const key = event.key.toLowerCase()
    if ((event.ctrlKey || event.metaKey) && event.shiftKey && key === 'enter') {
      event.preventDefault(); event.stopImmediatePropagation()
      void save('close')
    } else if (!editing && !event.ctrlKey && !event.metaKey && !event.shiftKey) {
      if (key === 'enter') {
        event.preventDefault(); event.stopImmediatePropagation()
        void save(onSavedNext ? 'next' : 'stay')
      } else if (arrow) {
        event.preventDefault(); event.stopImmediatePropagation()
        const workspace = workspaceRef.current!
        const horizontal = key === 'arrowleft' || key === 'arrowright'
        const preferred = activeScrollRef.current
        const focused = target?.closest<HTMLElement>(SCROLL_AREA)
        const candidates = [preferred, focused, workspace.querySelector<HTMLElement>('[data-artifact-scroll="primary"], [data-file-content-scroll]'),
          ...workspace.querySelectorAll<HTMLElement>(SCROLL_AREA)]
        const area = candidates.find(element => element && workspace.contains(element) &&
          (horizontal ? element.scrollWidth > element.clientWidth : element.scrollHeight > element.clientHeight))
        if (area) {
          const delta = key === 'arrowup' || key === 'arrowleft' ? -48 : 48
          if (horizontal) area.scrollLeft = Math.max(0, Math.min(area.scrollWidth - area.clientWidth, area.scrollLeft + delta))
          else area.scrollTop = Math.max(0, Math.min(area.scrollHeight - area.clientHeight, area.scrollTop + delta))
        }
      } else if (['1', '2', '3'].includes(key) && !controlsDisabled) {
        event.preventDefault(); event.stopImmediatePropagation()
        setDraftDecision(({ '1': 'confirmed', '2': 'reviewed', '3': 'dismissed' } as const)[key as '1' | '2' | '3'])
      } else if (key === 'f' && kind === 'file') {
        event.preventDefault(); event.stopImmediatePropagation()
        setExpanded(value => !value)
      }
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
      {file.changed_since_scan && <div className="col-span-2 rounded-lg border border-[var(--warn)]/40 p-3 text-[12px] text-[var(--warn)]">
        <p>{tr('cti.fileChanged')}</p>{file.scanned_sha256 && <p className="mono mt-1 break-all" title={tr('cti.scannedHash')}>{file.scanned_sha256}</p>}
      </div>}
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

  const decisions: Array<{
    state: Decision
    label: string
    icon: typeof Check
    tone: string
    text: string
    background: string
    selectedBackground: string
  }> = [
    { state: 'confirmed', label: tr('artifact.truePositiveCollect'), icon: Check,
      tone: 'var(--incident)', text: 'var(--danger-text)',
      background: 'var(--danger-soft)', selectedBackground: 'var(--danger-soft-hover)' },
    { state: 'reviewed', label: tr('artifact.reviewedAction'), icon: Clock3,
      tone: 'var(--sev-low)', text: 'var(--review-text)',
      background: 'var(--review-soft)',
      selectedBackground: 'color-mix(in srgb, var(--sev-low) 20%, var(--panel-2))' },
    { state: 'dismissed', label: tr('artifact.falsePositiveAction'), icon: ShieldCheck,
      tone: 'var(--ok)', text: 'color-mix(in srgb, var(--ok) 76%, var(--fg))',
      background: 'color-mix(in srgb, var(--ok) 9%, var(--panel-2))',
      selectedBackground: 'color-mix(in srgb, var(--ok) 18%, var(--panel-2))' },
  ]

  return (
    <Modal open onClose={() => { if (!saving) onClose() }} contained bodyClassName="overflow-hidden"
      title={<span className="flex min-w-0 items-center gap-2">
        <SeverityBadge severity={worst} />
        <Icon size={15} className="shrink-0 text-[var(--muted)]" />
        <span className="mono truncate">{kind === 'file' && root ? rel : artifact.artifact}</span>
        <TriageBadge state={state} label={tr(`triage.${state}`)} />
      </span>}>
      <div ref={workspaceRef} className="flex h-full min-h-0 flex-col"
        onPointerOver={event => {
          const area = (event.target as HTMLElement).closest<HTMLElement>(SCROLL_AREA)
          if (area) activeScrollRef.current = area
        }}
        onFocusCapture={event => {
          const area = event.target.closest<HTMLElement>(SCROLL_AREA)
          if (area) activeScrollRef.current = area
        }}>
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
                <ArrowLeft size={14} /> {tr('artifact.backToEvidence')} <KeyHint>F</KeyHint>
              </Button>
            </div>
            <FileContentPane slug={slug} path={artifact.artifact} focusLine={focusLine}
              className="min-h-0 flex-1" />
          </div>
        ) : kind === 'file' ? (
          <div data-artifact-scroll className="grid min-h-0 flex-1 gap-4 overflow-y-auto p-4 lg:grid-cols-[minmax(19rem,0.86fr)_minmax(0,1.35fr)] lg:overflow-hidden">
            <div data-artifact-scroll tabIndex={0} className="flex flex-col gap-4 lg:min-h-0 lg:overflow-y-auto lg:pr-1">
              {identity}
              {fileFacts}
            </div>
            <div className="flex min-h-[28rem] flex-col gap-4 lg:min-h-0">
              <div className="shrink-0"><Tabs active={evidenceTab} onChange={setEvidenceTab} tabs={[
                { id: 'findings' as const, label: `${tr('artifact.findingsTab')} · ${findings.length}` },
                { id: 'ips' as const, label: `${tr('artifact.ipsTab')} · ${ips.length}` },
              ]} /></div>
              {evidenceTab === 'findings' ? <div role="tabpanel" aria-label={tr('artifact.findingsTab')} className="flex min-h-0 flex-1 flex-col gap-3">
                <FindingList key={artifactKey} findings={findings} selected={selectedFinding?.fingerprint ?? null} onSelect={setSelectedFinding} preview={preview} loading={needsPreview && previewLoading} />
                <ContextPreview preview={preview} loading={needsPreview && previewLoading} onExpand={() => setExpanded(true)} />
              </div> : <div data-artifact-scroll="primary" tabIndex={0} role="tabpanel" aria-label={tr('artifact.ipsTab')} className="min-h-0 flex-1 overflow-y-auto">
                <Clients ips={ips} marks={marks} onTrace={onTrace} />
              </div>}
            </div>
          </div>
        ) : (
          <div data-artifact-scroll="primary" tabIndex={0} className="min-h-0 flex-1 overflow-y-auto p-4">
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
              {decisions.map(({ state: option, label, icon: DecisionIcon, tone, text,
                                background, selectedBackground }, index) => (
                <label key={option} className={clsx(
                  'flex min-w-[9rem] flex-1 cursor-pointer items-center gap-2 rounded-xl border px-3 py-2 text-[12.5px] font-semibold transition-[border-color,background-color,color,box-shadow,filter]',
                  !controlsDisabled && 'hover:brightness-110',
                  controlsDisabled && 'cursor-not-allowed opacity-50')}
                  style={{
                    borderColor: draftDecision === option
                      ? tone
                      : `color-mix(in srgb, ${tone} 58%, var(--line-strong))`,
                    background: draftDecision === option ? selectedBackground : background,
                    color: text,
                    boxShadow: draftDecision === option
                      ? `inset 0 0 0 1px ${tone}, 0 0 0 2px color-mix(in srgb, ${tone} 22%, transparent)`
                      : undefined,
                  }}>
                  <input type="radio" name={`artifact-decision-${artifact.artifact}`}
                    aria-keyshortcuts={String(index + 1)}
                    value={option} checked={draftDecision === option}
                    disabled={controlsDisabled}
                    onChange={() => setDraftDecision(option)}
                    style={{ accentColor: tone }}
                    className="h-4 w-4 shrink-0" />
                  <DecisionIcon size={14} /> {label} <KeyHint>{index + 1}</KeyHint>
                </label>
              ))}
            </div>
            <div className="ml-auto flex shrink-0 flex-wrap gap-2">
              <Button variant="primary" disabled={controlsDisabled || !draftDecision}
                aria-keyshortcuts="Enter"
                onClick={() => save(onSavedNext ? 'next' : 'stay')}>
                {saving && <LoaderCircle size={14} className="animate-spin" />}
                {tr(onSavedNext ? 'artifact.saveNext' : 'artifact.saveDecision')}
                <KeyHint>↵</KeyHint>
              </Button>
              <Button disabled={controlsDisabled || !draftDecision} aria-keyshortcuts="Control+Shift+Enter Meta+Shift+Enter" onClick={() => save('close')}>
                {tr('artifact.saveClose')} <KeyHint>Ctrl ⇧ ↵</KeyHint>
              </Button>
            </div>
          </div>

          {kind === 'file' ? <fieldset className="mt-3" disabled={controlsDisabled}>
            <legend className="mb-2 flex items-center gap-1 text-[10.5px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              {tr('artifact.classifications')} <InfoDot body={tr('artifact.classificationsHint')} />
            </legend>
            <div className="flex flex-wrap gap-1.5">
              {FILE_CLASSES.map(value => <button key={value} type="button" aria-pressed={classifications.includes(value)}
                onClick={() => {
                  setClassifications(previous => previous.includes(value) ? previous.filter(item => item !== value) : [...previous, value])
                  if (state !== 'new') setDraftDecision(previous => previous ?? state)
                }}
                className={clsx('ui-press flex cursor-pointer items-center gap-1 rounded px-2 py-1 text-[11px] font-medium transition-colors disabled:opacity-50',
                  classifications.includes(value) ? 'bg-[var(--accent-soft)] text-[var(--accent-text)] ring-1 ring-inset ring-[var(--accent)]/50' : 'bg-[var(--panel-2)] text-[var(--muted)] hover:text-[var(--fg)]')}>
                {classifications.includes(value) && <Check size={11} />}{tr(`artifact.class.${value}`)}
              </button>)}
            </div>
          </fieldset> : <label className="mt-2 block text-[10.5px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('artifact.reasoning.optional')}
            <textarea value={note} onChange={(event) => setNote(event.target.value)} rows={2}
              disabled={controlsDisabled} aria-busy={!contextReady}
              placeholder={tr('artifact.note.placeholder')}
              className="mt-1 w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] font-normal normal-case tracking-normal text-[var(--fg)] outline-none focus:border-[var(--accent)]/70 disabled:cursor-wait disabled:opacity-60" />
          </label>}
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
