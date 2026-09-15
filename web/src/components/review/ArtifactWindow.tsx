import { directSupported, useDirectSettings } from '../../directEnrichment'
// ArtifactWindow.tsx -- one bounded evidence workspace and an explicit save.
//
// Hostile files are only ever rendered as inert JSON text. Intelligence
// panels read stored results; "show in file manager" selects the file
// and never executes it. The same review window is shared by every view.
import { plural, useT } from '../../i18n'
import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowLeft, Bug, Check, ChevronRight, Clock3, Crosshair, Expand, FolderOpen,
  LoaderCircle, ShieldCheck, ShieldOff, ExternalLink, GripVertical, Database,
} from 'lucide-react'
import { KIND_ICON } from '../../artifactKinds'
import {
  api, post, type ArtifactContext, type FilePreview, type Finding, type TriageResult, type TriageState,
} from '../../api'
import {
  absoluteTime, formatBytes, formatCount,
  formatLogTime, relativeTime, relativeToRoot, type EvidenceRoot,
} from '../../format'
import { Button, CopyButton, Modal, SeverityBadge, Tabs, Tag, TriageBadge } from '../ui/ui'
import { InfoDot, Tooltip } from '../ui/Tooltip'
import { IpFlag } from '../ui/IpFlag'
import { TraceWindow, type TraceMarks } from '../logview/TraceWindow'
import { explainRule } from '../../explain'
import { useOpenCtiSettings } from '../../opencti'
import { useGeo } from '../../geo'
import { GroupedActions } from '../enrichment/OpenCti'
import { ArtifactEnrichment } from '../enrichment/ArtifactEnrichment'
import { SuccessfulAccesses, TableRecord } from './ReviewEvidence'
import { LogEntryContext } from '../logview/LogEntryContext'
import { LogFindingReview } from '../logview/LogFindingReview'
import { IocTypeBadge } from '../iocs/IocTypeBadge'
import { FileContentPane } from './FileViewer'
import { SyntaxText } from '../ui/SyntaxCode'
import { useSyntaxLines } from '../../useSyntaxLines'

const KIND_THIS: Record<string, string> = {
  file: 'artifact.this.file', table: 'artifact.this.table',
  client: 'artifact.this.client', dump: 'artifact.this.dump', log_observation: 'artifact.this.log_observation',
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
  artifact_kind: 'file' | 'table' | 'client' | 'dump' | 'log_observation'
  worst: number
  triage: TriageState
  triage_note: string
  items?: Finding[]
}

function MetaCell({ label, children, explain }: {
  label: string; children: React.ReactNode; explain?: string
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 border-b border-[var(--line-soft)] py-2">
      <div className="flex items-center gap-1 text-[11px] font-medium text-[var(--muted)]">
        {label}{explain && <InfoDot body={explain} />}
      </div>
      <div className="min-w-0 max-w-full text-[12px]">{children}</div>
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

function FindingList({ findings, selected, onSelect, preview, loading, kind = 'file' }: {
  findings: Finding[]; selected: string | null; onSelect: (finding: Finding) => void
  preview?: FilePreview; loading: boolean; kind?: string
}) {
  const tr = useT()
  const [opened, setOpened] = useState<string | null>(null)
  return <div data-artifact-scroll tabIndex={0} className="min-h-0 shrink-0 overflow-y-auto rounded-lg border border-[var(--line)]"
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
              : finding.line ? `${tr(kind === 'table' ? 'database.row.label' : 'artifact.line')} ${finding.line}` : tr(kind === 'file' || kind === 'dump' ? 'artifact.wholeFile' : 'review.aggregate')}
          </span>
        </button>
        {open && <div className="border-t border-[var(--line-soft)] px-3 py-2 text-[12px] leading-relaxed">
          <p>{explanation?.what ?? tr('artifact.ruleMatched')}</p>
          {finding.retired === 1 ? <pre className="mono mt-2 max-h-24 overflow-auto whitespace-pre-wrap break-all text-[11px]">{finding.evidence}</pre>
            : kind !== 'file' && kind !== 'dump' ? <pre className="mono mt-2 max-h-24 overflow-auto whitespace-pre-wrap break-all text-[11px]">{finding.evidence}</pre>
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

function Clients({ ips, marks, onTrace, slug }: {
  ips: ArtifactContext['related_ips']
  slug: string
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
              <a className="mono font-medium text-[var(--accent-text)] hover:underline" href={`?case=${encodeURIComponent(slug)}&view=actors&actor=${encodeURIComponent(entry.ip)}`} target="_blank" rel="noreferrer">{entry.ip}</a>
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
              {entry.ok_hits != null && <Tag tone={entry.ok_hits > 0 ? 'ok' : undefined}>{tr('review.successes', { n: entry.ok_hits })}</Tag>}
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

function ContextPreview({ preview, onExpand, loading = false, sql = false, path = '' }: {
  preview: NonNullable<ArtifactContext['file']>['preview'] | undefined
  onExpand?: () => void
  loading?: boolean
  sql?: boolean
  path?: string
}) {
  const tr = useT()
  const syntax = useSyntaxLines(sql ? 'preview.sql' : path, preview?.lines, !preview?.binary)
  const hitRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const row = hitRef.current
    if (row?.parentElement) row.parentElement.scrollTop = Math.max(0, row.offsetTop - row.parentElement.offsetTop - 48)
  }, [preview])
  return (
    <Block className="flex min-h-[12rem] flex-1 flex-col"
      title={<>{tr(sql ? 'review.sqlEvidence' : 'artifact.fileContent')}{' '}
        {preview?.focus
          ? tr('artifact.aroundLine', { n: preview.focus })
          : tr('artifact.fromStart')}
        {preview?.truncated && ` — ${tr('artifact.readTruncated')}`}</>}
      right={onExpand && <Button variant="special" onClick={onExpand}>
        <Expand size={13} /> {tr(sql ? 'review.expandSql' : 'artifact.expandFile')} <KeyHint>F</KeyHint>
      </Button>}>
      {loading ? <div role="status" className="flex flex-1 items-center justify-center"><LoaderCircle size={18} className="animate-spin" /></div>
      : preview && !preview.error && !preview.binary && preview.lines ? (
        <div data-artifact-scroll="primary" tabIndex={0} role="region" aria-label={tr(sql ? 'review.sqlEvidence' : 'artifact.fileContent')}
          className="mono min-h-0 flex-1 overflow-auto rounded-lg bg-[var(--code-bg)] py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
          {preview.lines.map((line, index) => {
            const number = (preview.from_line ?? 1) + index
            const hit = number === preview.focus
            return (
              <div key={number} ref={hit ? hitRef : undefined} data-focus-line={hit ? number : undefined} className={clsx('flex px-3', hit && 'bg-[rgba(208,59,59,0.18)]')}>
                <span className={clsx('w-10 shrink-0 select-none pr-3 text-right',
                  hit ? 'text-[#ff8b8b]' : 'text-[#4b5566]')}>{number}</span>
                <SyntaxText text={line} tokens={syntax.tokens?.[index]} />
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
  const [contextLoadedFor, setContextLoadedFor] = useState<string | null>(null)
  const [draftDecision, setDraftDecision] = useState<Decision | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState('')
  const [expanded, setExpanded] = useState(false)
  const [revealError, setRevealError] = useState('')
  const [evidenceTab, setEvidenceTab] = useState(artifact?.artifact_kind === 'client' ? 'trace' : 'findings')
  const [leftWidth, setLeftWidth] = useState(28)
  const splitRef = useRef<HTMLDivElement>(null)
  const [selectedTable, setSelectedTable] = useState<number | null>(null)
  const conf = useOpenCtiSettings(!!artifact)
  const direct = useDirectSettings(!!artifact)
  const geo = useGeo(artifact?.artifact_kind === 'client' ? artifact.artifact : null)
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
  const needsPreview = !!artifact && !!ctx?.file?.exists && ctx.file.available !== false && selectedFinding?.artifact === artifact.artifact && !!previewLine && !inPreview
  const { data: linePreview, isFetching: previewLoading, error: previewError } = useQuery({
    queryKey: ['artifact-line-preview', slug, artifact?.artifact, previewLine],
    queryFn: () => api<FilePreview>(`/api/cases/${slug}/file-preview?path=${encodeURIComponent(artifact!.artifact)}&line=${previewLine}`),
    enabled: needsPreview,
  })

  const sqlFocus = selectedFinding ? (selectedFinding.retired !== 1 ? selectedLine : null) : ctx?.findings.find(item => item.retired !== 1 && item.line)?.line ?? null
  const sqlQuery = useQuery({ queryKey: ['review-sql', slug, artifact?.artifact, sqlFocus, expanded],
    queryFn: () => api<FilePreview>(`/api/cases/${slug}/database/sql-preview?path=${encodeURIComponent(artifact!.artifact)}${sqlFocus ? `&line=${sqlFocus}` : ''}&expanded=${expanded}`),
    enabled: artifact?.artifact_kind === 'dump' && !!ctx?.dump })

  const reveal = useMutation({
    mutationFn: (path: string) => post(`/api/cases/${slug}/reveal-file`, { path }),
    onMutate: () => setRevealError(''),
    onError: (error) => setRevealError(String((error as Error)?.message ?? error)),
  })

  // Seed classifications once per matching artifact so refetches preserve draft choices.
  const contextFor = useRef<string | null>(null)
  const artifactKey = artifact ? JSON.stringify([slug, artifact.artifact]) : null
  const artifactPath = artifact?.artifact
  // Reset only when the identity changes, not when the query or caller's
  // stub refreshes. Those updates must preserve every unsaved control.
  useEffect(() => {
    contextFor.current = null
    setContextLoadedFor(null)
    setDraftDecision(null)
    setSaveError('')
    setExpanded(false)
    setRevealError('')
    setEvidenceTab(artifact?.artifact_kind === 'client' ? 'trace' : 'findings')
    setSelectedFinding(null)
    setClassifications(['webshell'])
    setSelectedTable(null)
  }, [artifactKey, artifact?.artifact_kind])
  useEffect(() => {
    if (!artifactKey || contextFor.current === artifactKey) return
    if (ctx && ctx.artifact === artifactPath) {
      contextFor.current = artifactKey
      setClassifications(ctx.file?.classifications ?? ['webshell'])
      setContextLoadedFor(artifactKey)
    }
  }, [artifactKey, artifactPath, ctx])

  shortcutRef.current = () => {}
  if (!artifact) return null
  const kind = artifact.artifact_kind
  const canEnrich = (kind === 'file' || kind === 'client') && (conf.data?.configured === true || (conf.data?.configured === false && directSupported(direct.data, kind === 'client' ? 'ip' : 'file')))
  const tab = evidenceTab === 'enrichment' && !canEnrich ? (kind === 'client' ? 'trace' : 'findings') : evidenceTab
  const activeFinding = selectedFinding ?? ctx?.findings.find(item => item.retired !== 1) ?? ctx?.findings[0]
  const boxUrl = new URL(location.href)
  boxUrl.searchParams.set('case', slug); boxUrl.searchParams.set('view', 'iocbox')
  if (ctx?.ioc_ids?.[0]) boxUrl.searchParams.set('ioc', String(ctx.ioc_ids[0])); else boxUrl.searchParams.delete('ioc')
  boxUrl.searchParams.delete('iocTab')
  boxUrl.searchParams.delete('artifact')
  const file = ctx?.file
  const fileAvailable = !!file?.exists && file.available !== false
  const fileHashes = file?.hashes ?? (file?.sha256 ? { sha256: file.sha256 } : {})
  const actor = ctx?.actor
  const findings = ctx?.findings ?? artifact.items ?? []
  const logReview = kind === 'log_observation' || (kind === 'file' && !!ctx?.log_observations?.length && findings.length > 0 && findings.every(finding => finding.source === 'log_observation'))
  const state: TriageState = ctx?.triage ?? artifact.triage
  const worst = ctx?.worst ?? artifact.worst
  const ips = ctx?.related_ips ?? []
  const { root, rel } = relativeToRoot(artifact.artifact, roots)
  const rootName = root && (root.label?.trim() ||
    root.path.replace(/\\/g, '/').replace(/\/+$/, '').split('/').pop())
  const displayedIdentity = kind === 'log_observation' ? (ctx?.log_observations?.[0] ? `${ctx.log_observations[0].source_name}:${ctx.log_observations[0].line}` : tr('logEvidence.entry')) : ['file', 'dump'].includes(kind) && root
    ? `${rootName} · ${rel}`
    : kind === 'dump' ? artifact.artifact.replace(/\\/g, '/').split('/').pop() || artifact.artifact : artifact.artifact
  const contextReady = ctx?.artifact === artifact.artifact && contextLoadedFor === artifactKey
  const progress = !contextError && ctx?.artifact === artifact.artifact
    ? ctx.review_progress : undefined
  const progressText = progress && tr('artifact.reviewProgress.counts', {
    done: formatCount(progress.reviewed), total: formatCount(progress.total),
    remaining: formatCount(progress.remaining),
  })
  const controlsDisabled = !contextReady || saving
  const Icon = KIND_ICON[kind] ?? Bug
  const focusLine = selectedFinding ? selectedLine : findings.find((finding) => finding.retired !== 1 && finding.line)?.line ?? null
  const preview = needsPreview ? (previewError ? { error: String(previewError) } : linePreview)
    : selectedFinding && initialPreview ? { ...initialPreview, focus: selectedLine } : initialPreview

  const marks: TraceMarks = kind === 'file'
    ? { contains: [root ? rel : artifact.artifact.replace(/\\/g, '/')],
        reason: tr('marks.fileFetched') }
    : kind === 'client' ? { findingIds: findings.map(finding => finding.id),
        reason: tr('review.traceFindingMatches') } : {}

  const save = async (intent: 'stay' | 'next' | 'close') => {
    if (!draftDecision || controlsDisabled || saveInProgress.current) return
    saveInProgress.current = true
    setSaving(true)
    setSaveError('')
    try {
      // Removing the editor must not clear historical notes when a decision is saved.
      const note = ctx?.triage_note ?? ''
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
        if (target?.closest('button,a,[role=tab],[role=separator]') && !target?.closest('[data-review-classifications]')) return
        event.preventDefault(); event.stopImmediatePropagation()
        void save(onSavedNext ? 'next' : 'stay')
      } else if (arrow) {
        if (target?.closest('[role=tablist], [role=separator]')) return
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
      } else if (key === 'f' && ((kind === 'file' && fileAvailable) || (kind === 'dump' && !!ctx?.dump))) {
        event.preventDefault(); event.stopImmediatePropagation()
        setExpanded(value => !value)
      }
    }
  }

  const identity = <Block title={tr(`review.context.${kind}`)}>
    <div className="flex items-start gap-2 py-2 text-[12px]">
      {kind === 'file' || kind === 'client' ? <IocTypeBadge type={kind === 'client' ? 'ip' : 'file'} value={artifact.artifact} /> : <Tag>{tr(`kind.${kind}`)}</Tag>}
      {kind === 'client' ? <><IpFlag ip={artifact.artifact} /><span>{geo?.name || artifact.artifact}</span></> : <span className="mono min-w-0 flex-1 break-all" title={artifact.artifact}>{displayedIdentity}</span>}
      <CopyButton value={kind === 'log_observation' ? displayedIdentity : artifact.artifact} label={tr(kind === 'log_observation' ? 'logEvidence.copyReference' : 'copy.path')} className="shrink-0" />
    </div>
    {kind !== 'log_observation' && <div className="mt-2 flex flex-wrap gap-2 [&>div>div]:left-0 [&>div>div]:right-auto">
      {kind === 'client' ? <a href={boxUrl.toString()} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-lg border border-[var(--line)] px-3 py-2 text-[12px] hover:bg-[var(--panel-2)]"><ExternalLink size={13} />{tr('cti.toBox')}</a>
        : <GroupedActions label={tr('review.open')} icon={<ExternalLink size={13} />}>
          <Button variant="ghost" disabled={reveal.isPending || (kind === 'table' && (ctx?.table_sources?.length ?? 0) !== 1) || (kind === 'file' && !fileAvailable)} onClick={() => reveal.mutate(kind === 'table' ? ctx!.table_sources![0].dump_path : artifact.artifact)}><FolderOpen size={13} />{tr('artifact.showInFileManager')}</Button>
          <a href={boxUrl.toString()} target="_blank" rel="noreferrer" className="flex items-center gap-2 rounded px-3 py-2 text-[12px] hover:bg-[var(--panel-2)]"><ExternalLink size={13} />{tr('cti.toBox')}</a>
        </GroupedActions>}
    </div>}
    {revealError && <p role="alert" className="mt-2 text-[12px] text-[var(--danger-text)]">{tr('artifact.revealError')}: {revealError}</p>}
  </Block>

  const fileFacts = file && (
    <div className="flex flex-col">
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
      {fileHashes.sha256 && <div className="border-t border-[var(--line)] pt-3"><div className="mb-2 flex items-center gap-2 text-[12px]">SHA-256<InfoDot body={tr('field.sha256')} /><CopyButton value={fileHashes.sha256} label={tr('copy.hash')} /></div><p className="mono break-all text-[11px]">{fileHashes.sha256}</p></div>}
      {(fileHashes.md5 || fileHashes.sha1) && <details className="mt-2 text-[12px]"><summary className="cursor-pointer text-[var(--muted)]">{tr('review.otherHashes')}</summary><div className="mt-2 space-y-2">{[['MD5', fileHashes.md5], ['SHA-1', fileHashes.sha1]].filter(([, value]) => value).map(([label, value]) => <div key={label}><div className="flex items-center gap-2">{label}<CopyButton value={value!} label={tr('copy.hash')} /></div><p className="mono break-all text-[11px]">{value}</p></div>)}</div></details>}

    </div>
  )

  const nonFileContext = <>
    {kind === 'client' && actor && (
      <div className="flex flex-col gap-2">
        <div className="flex flex-col">
          <MetaCell label={tr('table.requests')}>{formatCount(actor.actor.requests)}</MetaCell>
          {actor.ok_requests != null && <MetaCell label={tr('review.successCount')}>{formatCount(actor.ok_requests)} × 2xx</MetaCell>}
          <MetaCell label={tr('field.period')}>
            {formatLogTime(actor.actor.first_epoch, actor.actor.tz, { withZone: true })} → {formatLogTime(actor.actor.last_epoch, actor.actor.tz, { withZone: true })}
          </MetaCell>
          <MetaCell label={tr('artifact.errors')}>{formatCount(actor.actor.err4 + actor.actor.err5)}</MetaCell>
          <MetaCell label={tr('artifact.loginPosts')}>
            {formatCount(actor.actor.login_posts)}
            {actor.actor.login_redirects > 0 &&
              <span className="text-[var(--sev-high)]"> · {actor.actor.login_redirects} Redirects!</span>}
          </MetaCell>
        </div>

      </div>
    )}
    {ctx?.table && (ctx.table_sources?.length ?? 0) <= 1 && (
      <div className="flex flex-col">
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
      <div className="flex flex-col">
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
    { state: 'confirmed', label: tr(kind === 'log_observation' ? 'logEvidence.confirm' : 'artifact.truePositiveCollect'), icon: Check,
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

  return (<>
    <Modal open onClose={() => { if (!saving) onClose() }} contained bodyClassName="overflow-hidden"
      headerMeta={progress && progress.total > 0 && (
        <div className="text-[11px] font-normal text-[var(--muted)] tabular"
          title={tr('artifact.reviewProgress.explain', { skipped: formatCount(progress.skipped) })}>
          <span className="mr-2">{tr('artifact.reviewProgress.label')}</span>
          <span className="text-[var(--fg)]">{progressText}</span>
        </div>
      )}
      headerDivider={progress && progress.total > 0 && (
        <div role="progressbar" aria-label={tr('artifact.reviewProgress.label')}
          aria-valuemin={0} aria-valuemax={progress.total} aria-valuenow={progress.reviewed}
          aria-valuetext={progressText || undefined}
          className="h-0.5 shrink-0 overflow-hidden bg-[var(--line)]">
          <div className="h-full transition-[width] duration-300 motion-reduce:transition-none"
            style={{ width: `${100 * progress.reviewed / progress.total}%`,
              backgroundColor: progress.remaining === 0 ? 'var(--ok)' : 'var(--accent)' }} />
        </div>
      )}
      title={<span className="flex min-w-0 items-center gap-2">
        <SeverityBadge severity={worst} />
        <Icon size={15} className="shrink-0 text-[var(--muted)]" />
        <span className="mono truncate" title={artifact.artifact}>{kind === 'file' && root ? rel : ['dump', 'log_observation'].includes(kind) ? displayedIdentity : artifact.artifact}</span>
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

        {expanded && (kind === 'file' || kind === 'dump') ? (
          <div className="flex min-h-0 flex-1 flex-col gap-3 p-4">
            <div className="shrink-0"><Button onClick={() => setExpanded(false)}><ArrowLeft size={14} />{tr('artifact.backToEvidence')} <KeyHint>F</KeyHint></Button></div>
            {kind === 'file' ? <FileContentPane slug={slug} path={artifact.artifact} focusLine={focusLine} className="min-h-0 flex-1" />
              : <ContextPreview sql preview={sqlQuery.data} loading={sqlQuery.isFetching} />}
          </div>
        ) : logReview ? <LogFindingReview key={artifactKey} slug={slug} events={ctx?.log_observations ?? []} configured={conf.data?.configured === true || (conf.data?.configured === false && directSupported(direct.data, 'file'))} onFile={onView} /> : <div ref={splitRef} data-artifact-scroll className="review-split min-h-0 flex-1 overflow-y-auto" style={{ '--review-left': `${leftWidth}%` } as React.CSSProperties}>
          <aside data-artifact-scroll tabIndex={0} className="min-w-0 space-y-4 p-3 lg:overflow-y-auto">
            {identity}{kind === 'file' ? fileFacts : nonFileContext}
            {kind === 'dump' && !!ctx?.tables?.length && <Block title={tr('review.tables')}><div className="space-y-1">{ctx.tables.map(table => <button key={table.id} className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-[12px] hover:bg-[var(--panel-2)]" onClick={() => { setSelectedTable(table.id); setEvidenceTab('tables') }}><Database size={13} /><span className="mono min-w-0 flex-1 truncate">{table.name}</span><ChevronRight size={13} /></button>)}</div></Block>}
          </aside>
          <div role="separator" aria-label={tr('review.resize')} aria-orientation="vertical" aria-valuemin={20} aria-valuemax={42} aria-valuenow={leftWidth} tabIndex={0}
            className="hidden cursor-col-resize items-center justify-center border-x border-[var(--line)] text-[var(--muted)] hover:bg-[var(--accent-soft)] lg:flex"
            onKeyDown={event => { if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') { event.preventDefault(); event.stopPropagation(); setLeftWidth(value => Math.min(42, Math.max(20, value + (event.key === 'ArrowLeft' ? -2 : 2)))) } }}
            onPointerDown={event => { event.currentTarget.setPointerCapture(event.pointerId); event.preventDefault() }}
            onPointerMove={event => { if (event.currentTarget.hasPointerCapture(event.pointerId) && splitRef.current) { const rect = splitRef.current.getBoundingClientRect(); setLeftWidth(Math.max(20, Math.min(42, 100 * (event.clientX - rect.left) / rect.width))) } }}
            onPointerUp={event => { if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId) }}><GripVertical size={12} /></div>
          <div className="flex min-h-[30rem] min-w-0 flex-col gap-3 p-3 lg:min-h-0">
            <div className="shrink-0 overflow-x-auto"><Tabs active={tab} onChange={setEvidenceTab} tabs={[
              ...(kind === 'client' ? [{ id: 'trace', label: tr('review.trace') }] : []),
              ...(kind !== 'client' ? [{ id: 'findings', label: `${tr('artifact.findingsTab')} · ${findings.length}` }] : []),
              ...(kind === 'file' ? [{ id: 'ips', label: `${tr('artifact.ipsTab')} · ${ips.length}` }] : []),
              ...(kind === 'client' ? [{ id: 'accesses', label: tr('review.accesses') }, { id: 'agents', label: tr('review.agents') }] : []),
              ...(kind === 'table' ? [{ id: 'ips', label: `${tr('review.related')} · ${ips.length}` }] : []),
              ...(kind === 'dump' ? [{ id: 'tables', label: `${tr('review.tables')} · ${ctx?.tables?.length ?? 0}` }] : []),
              ...(canEnrich ? [{ id: 'enrichment', label: tr('review.enrichment') }] : []),
            ]} /></div>
            <div role="tabpanel" aria-label={tr(tab === 'findings' ? 'artifact.findingsTab' : tab === 'ips' ? 'artifact.ipsTab' : `review.${tab}`)}
              data-artifact-scroll={kind === 'client' ? 'primary' : undefined} tabIndex={0}
              className={clsx('flex min-h-0 flex-col gap-3', kind === 'file' ? 'max-h-[42%] overflow-y-auto' : 'flex-1 overflow-y-auto')}>
              {tab === 'findings' && <FindingList key={artifactKey} kind={kind} findings={findings} selected={activeFinding?.fingerprint ?? null} onSelect={setSelectedFinding} preview={kind === 'dump' ? sqlQuery.data : preview} loading={kind === 'dump' ? sqlQuery.isFetching : needsPreview && previewLoading} />}
              {tab === 'findings' && ctx?.log_observations?.map(event => <details key={event.id} className="rounded-lg border border-[var(--line)] p-3"><summary className="cursor-pointer text-sm font-medium">{event.source_name}:{event.line} · {tr('logEvidence.entry')}</summary><div className="mt-3"><LogEntryContext slug={slug} event={event} onFile={onView} /></div></details>)}
              {tab === 'ips' && <Clients slug={slug} ips={ips} marks={marks} onTrace={onTrace} />}
              {tab === 'accesses' && <SuccessfulAccesses key={artifactKey} slug={slug} ip={artifact.artifact} onView={onView} />}
              {kind === 'client' && tab === 'trace' && <div className="max-h-36 shrink-0 overflow-y-auto"><FindingList key={`trace:${artifactKey}`} kind={kind} findings={findings} selected={activeFinding?.fingerprint ?? null} onSelect={setSelectedFinding} loading={false} /></div>}
              {tab === 'trace' && <TraceWindow key={artifactKey} slug={slug} ips={[artifact.artifact]} embedded marks={marks} onClose={() => setEvidenceTab('trace')} />}
              {tab === 'agents' && <div className="overflow-x-auto rounded-lg border border-[var(--line)]"><table className="w-full text-left text-[12px]"><thead className="bg-[var(--panel-2)]"><tr><th className="p-2">{tr('review.agents')}</th><th className="p-2">{tr('table.requests')}</th></tr></thead><tbody>{actor?.top_agents?.map((entry, index) => <tr key={index} className="border-t border-[var(--line)]"><td className="mono break-all p-2">{entry.agent || tr('artifact.emptyAgent')}</td><td className="p-2">{formatCount(entry.n)}</td></tr>)}</tbody></table>{!actor?.top_agents?.length && <p className="p-3 text-[12px] text-[var(--muted)]">{tr('review.noAgents')}</p>}<p className="p-2 text-[11px] text-[var(--muted)]">{tr('review.agentLimit')}</p></div>}
              {tab === 'enrichment' && <ArtifactEnrichment key={JSON.stringify([artifactKey, ctx?.ioc_ids])} slug={slug} ids={ctx?.ioc_ids ?? []} />}
              {kind === 'table' && tab === 'findings' && <TableRecord key={`${artifactKey}:${activeFinding?.id}`} slug={slug} sources={ctx?.table_sources ?? []} finding={activeFinding} tableName={artifact.artifact} />}
              {kind === 'dump' && tab === 'findings' && <><ContextPreview sql preview={sqlQuery.data} loading={sqlQuery.isFetching} onExpand={ctx?.dump ? () => setExpanded(true) : undefined} />{sqlQuery.error && <p role="alert">{sqlQuery.error.message}</p>}</>}
              {kind === 'dump' && tab === 'tables' && <>
                <label className="flex flex-col gap-1 text-[12px]">{tr('review.tables')}<select aria-label={tr('review.tables')} className="rounded border border-[var(--line)] bg-[var(--panel-2)] p-2" value={selectedTable ?? ''} onChange={event => setSelectedTable(Number(event.target.value) || null)}><option value="">{tr('review.chooseTable')}</option>{ctx?.tables?.map(table => <option key={table.id} value={table.id}>{table.name} · {table.rows} {tr('review.rows')}</option>)}</select></label>
                {ctx?.tables?.filter(table => table.id === selectedTable).map(table => <TableRecord key={table.id} slug={slug} tableName={table.name} sources={[{ dump_id: table.dump_id, dump_path: artifact.artifact, table_id: table.id, rows: table.rows }]} />)}
                {!ctx?.tables?.length && <p role="status" className="text-[12px]">{tr('review.noTables')}</p>}
              </>}
            </div>
            {kind === 'file' && <>{fileAvailable ? <Block className="flex min-h-[12rem] flex-1 flex-col" title={tr('artifact.fileContent')}
                right={<Button variant="special" onClick={() => setExpanded(true)}><Expand size={13} />{tr('artifact.expandFile')} <KeyHint>F</KeyHint></Button>}>
                <FileContentPane slug={slug} path={artifact.artifact} focusLine={focusLine} showPath={false} compact className="flex-1" />
              </Block> : <ContextPreview path={artifact.artifact} preview={preview} loading={needsPreview && previewLoading} />}{!fileAvailable && file && <p role="status" className="text-[12px] text-[var(--muted)]">{file.unavailable_reason || tr('artifact.sourceUnavailable')}</p>}</>}
          </div>
        </div>}

        <div className="max-h-[48%] shrink-0 overflow-y-auto border-t border-[var(--line-strong)] bg-[var(--panel)] px-4 py-3 shadow-[0_-12px_30px_rgba(0,0,0,0.24)]">
          {kind === 'file' && <fieldset data-review-classifications className="mb-3" disabled={controlsDisabled}>
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
          </fieldset>}
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

          <div className="flex flex-col gap-2 xl:flex-row xl:items-center">
            <div role="radiogroup" aria-label={tr('artifact.decision.title')}
              className="grid flex-1 grid-cols-1 gap-2 sm:grid-cols-3">
              {decisions.map(({ state: option, label, icon: DecisionIcon, tone, text,
                                background, selectedBackground }, index) => (
                <label key={option} className={clsx(
                  'flex min-w-0 cursor-pointer items-center gap-2 rounded-xl border px-3 py-2 text-[12.5px] font-semibold transition-[border-color,background-color,color,box-shadow,filter]',
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


          <div role={contextError || saveError ? 'alert' : undefined}
            className={clsx('mt-1 text-[11px]',
            contextError || saveError ? 'text-[var(--danger-text)]' : 'text-[var(--muted)]')}>
            {saveError ? `${tr('artifact.saveError')}: ${saveError}`
              : contextError ? tr('artifact.contextError')
                : contextReady ? tr(kind === 'log_observation' ? 'logEvidence.triageExplain' : 'artifact.triage.explain') : tr('artifact.contextLoading')}
          </div>
        </div>
      </div>
    </Modal>

  </>)
}
