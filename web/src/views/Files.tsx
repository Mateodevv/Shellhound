// Files.tsx -- manual inspection of registered evidence, one file at a time.
// Scanner observations remain available, while case decisions live in the
// shared Findings workflow instead of being duplicated here.
import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  ArrowLeft, ArrowRight, Bug, ChevronRight, Clock3,
  FileCode2, FileSearch, FileText, Fingerprint, FolderOpen, FolderTree,
} from 'lucide-react'
import {
  api, type BrowseFile, type BrowseResponse, type CaseDetail, type FileContent,
} from '../api'
import { absoluteTime, formatBytes, formatCount, type EvidenceRoot } from '../format'
import { useT } from '../i18n'
import { Button, Card, CopyButton, EmptyState, SearchInput, SeverityBadge, Tag, TriageBadge } from '../components/ui'
import { FileViewer } from '../components/FileViewer'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import type { ViewId } from '../App'

export function Files({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const [path, setPath] = useState('')
  const [filter, setFilter] = useState('')
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [viewing, setViewing] = useState<string | null>(null)
  const [artifact, setArtifact] = useState<ArtifactStub | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const triage = useTriage(slug)

  const browse = useQuery({
    queryKey: ['browse', slug, path],
    queryFn: () => api<BrowseResponse>(
      `/api/cases/${slug}/browse?path=${encodeURIComponent(path)}`),
    enabled: Boolean(path),
  })
  const caseQuery = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = useMemo(() =>
    (caseQuery.data?.evidence_items ?? []).map((item) => ({
      kind: item.kind, path: item.path, label: item.label,
    })), [caseQuery.data?.evidence_items])
  const fileRoots = useMemo(() => roots.filter((root) => root.kind === 'webroot'), [roots])

  // The first registered webroot is the useful default. A separate landing
  // screen added a click without adding information; multiple roots remain
  // directly switchable in the toolbar.
  useEffect(() => {
    setPath('')
  }, [slug])
  useEffect(() => {
    if (!path && fileRoots[0]?.path) setPath(fileRoots[0].path)
  }, [path, fileRoots])

  useEffect(() => {
    setFilter('')
    setSelectedPath(null)
  }, [path])

  const files = useMemo(() => (browse.data?.files ?? []).filter((file) =>
    !filter || file.name.toLowerCase().includes(filter.toLowerCase())),
  [browse.data, filter])
  const dirs = useMemo(() => (browse.data?.dirs ?? []).filter((dir) =>
    !filter || dir.name.toLowerCase().includes(filter.toLowerCase())),
  [browse.data, filter])
  const selected = browse.data?.files.find((file) => file.path === selectedPath) ?? null
  const selectedIndex = files.findIndex((file) => file.path === selectedPath)
  const atRoot = !path

  const chooseFile = (file: BrowseFile) => {
    setSelectedPath(file.path)
    triage.clearCollected()
  }
  const move = (delta: number) => {
    const next = files[selectedIndex + delta]
    if (next) chooseFile(next)
  }

  return <div className="flex flex-col gap-3">
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <div className="flex items-center gap-2">
          <FileSearch size={18} className="text-[var(--accent-text)]" />
          <h1 className="text-lg font-bold">{tr('files.review.title')}</h1>
        </div>
        <p className="mt-0.5 max-w-3xl text-[12.5px] text-[var(--muted)]">
          {tr('files.review.sub')}
        </p>
      </div>
      {!atRoot && <Metric value={(browse.data?.files ?? []).length} label={tr('files.metric.files')} />}
    </header>

    <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--panel)] p-2.5">
      {!atRoot && fileRoots.length > 1 && (
        <select
          aria-label={tr('files.roots')}
          value={fileRoots.find((root) => pathWithinRoot(path, root.path))?.path ?? fileRoots[0].path}
          onChange={(event) => setPath(event.target.value)}
          className="max-w-72 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2.5 py-1.5 text-[12px] outline-none focus:border-[var(--accent)]/70"
        >
          {fileRoots.map((root) => (
            <option key={root.path} value={root.path}>
              {root.label?.trim() || root.path}
            </option>
          ))}
        </select>
      )}
      {browse.data?.parent != null && <Button variant="ghost" onClick={() => setPath(browse.data!.parent!)}>
        <ArrowLeft size={14} /> {tr('evidence.parentDir')}
      </Button>}
      {!atRoot && <span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]"
        title={browse.data?.path}>{browse.data?.path}</span>}
      {!atRoot && <div className="ml-auto min-w-64">
        <SearchInput value={filter} onChange={setFilter} placeholder={tr('files.filter')} />
      </div>}
    </div>

    {browse.isError && <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)]">
      {String((browse.error as Error)?.message ?? browse.error)}
    </div>}

    {atRoot && caseQuery.isSuccess && !fileRoots.length && (
      <EmptyState icon={<FolderTree size={36} />} title={tr('files.empty.title')}
        sub={tr('files.empty.sub')} />
    )}

    {!atRoot && <div className="grid min-w-0 items-start gap-4 lg:grid-cols-[minmax(360px,0.78fr)_minmax(520px,1.22fr)]">
      <Card className="min-w-0 overflow-hidden">
        <div className="flex items-center justify-between border-b border-[var(--line)] bg-[var(--panel-2)] px-3 py-2">
          <span className="text-[10px] font-bold uppercase tracking-[0.12em] text-[var(--muted)]">
            {tr('files.queue.title')}
          </span>
          <span className="tabular text-[10px] text-[var(--muted)]">
            {tr('files.count', { dirs: formatCount(dirs.length), files: formatCount(files.length) })}
          </span>
        </div>
        <div className="max-h-[calc(100vh-245px)] overflow-y-auto">
          {dirs.map((dir) => <button key={dir.path} type="button" onClick={() => setPath(dir.path)}
            className="group flex w-full cursor-pointer items-center gap-2.5 border-b border-[var(--line-soft)] px-3 py-2.5 text-left hover:bg-[var(--panel-2)]">
            <FolderOpen size={15} className="shrink-0 text-[var(--muted)]" />
            <span className="min-w-0 flex-1 truncate text-[12.5px] font-medium">{dir.name}</span>
            <ChevronRight size={14} className="text-[var(--muted)] opacity-0 group-hover:opacity-100" />
          </button>)}
          {files.map((file) => <FileRow key={file.path} file={file}
            active={selectedPath === file.path} onClick={() => chooseFile(file)} tr={tr} />)}
          {!dirs.length && !files.length && <div className="px-4 py-8 text-center text-[13px] text-[var(--muted)]">
            {filter ? tr('files.noMatch') : tr('files.emptyDir')}
          </div>}
        </div>
        {browse.data?.truncated && <div className="border-t border-[var(--line)] px-4 py-2 text-[11px] text-[var(--sev-low)]">
          {tr('files.truncated')}
        </div>}
      </Card>

      <FileReviewPanel key={selected?.path ?? 'no-file'} slug={slug} file={selected}
        position={selectedIndex >= 0 ? selectedIndex + 1 : 0} total={files.length}
        canPrevious={selectedIndex > 0} canNext={selectedIndex >= 0 && selectedIndex < files.length - 1}
        onPrevious={() => move(-1)} onNext={() => move(1)}
        onView={() => selected && setViewing(selected.path)}
        onOpenArtifact={() => selected && selected.worst != null && setArtifact({
          artifact: selected.path, artifact_kind: 'file', worst: selected.worst,
          triage: selected.triage ?? 'new', triage_note: selected.review?.note ?? '',
        })} />
    </div>}

    <FileViewer slug={slug} path={viewing} layer={2} onClose={() => setViewing(null)} />
    <ArtifactWindow slug={slug} artifact={artifact} roots={roots}
      collected={triage.collected} onView={(file) => setViewing(file)}
      onTrace={(ips, marks) => { setTraceMarks(marks); setTraceIps(ips) }}
      onClose={() => { setArtifact(null); triage.clearCollected() }}
      onTriage={(state, note) => artifact && triage.decide([artifact.artifact], state, note)} />
    <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
      onClose={() => setTraceIps(null)} />
    <TriageFollowUp t={triage} roots={roots} />
  </div>
}

type Tr = ReturnType<typeof useT>

function Metric({ value, label, danger = false }: { value: number; label: string; danger?: boolean }) {
  return <div className="text-right">
    <div className={clsx('text-base font-bold tabular', danger ? 'text-[var(--danger-text)]' : 'text-[var(--fg)]')}>
      {formatCount(value)}
    </div>
    <div className="text-[9px] uppercase tracking-wider text-[var(--muted)]">{label}</div>
  </div>
}

function pathWithinRoot(path: string, root: string) {
  const normalizedPath = path.replace(/\\/g, '/').toLowerCase()
  const normalizedRoot = root.replace(/\\/g, '/').replace(/\/$/, '').toLowerCase()
  return normalizedPath === normalizedRoot || normalizedPath.startsWith(`${normalizedRoot}/`)
}

function forensicTime(value: string | null) {
  return value ? `${absoluteTime(value)} UTC` : '—'
}

function FileRow({ file, active, onClick, tr }: {
  file: BrowseFile; active: boolean; onClick: () => void; tr: Tr
}) {
  return <button type="button" onClick={onClick}
    aria-label={tr('files.queue.openSimple', { name: file.name })}
    aria-pressed={active}
    className={clsx(
      'grid w-full cursor-pointer grid-cols-[20px_minmax(0,1fr)_auto] items-center gap-2.5 border-b border-[var(--line-soft)] px-3 py-2.5 text-left transition-colors last:border-0',
      active ? 'bg-[var(--accent-soft)]' : 'hover:bg-[var(--panel-2)]',
    )}>
    <FileText size={15} className={file.flagged ? 'text-[var(--sev-medium)]' : 'text-[var(--muted)]'} />
    <span className="min-w-0">
      <span className="flex items-center gap-2">
        <span className="mono min-w-0 flex-1 truncate text-[11.5px] font-semibold">{file.name}</span>
        {file.flagged > 0 && file.worst != null && <SeverityBadge severity={file.worst} plain />}
      </span>
      <span className="mt-1 flex items-center gap-2 text-[9.5px] text-[var(--muted)]">
        <span>{formatBytes(file.size)}</span><span>·</span>
        <span>{tr('files.time.modified.short')} {forensicTime(file.modified_at)}</span>
      </span>
    </span>
    {file.flagged > 0 && <Tag tone="warn">{formatCount(file.flagged)}</Tag>}
  </button>
}

function FileReviewPanel({ slug, file, position, total, canPrevious, canNext,
  onPrevious, onNext, onView, onOpenArtifact }: {
  slug: string
  file: BrowseFile | null
  position: number
  total: number
  canPrevious: boolean
  canNext: boolean
  onPrevious: () => void
  onNext: () => void
  onView: () => void
  onOpenArtifact: () => void
}) {
  const tr = useT()
  const preview = useQuery({
    queryKey: ['file-review-preview', slug, file?.path],
    queryFn: () => api<FileContent>(
      `/api/cases/${slug}/file?path=${encodeURIComponent(file!.path)}&mode=raw&offset=0`),
    enabled: !!file,
  })

  if (!file) return <Card className="flex min-h-[560px] items-center justify-center p-8">
    <EmptyState icon={<FileCode2 size={36} />} title={tr('files.review.select')}
      sub={tr('files.review.select.sub')} />
  </Card>

  const facts = preview.data ?? file
  const copyableContent = preview.data?.binary ? '' : preview.data?.lines?.join('\n') ?? ''
  return <Card className="min-w-0 overflow-hidden">
    <header className="flex flex-wrap items-center gap-3 border-b border-[var(--line)] px-4 py-3">
      <span className="flex size-9 items-center justify-center rounded-lg bg-[var(--panel-2)] text-[var(--accent-text)]">
        <FileCode2 size={17} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex min-w-0 items-center gap-1">
          <span className="mono min-w-0 truncate text-[13px] font-bold">{file.name}</span>
          <CopyButton value={file.name} label={tr('copy.name')} className="shrink-0" />
        </span>
        <span className="flex min-w-0 items-center gap-1">
          <span className="mono min-w-0 truncate text-[9.5px] text-[var(--muted)]" title={file.path}>{file.path}</span>
          <CopyButton value={file.path} label={tr('copy.path')} className="shrink-0" />
        </span>
      </span>
      <span className="tabular text-[10px] text-[var(--muted)]">{position} / {formatCount(total)}</span>
      <div className="flex gap-1">
        <Button variant="ghost" disabled={!canPrevious} onClick={onPrevious} title={tr('files.review.previous')}>
          <ArrowLeft size={14} />
        </Button>
        <Button variant="ghost" disabled={!canNext} onClick={onNext} title={tr('files.review.next')}>
          <ArrowRight size={14} />
        </Button>
      </div>
    </header>

    <div className="space-y-4 p-4">
      <section>
        <div className="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.12em] text-[var(--muted)]">
          <Clock3 size={13} /> {tr('files.metadata.title')}
        </div>
        <div className="grid grid-cols-2 gap-2 xl:grid-cols-5">
          <Fact label={tr('files.metadata.size')} value={formatBytes(facts.size)} tr={tr} />
          <Fact label={tr('files.time.created')} value={forensicTime(facts.created_at)} tr={tr} />
          <Fact label={tr('files.time.modified')} value={forensicTime(facts.modified_at)} tr={tr} />
          <Fact label={tr('files.time.accessed')} value={forensicTime(facts.accessed_at)} tr={tr} />
          <Fact label={tr('files.time.changed')} value={forensicTime(facts.changed_at)} tr={tr} />
        </div>
        <p className="mt-2 text-[9.5px] text-[var(--muted)]">{tr('files.metadata.caution')}</p>
      </section>

      <section>
        <div className="mb-2 flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.12em] text-[var(--muted)]">
          <Fingerprint size={13} /> {tr('files.hashes.title')}
        </div>
        <div className="grid gap-2 xl:grid-cols-3">
          <HashFact label="MD5" value={preview.data?.hashes.md5} tr={tr} />
          <HashFact label="SHA-1" value={preview.data?.hashes.sha1} tr={tr} />
          <HashFact label="SHA-256" value={preview.data?.hashes.sha256} tr={tr} />
        </div>
        <p className="mt-2 text-[9.5px] text-[var(--muted)]">
          {preview.data?.hashes_limited
            ? tr('files.hashes.tooLarge')
            : tr('files.hashes.caution')}
        </p>
      </section>

      <section>
        <div className="mb-2 flex items-center justify-between gap-2">
          <span className="text-[10px] font-bold uppercase tracking-[0.12em] text-[var(--muted)]">
            {tr('files.preview.title')}
          </span>
          <span className="flex items-center gap-1">
            {!!copyableContent && <CopyButton value={copyableContent}
              label={preview.data?.eof ? tr('copy.content') : tr('copy.loadedContent')} />}
            <Button variant="ghost" onClick={onView}><FileSearch size={13} /> {tr('files.preview.open')}</Button>
          </span>
        </div>
        <div className="min-h-40 overflow-hidden rounded-lg bg-[var(--code-bg)]">
          {preview.isPending && <div className="p-6 text-center text-[11px] text-[#8993a4]">{tr('common.loading')}</div>}
          {preview.isError && <div className="p-4 text-[11px] text-[#ff8b8b]">{String(preview.error)}</div>}
          {preview.data?.binary && <div className="flex min-h-40 items-center justify-center p-5 text-center text-[11px] text-[#8993a4]">
            {tr('files.preview.binary')}
          </div>}
          {preview.data?.lines && !preview.data.binary && <pre className="mono max-h-64 overflow-auto py-2 text-[10.5px] leading-relaxed text-[#e6edf3]">
            {preview.data.lines.slice(0, 80).map((line, index) => <div key={index} className="flex px-3">
              <span className="w-10 shrink-0 select-none pr-3 text-right text-[#4b5566]">{index + 1}</span>
              <span className="whitespace-pre-wrap break-all">{line || ' '}</span>
            </div>)}
          </pre>}
        </div>
      </section>

      {file.flagged > 0 && <div className="flex flex-wrap items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2.5">
        <Bug size={14} className="text-[var(--sev-medium)]" />
        <span className="min-w-0 flex-1 text-[11px] text-[var(--muted)]">
          {tr('files.detected', { n: formatCount(file.flagged) })}
        </span>
        {file.worst != null && <SeverityBadge severity={file.worst} />}
        {file.triage && <TriageBadge state={file.triage} label={tr(`triage.${file.triage}`)} />}
        <Button variant="ghost" onClick={onOpenArtifact}>{tr('files.detected.open')}</Button>
      </div>}

    </div>
  </Card>
}

function Fact({ label, value, tr }: { label: string; value: string; tr: Tr }) {
  return <div className="rounded-lg bg-[var(--panel-2)] px-2.5 py-2">
    <div className="text-[8.5px] font-bold uppercase tracking-wider text-[var(--muted)]">{label}</div>
    <div className="mt-1 flex min-w-0 items-center gap-1">
      <span className="mono min-w-0 flex-1 break-all text-[10px]">{value}</span>
      <CopyButton value={value} label={tr('copy.value', { what: label })} className="shrink-0" />
    </div>
  </div>
}

function HashFact({ label, value, tr }: {
  label: string; value?: string; tr: Tr
}) {
  return <div className="rounded-lg bg-[var(--panel-2)] px-2.5 py-2">
    <div className="text-[8.5px] font-bold uppercase tracking-wider text-[var(--muted)]">{label}</div>
    <div className="mt-1 flex min-w-0 items-center gap-2">
      <span className="mono min-w-0 flex-1 break-all text-[10px]">{value || '—'}</span>
      {value && <CopyButton value={value} label={tr('copy.hash')} className="shrink-0" />}
    </div>
  </div>
}
