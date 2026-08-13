// Files.tsx -- click through the evidence and take files in as indicators by
// hand.
//
// The rules find what they know. This view is for everything else: the file
// that catches one's eye while looking through, because it sits in the wrong
// place, because its name does not fit, because the modification date falls
// into the night of the incident. A human sees that -- a rule was not
// looking for it.
//
// One starts at the registered evidence roots, not at the file system: what
// belongs to the case is the selection. Going deeper only happens within
// those roots (the same fence as in the file viewer, on the resolved path).
//
// Every entry shows right away what the case already knows about it --
// already in the IOC box, findings on it -- so that one does not mark by
// hand what has long been recorded.
import { plural, useT } from '../i18n'
import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Box, ChevronRight, FileSearch, FileText, FolderOpen, FolderTree, HardDrive,
  Home,
} from 'lucide-react'
import { api, post, type BrowseResponse, type CaseDetail } from '../api'
import {
  formatBytes, formatCount, type EvidenceRoot,
} from '../format'
import {
  Button, Card, EmptyState, SearchInput, SeverityBadge, Tag, TriageBadge,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { FileViewer } from '../components/FileViewer'
import { WebrootDiff } from '../components/WebrootDiff'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import type { ViewId } from '../App'

export function Files({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [path, setPath] = useState('')
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [note, setNote] = useState('')
  const [filter, setFilter] = useState('')
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // What the trace should mark red -- comes from the artifact window, which
  // knows what this is about (the file, or the client's alert).
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const t = useTriage(slug)

  const { data, isError, error } = useQuery({
    queryKey: ['browse', slug, path],
    queryFn: () => api<BrowseResponse>(
      `/api/cases/${slug}/browse?path=${encodeURIComponent(path)}`),
  })
  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))

  // Changing directory discards the selection: a check one can no longer
  // see would later get flagged along by accident.
  useEffect(() => { setChecked(new Set()); setFilter('') }, [path])

  const flag = useMutation({
    mutationFn: (paths: string[]) =>
      post<{ added: { value: string; type: string }[] }>(
        `/api/cases/${slug}/files/flag`, { paths, note }),
    onSuccess: () => {
      setChecked(new Set())
      setNote('')
      qc.invalidateQueries({ queryKey: ['browse'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  const files = useMemo(() => (data?.files ?? []).filter((f) =>
    !filter || f.name.toLowerCase().includes(filter.toLowerCase())),
    [data, filter])
  const dirs = useMemo(() => (data?.dirs ?? []).filter((d) =>
    !filter || d.name.toLowerCase().includes(filter.toLowerCase())),
    [data, filter])

  const atRoot = !path
  const toggleAll = () => {
    if (checked.size === files.length) setChecked(new Set())
    else setChecked(new Set(files.map((f) => f.path)))
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title={tr('nav.files')}
          body={tr('files.title.body')}
          hint={tr('files.title.hint')}>
          <h1 className="mr-2 text-lg font-bold">{tr('nav.files')}</h1>
        </Tooltip>
        {!atRoot && (
          <Button variant="ghost" onClick={() => setPath('')}>
            <Home size={14} /> {tr('files.roots')}
          </Button>
        )}
        {data?.parent != null && (
          <Button variant="ghost" onClick={() => setPath(data.parent!)}>
            {tr('evidence.parentDir')}
          </Button>
        )}
        {!atRoot && (
          <div className="ml-auto">
            <SearchInput value={filter} onChange={setFilter}
              placeholder={tr('files.filter')} />
          </div>
        )}
      </div>

      {!atRoot && (
        <div className="mono truncate rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[11.5px] text-[var(--muted)]"
          title={data?.path}>
          {data?.path}
        </div>
      )}

      {checked.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-4 py-2 animate-fade-up">
          <span className="text-[13px] font-semibold">
            {plural(tr, checked.size, 'files.marked.one', 'files.marked.many',
                    { n: checked.size })}
          </span>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder={tr('files.note.placeholder')}
            className="min-w-56 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
          <Button variant="primary" disabled={flag.isPending}
            onClick={() => flag.mutate([...checked])}>
            <Box size={14} /> {tr('files.toIocBox')}
          </Button>
          <Button variant="ghost" onClick={() => setChecked(new Set())}>
            {tr('common.clearSelection')}
          </Button>
        </div>
      )}

      {flag.data && (
        <div className="rounded-lg border border-[var(--ok)]/40 bg-[rgba(12,163,12,0.08)] px-3 py-2 text-[12px] animate-fade-up">
          <span className="font-semibold text-[var(--ok)]">
            {tr('files.flagged.count', { n: formatCount(flag.data.added.length) })}
          </span>
          <span className="ml-2 text-[var(--muted)]">
            {tr('files.flagged.hashes', {
              n: flag.data.added.filter((a) => a.type === 'hash').length,
            })}
          </span>
        </div>
      )}

      {isError && (
        <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)]">
          {String((error as Error)?.message ?? error)}
        </div>
      )}

      {/* ---- entry point: the roots of the case ---- */}
      {atRoot && (
        <div className="grid gap-3 md:grid-cols-2">
          {data?.roots.map((r) => (
            <Card key={r.path}
              className="px-4 py-3 transition-colors hover:border-[var(--accent)]/60">
              <button
                className="flex w-full cursor-pointer items-center gap-3 text-left"
                onClick={() => setPath(r.path)}>
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
                  <HardDrive size={16} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-semibold">
                    {r.label?.trim() || tr(`evidence.${r.kind}`) || r.kind}
                  </div>
                  <div className="mono truncate text-[11px] text-[var(--muted)]" title={r.path}>
                    {r.path}
                  </div>
                </div>
                <ChevronRight size={16} className="shrink-0 text-[var(--muted)]" />
              </button>
            </Card>
          ))}
          {data && !data.roots.length && (
            <div className="md:col-span-2">
              <EmptyState icon={<FolderTree size={36} />} title={tr('files.empty.title')}
                sub={tr('files.empty.sub')} />
            </div>
          )}
        </div>
      )}

      {/* ---- webroot against a reference copy ---- */}
      {atRoot && (caseInfo?.evidence_items?.length ?? 0) > 0 && (
        <WebrootDiff slug={slug} evidence={caseInfo!.evidence_items}
          onView={(p) => setViewing({ path: p, line: null })} />
      )}

      {/* ---- the content of a directory ---- */}
      {!atRoot && (
        <Card className="overflow-hidden">
          {files.length > 0 && (
            <div className="flex items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5">
              <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                checked={checked.size > 0 && checked.size === files.length}
                onChange={toggleAll} />
              <span className="text-[11px] uppercase tracking-wider text-[var(--muted)]">
                {tr('files.count', {
                  dirs: formatCount(dirs.length), files: formatCount(files.length),
                })}
              </span>
            </div>
          )}
          {dirs.map((d) => (
            <button key={d.path}
              onClick={() => setPath(d.path)}
              className="group flex w-full cursor-pointer items-center gap-2.5 border-b border-[var(--line-soft)] px-3 py-1.5 text-left last:border-0 hover:bg-[var(--panel-2)]">
              <span className="w-4" />
              <FolderOpen size={15} className="shrink-0 text-[var(--muted)]" />
              <span className="min-w-0 flex-1 truncate text-[13px]">{d.name}</span>
              <ChevronRight size={14} className="shrink-0 text-[var(--muted)] opacity-0 group-hover:opacity-100" />
            </button>
          ))}
          {files.map((f) => (
            <div key={f.path}
              className={clsx(
                'group flex items-center gap-2.5 border-b border-[var(--line-soft)] px-3 py-1.5 last:border-0',
                'transition-colors hover:bg-[var(--panel-2)]',
                checked.has(f.path) && 'bg-[var(--accent-soft)]')}>
              <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                checked={checked.has(f.path)}
                onChange={(e) => {
                  const next = new Set(checked)
                  if (e.target.checked) next.add(f.path)
                  else next.delete(f.path)
                  setChecked(next)
                }} />
              <FileText size={15} className="shrink-0 text-[var(--muted)]" />
              <span className="min-w-0 flex-1 truncate text-[13px]" title={f.name}>
                {f.name}
              </span>
              {/* What the case already knows about this file. */}
              {f.flagged > 0 && f.worst != null && (
                <Tooltip hint={tr('files.flagged.hint')}>
                  <button
                    className="shrink-0 cursor-pointer"
                    onClick={() => {
                      t.clearCollected()
                      setSelected({
                        artifact: f.path, artifact_kind: 'file',
                        worst: f.worst!, triage: f.triage ?? 'new',
                        triage_note: '',
                      })
                    }}>
                    <SeverityBadge severity={f.worst} />
                  </button>
                </Tooltip>
              )}
              {f.triage && f.triage !== 'new' && (
                <TriageBadge state={f.triage} label={tr(`triage.${f.triage}`)} />
              )}
              {f.in_box && (
                <Tag tone="accent" explain={tr('files.inBox')}>IOC</Tag>
              )}
              <span className="w-20 shrink-0 text-right tabular text-[11px] text-[var(--muted)]">
                {formatBytes(f.size)}
              </span>
              <Tooltip hint={tr('findings.viewFile.hint')}>
                <button
                  className="shrink-0 cursor-pointer rounded p-1 text-[var(--muted)] opacity-0 transition-opacity hover:text-[var(--accent)] group-hover:opacity-100"
                  onClick={() => setViewing({ path: f.path, line: null })}>
                  <FileSearch size={15} />
                </button>
              </Tooltip>
            </div>
          ))}
          {!dirs.length && !files.length && (
            <div className="px-4 py-8 text-center text-[13px] text-[var(--muted)]">
              {filter ? tr('files.noMatch') : tr('files.emptyDir')}
            </div>
          )}
          {data?.truncated && (
            <div className="border-t border-[var(--line)] px-4 py-2 text-[12px] text-[var(--sev-low)]">
              {tr('files.truncated')}
            </div>
          )}
        </Card>
      )}

      <FileViewer slug={slug} path={viewing?.path ?? null}
        focusLine={viewing?.line} layer={2} onClose={() => setViewing(null)} />
      <ArtifactWindow
        slug={slug}
        artifact={selected}
        roots={roots}
        collected={t.collected}
        onView={(p, line) => setViewing({ path: p, line })}
        onTrace={(ips, m) => { setTraceMarks(m); setTraceIps(ips) }}
        onClose={() => { setSelected(null); t.clearCollected() }}
        onTriage={(state, n) => {
          if (selected) t.decide([selected.artifact], state, n)
        }}
      />
      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
      <TriageFollowUp t={t} roots={roots} />
    </div>
  )
}
