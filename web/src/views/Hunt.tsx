// Hunt.tsx -- the pattern hunt: stored exploit paths against the log index.
//
// The opposite direction from everything else in the tool. Findings and
// Actors show what the SHIPPED rules found; here the analyst brings in their
// own knowledge -- "this path is only requested by someone running this
// exploit" -- and the tool says who requested it.
//
// THE LIBRARY BELONGS TO THE WORKSPACE, NOT TO THE CASE: created once, a
// pattern is ready in every further case. The case only records what was
// searched for in it -- unsuccessfully included, because "we checked for
// this, there was nothing" is written down nowhere else.
import { useT } from '../i18n'
import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  BarChart3, Box, Check, ChevronDown, ChevronUp,
  ChevronsUpDown, Clock3, Crosshair, Download, HelpCircle, Link2,
  ListFilter, PencilLine, Play, Plus, Radar, Search, Settings2, ToggleLeft,
  ToggleRight, Trash2, Upload, Users,
} from 'lucide-react'
import {
  api, del, downloadUrl, patch, post, type HuntClient, type HuntPattern,
  type HuntResult, type HuntRun,
} from '../api'
import { formatCount, formatLogTime, formatSpan } from '../format'
import {
  Button, Card, EmptyState, Tag,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { IpFlag } from '../components/IpFlag'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import type { ViewId } from '../App'

type HuntPreview = Pick<HuntResult,
  'hits' | 'ok_hits' | 'clients_total' | 'ok_clients' | 'uri_total' |
  'first_epoch' | 'last_epoch' | 'timeline'>

export function Hunt({ slug, gotoView }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  // A list, not a string: several paths in one entry are combined over
  // CLIENTS -- "this address fetched the exploit path AND what it dropped".
  const [paths, setPaths] = useState<string[]>([''])
  const [match, setMatch] = useState<'any' | 'all'>('any')
  const [name, setName] = useState('')
  const [cve, setCve] = useState('')
  const [description, setDescription] = useState('')
  const [importText, setImportText] = useState('')
  const [showImport, setShowImport] = useState(false)
  const [results, setResults] = useState<HuntResult[] | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // The URLs hit by the pattern -- marked red in the trace, so that one does
  // not hunt for the request that matters among a thousand others.
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [editing, setEditing] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [showManager, setShowManager] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [librarySearch, setLibrarySearch] = useState('')
  const [libraryMode, setLibraryMode] = useState<'active' | 'all' | 'own'>('active')

  const { data: lib } = useQuery({
    queryKey: ['patterns'],
    queryFn: () => api<{ patterns: HuntPattern[]; path: string
                         bundled: number; disabled: number }>('/api/patterns'),
  })
  const { data: runs } = useQuery({
    queryKey: ['hunt-runs', slug],
    queryFn: () => api<{ runs: HuntRun[] }>(`/api/cases/${slug}/hunt/runs`),
  })

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['patterns'] })
    qc.invalidateQueries({ queryKey: ['hunt-runs'] })
  }

  const add = useMutation({
    mutationFn: () => post('/api/patterns', {
      patterns: paths.map((p) => p.trim()).filter(Boolean),
      match, name, cve, description,
    }),
    onSuccess: () => {
      setPaths(['']); setMatch('any'); setName(''); setCve('')
      setDescription(''); setError(''); preview.reset(); refresh()
    },
    onError: (e: Error) => setError(e.message),
  })
  const bulk = useMutation({
    mutationFn: () => post<{ added: number; skipped: number; invalid: number }>(
      '/api/patterns', { text: importText }),
    onSuccess: (r) => {
      setImportText('')
      setShowImport(false)
      setError(r.invalid
        ? tr('hunt.import.result', { added: r.added, skipped: r.skipped, invalid: r.invalid })
        : '')
      refresh()
    },
    onError: (e: Error) => setError(e.message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => del(`/api/patterns/${id}`),
    onSuccess: refresh,
  })
  // A bundled pattern is switched off, never deleted: it lives in the
  // package, so a delete would come back on the next start.
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      post(`/api/patterns/${id}/enabled`, { enabled }),
    onSuccess: refresh,
  })
  const run = useMutation({
    mutationFn: (ids: string[]) =>
      post<{ results: HuntResult[]; findings: number }>(
        `/api/cases/${slug}/hunt/run`, { ids }),
    onSuccess: (r) => {
      setResults(r.results)
      if (r.results[0]) setSelectedId(r.results[0].id)
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['actors'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      qc.invalidateQueries({ queryKey: ['hunt-runs'] })
    },
  })
  const preview = useMutation({
    mutationFn: () => post<HuntPreview>(`/api/cases/${slug}/hunt/preview`, {
      patterns: paths.map((path) => path.trim()).filter(Boolean), match,
    }),
    onError: (e: Error) => setError(e.message),
  })

  const patterns = lib?.patterns ?? []
  // Only what is switched on gets run, so that is what the button counts.
  const runnable = patterns.filter((p) => p.enabled)
  const runByPattern = new Map((runs?.runs ?? []).map((r) => [r.pattern, r]))
  const shown = results ?? []
  const filteredPatterns = patterns.filter((pattern) => {
    if (libraryMode === 'active' && !pattern.enabled) return false
    if (libraryMode === 'own' && pattern.source !== 'own') return false
    const needle = librarySearch.trim().toLowerCase()
    return !needle || [pattern.name, pattern.cve, pattern.description,
      ...pattern.patterns, ...(pattern.request?.methods ?? []),
      ...(pattern.request?.user_agents ?? [])]
      .some((value) => value.toLowerCase().includes(needle))
  })
  const selected = patterns.find((pattern) => pattern.id === selectedId)
    ?? runnable[0] ?? patterns[0]
  const selectedResult = shown.find((result) => result.id === selected?.id)
  const selectedRun = selected ? runByPattern.get(joinPaths(selected)) : undefined

  useEffect(() => {
    if (!selectedId && selected) setSelectedId(selected.id)
  }, [selected, selectedId])

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start gap-2">
        <div className="mr-auto">
          <Tooltip title={tr('nav.hunt')} body={tr('hunt.title.body')}
            hint={tr('hunt.title.hint')}>
            <h1 className="text-lg font-bold">{tr('nav.hunt')}</h1>
          </Tooltip>
          <p className="mt-0.5 text-[12px] text-[var(--muted)]">{tr('hunt.workspace.sub')}</p>
        </div>
        <Button variant="primary" disabled={!selected?.enabled || run.isPending}
          onClick={() => selected && run.mutate([selected.id])}>
          <Play size={14} /> {run.isPending ? tr('hunt.searching') : tr('hunt.runSelected')}
        </Button>
        <Button disabled={!runnable.length || run.isPending} onClick={() => run.mutate([])}>
          <Radar size={14} /> {tr('hunt.runEnabled', { n: formatCount(runnable.length) })}
        </Button>
        <Button onClick={() => setShowManager(!showManager)}>
          <Settings2 size={14} /> {tr('hunt.manageLibrary')}
        </Button>
      </div>

      {run.data && (
        <div className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12px] text-[var(--muted)]">
          {run.data.findings > 0
            ? <>{tr('hunt.findingsWritten', { n: formatCount(run.data.findings) })} —{' '}
              <button className="cursor-pointer text-[var(--accent-text)] hover:underline"
                onClick={() => gotoView('findings')}>{tr('hunt.seeInList')}</button></>
            : tr('hunt.noHits')}
        </div>
      )}
      {error && (
        <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)]">
          {error}
        </div>
      )}

      <div className="grid min-h-[620px] gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
        <Card className="flex min-h-0 flex-col overflow-hidden">
          <div className="border-b border-[var(--line)] p-3">
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-2.5 text-[var(--muted)]" />
              <input value={librarySearch} onChange={(event) => setLibrarySearch(event.target.value)}
                placeholder={tr('hunt.library.search')}
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] py-2 pl-8 pr-2 text-[12px] outline-none focus:border-[var(--accent)]/70" />
            </div>
            <div className="mt-2 flex gap-1">
              {(['active', 'all', 'own'] as const).map((mode) => (
                <button key={mode} type="button" onClick={() => setLibraryMode(mode)}
                  className={clsx('cursor-pointer rounded-md px-2 py-1 text-[10.5px] font-medium',
                    libraryMode === mode
                      ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                      : 'text-[var(--muted)] hover:bg-[var(--panel-2)]')}>
                  {tr(`hunt.library.filter.${mode}`)}
                </button>
              ))}
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {filteredPatterns.map((pattern) => {
              const result = shown.find((entry) => entry.id === pattern.id)
              const last = runByPattern.get(joinPaths(pattern))
              const hits = result?.hits ?? last?.hits
              const ok = result?.ok_hits ?? last?.ok_hits
              return (
                <button key={pattern.id} type="button" onClick={() => setSelectedId(pattern.id)}
                  aria-pressed={selected?.id === pattern.id}
                  className={clsx('w-full cursor-pointer border-b border-[var(--line-soft)] px-3 py-2.5 text-left transition-colors',
                    selected?.id === pattern.id
                      ? 'bg-[var(--accent-soft)] shadow-[inset_3px_0_0_var(--accent)]'
                      : 'hover:bg-[var(--panel-2)]',
                    !pattern.enabled && 'opacity-45')}>
                  <span className="flex items-start justify-between gap-2">
                    <span className="min-w-0">
                      <span className="block truncate text-[12.5px] font-semibold">
                        {pattern.name || pattern.patterns[0]}
                      </span>
                      <span className="mono mt-0.5 block truncate text-[10.5px] text-[var(--muted)]">
                        {joinPaths(pattern)}
                      </span>
                    </span>
                    {hits !== undefined && (
                      <span className={clsx('shrink-0 text-[11px] font-semibold tabular',
                        ok ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
                        {formatCount(hits)}
                      </span>
                    )}
                  </span>
                  <span className="mt-1.5 flex flex-wrap gap-1">
                    {pattern.cve && <Tag>{pattern.cve}</Tag>}
                    <Tag>{pattern.source === 'bundled' ? tr('hunt.bundled') : tr('hunt.own')}</Tag>
                    <PatternConditions pattern={pattern} compact />
                    {!pattern.enabled && <Tag>{tr('hunt.disabled')}</Tag>}
                  </span>
                </button>
              )
            })}
            {!filteredPatterns.length && (
              <div className="p-6 text-center text-[12px] text-[var(--muted)]">
                {tr('hunt.library.noMatch')}
              </div>
            )}
          </div>
        </Card>

        <div className="flex min-w-0 flex-col gap-4">
          {selected ? (() => {
            const meaning = splitDescription(selected.description)
            return <>
              <Card className="overflow-hidden">
                <div className="flex flex-wrap items-start gap-3 border-b border-[var(--line)] px-4 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="text-[15px] font-semibold">{selected.name || selected.patterns[0]}</h2>
                      {selected.cve && <Tag tone="accent">{selected.cve}</Tag>}
                      <Tag>{selected.source === 'bundled' ? tr('hunt.bundled') : tr('hunt.own')}</Tag>
                    </div>
                    <div className="mono mt-1 break-all text-[11px] text-[var(--muted)]">
                      {joinPaths(selected)}
                    </div>
                    <PatternConditions pattern={selected} />
                  </div>
                  <Button variant="primary" disabled={!selected.enabled || run.isPending}
                    onClick={() => run.mutate([selected.id])}>
                    <Play size={13} /> {tr('hunt.runHypothesis')}
                  </Button>
                </div>
                <div className="grid gap-3 p-4 md:grid-cols-2">
                  <div className="rounded-lg bg-[var(--panel-2)] p-3">
                    <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--accent-text)]">
                      <Check size={12} /> {tr('hunt.means.title')}
                    </div>
                    <p className="text-[12px] leading-relaxed text-[var(--fg)]/85">
                      {meaning.means || tr('hunt.means.fallback')}
                    </p>
                  </div>
                  <div className="rounded-lg bg-[var(--panel-2)] p-3">
                    <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">
                      <HelpCircle size={12} /> {tr('hunt.notMeans.title')}
                    </div>
                    <p className="text-[12px] leading-relaxed text-[var(--muted)]">
                      {meaning.notMeans || tr('hunt.notMeans.fallback')}
                    </p>
                  </div>
                </div>
                {selectedRun && !selectedResult && (
                  <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-[var(--line)] px-4 py-2 text-[11.5px] text-[var(--muted)]">
                    <span>{tr('hunt.lastRun', { at: selectedRun.ran_at.replace('T', ' ') })}</span>
                    <span>{formatCount(selectedRun.clients)} {tr('hunt.clients')}</span>
                    <span>{formatCount(selectedRun.ok_clients)} {tr('hunt.clients2xx')}</span>
                    <span>{formatCount(selectedRun.hits)} {tr('hunt.requests')}</span>
                  </div>
                )}
              </Card>

              {selectedResult ? (
                <ResultCard slug={slug} result={selectedResult}
                  onTrace={(ips) => {
                    setTraceMarks({ exact: selectedResult.uris.map((uri) => uri.uri),
                                    reason: tr('hunt.traceReason') })
                    setTraceIps(ips)
                  }} />
              ) : (
                <Card className="px-5 py-10 text-center">
                  <Radar size={30} className="mx-auto text-[var(--muted)]" />
                  <div className="mt-3 text-[13px] font-semibold">{tr('hunt.result.ready')}</div>
                  <p className="mx-auto mt-1 max-w-md text-[12px] text-[var(--muted)]">
                    {tr('hunt.result.ready.sub')}
                  </p>
                </Card>
              )}
            </>
          })() : (
            <EmptyState icon={<Radar size={36} />} title={tr('hunt.empty.title')}
              sub={tr('hunt.empty.sub')} />
          )}
        </div>
      </div>

      {showManager && (
        <Card className="overflow-hidden">
          <div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2.5">
            <Settings2 size={14} className="text-[var(--accent)]" />
            <span className="mr-auto text-[13px] font-semibold">{tr('hunt.manageLibrary')}</span>
            <InfoDot title={tr('hunt.library.title')}
              body={tr('hunt.library.body', { path: lib?.path ?? '—' })}
              hint={tr('hunt.library.hint')} wide />
            <Button onClick={() => setShowImport(!showImport)}>
              <Upload size={13} /> {tr('hunt.import')}
            </Button>
            <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-1.5 text-[12px] font-medium hover:border-[var(--accent)]/60"
              href={downloadUrl('/api/patterns/export')}>
              <Download size={13} /> {tr('hunt.backup')}
            </a>
          </div>
          <div className="flex flex-wrap items-end gap-2 border-b border-[var(--line)] p-4">
            <div className="flex basis-full flex-col gap-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                {tr('hunt.field.pattern')}
              </span>
              <PathList paths={paths} onChange={(next) => { setPaths(next); preview.reset() }} />
              {paths.filter((path) => path.trim()).length > 1 && (
                <MatchPicker value={match} onChange={(next) => { setMatch(next); preview.reset() }} />
              )}
            </div>
            <label className="flex w-56 flex-col gap-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">{tr('hunt.field.name')}</span>
              <input value={name} onChange={(event) => setName(event.target.value)}
                placeholder="Joomla JCE editor RCE"
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
            </label>
            <label className="flex w-48 flex-col gap-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">{tr('hunt.field.cve')}</span>
              <input value={cve} onChange={(event) => setCve(event.target.value)}
                placeholder="CVE-2026-48907"
                className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
            </label>
            <label className="flex min-w-72 flex-1 basis-full flex-col gap-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">{tr('hunt.field.description')}</span>
              <textarea value={description} onChange={(event) => setDescription(event.target.value)}
                rows={2} placeholder={tr('hunt.field.description.placeholder')}
                className="w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
            </label>
            <Button disabled={!paths.some((path) => path.trim()) || preview.isPending}
              onClick={() => preview.mutate()}>
              <Search size={13} /> {preview.isPending ? tr('hunt.searching') : tr('hunt.preview')}
            </Button>
            <Button variant="primary" disabled={!paths.some((path) => path.trim())}
              onClick={() => add.mutate()}>
              <Plus size={14} /> {tr('hunt.store')}
            </Button>
            {preview.data && (
              <div className="basis-full rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[12px] text-[var(--muted)]">
                {tr('hunt.preview.result', {
                  requests: formatCount(preview.data.hits),
                  clients: formatCount(preview.data.clients_total),
                  ok: formatCount(preview.data.ok_hits),
                  urls: formatCount(preview.data.uri_total),
                })}
              </div>
            )}
          </div>

          {showImport && (
            <div className="flex flex-col gap-2 border-b border-[var(--line)] p-4">
              <div className="text-[12px] text-[var(--muted)]">
                {tr('hunt.import.a')} <span className="mono">pattern | name | note</span>.{' '}
                {tr('hunt.import.b')} <span className="mono">#</span> {tr('hunt.import.c')}
              </div>
              <textarea value={importText} onChange={(event) => setImportText(event.target.value)}
                rows={5} placeholder={`# ${tr('hunt.import.example')}\n/administrator/components/com_adsmanager/ | AdsManager LFI`}
                className="mono w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12px] outline-none focus:border-[var(--accent)]/70" />
              <div className="flex gap-2">
                <Button variant="primary" disabled={!importText.trim()} onClick={() => bulk.mutate()}>{tr('hunt.read')}</Button>
                <Button variant="ghost" onClick={() => setShowImport(false)}>{tr('common.cancel')}</Button>
              </div>
            </div>
          )}

          <div>
            {patterns.map((pattern) => {
              if (editing === pattern.id) {
                return <PatternEditor key={pattern.id} slug={slug} entry={pattern}
                  onDone={() => { setEditing(null); refresh() }} />
              }
              const shipped = pattern.source === 'bundled'
              return (
                <div key={pattern.id} className={clsx(
                  'flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2 last:border-0',
                  !pattern.enabled && 'opacity-45')}>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[12.5px] font-medium">{pattern.name || pattern.patterns[0]}</div>
                    <div className="mono truncate text-[10.5px] text-[var(--muted)]">{joinPaths(pattern)}</div>
                    <PatternConditions pattern={pattern} compact />
                  </div>
                  {!shipped && (
                    <button aria-label={tr('hunt.edit.hint')} onClick={() => setEditing(pattern.id)}
                      className="cursor-pointer rounded p-1.5 text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--accent)]">
                      <PencilLine size={14} />
                    </button>
                  )}
                  {shipped ? (
                    <button aria-label={pattern.enabled ? tr('hunt.disable.hint') : tr('hunt.enable.hint')}
                      onClick={() => toggle.mutate({ id: pattern.id, enabled: !pattern.enabled })}
                      className="cursor-pointer rounded p-1.5 text-[var(--muted)] hover:bg-[var(--panel-2)]">
                      {pattern.enabled ? <ToggleRight size={16} className="text-[var(--accent)]" /> : <ToggleLeft size={16} />}
                    </button>
                  ) : (
                    <button aria-label={tr('hunt.delete.hint')} onClick={() => remove.mutate(pattern.id)}
                      className="cursor-pointer rounded p-1.5 text-[var(--muted)] hover:bg-[var(--danger-soft)] hover:text-[var(--danger-text)]">
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
              )
            })}
          </div>
        </Card>
      )}

      <TraceWindow slug={slug} ips={traceIps} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
    </div>
  )
}

function splitDescription(description: string) {
  const marker = /WHAT A HIT DOES NOT PROVE:/i
  const parts = description.split(marker)
  return { means: parts[0]?.trim() ?? '', notMeans: parts[1]?.trim() ?? '' }
}

/** Amend a pattern. Changes apply to ALL cases -- the library belongs to the
 *  workspace, and that is exactly what the button says. */
function PatternEditor({ slug, entry, onDone }: {
  slug: string
  entry: HuntPattern
  onDone: () => void
}) {
  const tr = useT()
  const [paths, setPaths] = useState<string[]>(entry.patterns)
  const [match, setMatch] = useState<'any' | 'all'>(entry.match)
  const [name, setName] = useState(entry.name)
  const [cve, setCve] = useState(entry.cve)
  const [description, setDescription] = useState(entry.description)
  const [error, setError] = useState('')
  void slug

  const save = useMutation({
    mutationFn: () =>
      patch(`/api/patterns/${entry.id}`, {
        patterns: paths.map((p) => p.trim()).filter(Boolean),
        match, name, cve, description,
      }),
    onSuccess: onDone,
    onError: (e: Error) => setError(e.message),
  })

  return (
    <div className="flex flex-col gap-2 border-b border-[var(--line-soft)] bg-[var(--panel-2)] px-4 py-3 last:border-0">
      <div className="flex flex-wrap items-end gap-2">
        <div className="flex basis-full flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('hunt.field.pattern')}
          </span>
          <PathList paths={paths} onChange={setPaths} dark />
          {paths.filter((p) => p.trim()).length > 1 && (
            <MatchPicker value={match} onChange={setMatch} />
          )}
        </div>
        <label className="flex w-48 flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('hunt.field.name')}
          </span>
          <input value={name} onChange={(e) => setName(e.target.value)}
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
        </label>
        <label className="flex w-40 flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('hunt.field.cve')}
          </span>
          <input value={cve} onChange={(e) => setCve(e.target.value)}
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
        </label>
        <Button variant="primary"
          disabled={!paths.some((p) => p.trim()) || save.isPending}
          onClick={() => save.mutate()}>
          {tr('common.save')}
        </Button>
        <Button variant="ghost" onClick={onDone}>{tr('common.cancel')}</Button>
        <label className="flex basis-full flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('hunt.field.description')}
          </span>
          <textarea value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            placeholder={tr('hunt.field.description.placeholder')}
            className="w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
        </label>
      </div>
      <div className="text-[11px] text-[var(--muted)]">
        {tr('hunt.edit.note')}
      </div>
      {error && <div className="text-[12px] text-[var(--danger-text)]">{error}</div>}
    </div>
  )
}

/** The key figures of a search in one block. A 2xx is deliberately described
 * as a server response, never as proof that exploitation succeeded. */
function HuntSummary({ result }: { result: HuntResult }) {
  const tr = useT()
  const confirmed = result.clients.filter((client) => client.triage === 'confirmed').length
  const inBox = result.clients.filter((client) => client.in_box).length
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-b border-[var(--line)] px-4 py-3">
      <Tooltip hint={tr('hunt.result.clients2xx.hint')}>
        <div className="flex items-baseline gap-1.5">
          <span className={clsx('text-[19px] font-bold leading-none tabular',
            result.ok_clients ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
            {formatCount(result.ok_clients)}
          </span>
          <span className="flex items-center gap-1 text-[13px] text-[var(--muted)]">
            {tr('hunt.result.clients2xx', { total: formatCount(result.clients_total) })}
            <HelpCircle size={11} className="shrink-0 opacity-50" />
          </span>
        </div>
      </Tooltip>

      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[12px] text-[var(--muted)]">
        <Tooltip hint={tr('hunt.requests.hint')}>
          <span>
            <span className="mono tabular text-[var(--fg)]">{formatCount(result.hits)}</span>
            {' '}{tr('hunt.requests')}, {tr('hunt.ofWhich')}{' '}
            <span className={clsx('mono tabular',
              result.ok_hits ? 'text-[var(--sev-high)]' : '')}>
              {formatCount(result.ok_hits)}×
            </span> {tr('hunt.with2xx')}
          </span>
        </Tooltip>
        <span className="opacity-40">·</span>
        <Tooltip hint={tr('hunt.time.hint')}>
          <span>
            <span className="mono tabular text-[var(--fg)]">
              {formatLogTime(result.first_epoch, result.tz)}
            </span>
            {' → '}
            <span className="mono tabular text-[var(--fg)]">
              {formatLogTime(result.last_epoch, result.tz)}
            </span>
            {' '}({formatSpan(result.first_epoch, result.last_epoch)})
          </span>
        </Tooltip>
        <span className="opacity-40">·</span>
        <Tooltip hint={tr('hunt.urls.hint')}>
          <span>
            <span className="mono tabular text-[var(--fg)]">
              {formatCount(result.uri_total)}
            </span> {result.uri_total === 1 ? 'URL' : 'URLs'}
          </span>
        </Tooltip>
      </div>
      <div className="ml-auto flex flex-wrap gap-1.5">
        {confirmed > 0 && <Tag tone="danger">{tr('hunt.result.confirmed', { n: formatCount(confirmed) })}</Tag>}
        {inBox > 0 && <Tag tone="accent">{tr('hunt.result.inBox', { n: formatCount(inBox) })}</Tag>}
      </div>
    </div>
  )
}

type SortCol = 'ip' | 'hits' | 'ok_hits' | 'first' | 'last' | 'dauer'
type Sort = { col: SortCol; desc: boolean }

/** An address as a number, so that 2 comes before 10. IPv6 falls back to a
 *  text comparison -- there the order is only a grouping anyway, not a
 *  statement. */
function ipKey(ip: string): string {
  const parts = ip.split('.')
  if (parts.length !== 4) return ip
  return parts.map((p) => p.padStart(3, '0')).join('.')
}

function SortHead({ col, sort, onSort, className, children }: {
  col: SortCol
  sort: Sort
  onSort: (s: Sort) => void
  className?: string
  children: React.ReactNode
}) {
  const active = sort.col === col
  return (
    <th className={className}>
      <button
        onClick={() => onSort({ col, desc: active ? !sort.desc : true })}
        className={clsx(
          'inline-flex cursor-pointer items-center gap-1 uppercase tracking-wider hover:text-[var(--fg)]',
          active && 'text-[var(--fg)]')}
      >
        {children}
        {active
          ? (sort.desc ? <ChevronDown size={11} /> : <ChevronUp size={11} />)
          : <ChevronsUpDown size={11} className="opacity-40" />}
      </button>
    </th>
  )
}

/** What a pattern found. The URIs hit are included: a pattern that reaches
 *  too far can only be recognised by seeing WHAT it hit. */
function ResultCard({ slug, result, onTrace }: {
  slug: string
  result: HuntResult
  onTrace: (ips: string[]) => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const [tab, setTab] = useState<'clients' | 'urls' | 'timeline'>('clients')
  const [sort, setSort] = useState<Sort>({ col: 'ok_hits', desc: true })
  const [clientSearch, setClientSearch] = useState('')
  const [only2xx, setOnly2xx] = useState(false)
  const [onlyCorrelated, setOnlyCorrelated] = useState(false)
  const [selectedIps, setSelectedIps] = useState<Set<string>>(new Set())

  const clients = useMemo(() => {
    const dir = sort.desc ? -1 : 1
    const needle = clientSearch.trim().toLowerCase()
    return [...result.clients].filter((client) => {
      if (needle && !client.ip.toLowerCase().includes(needle)) return false
      if (only2xx && !client.ok_hits) return false
      if (onlyCorrelated && client.triage !== 'confirmed' && !client.in_box && !client.finding_count) return false
      return true
    }).sort((a, b) => {
      if (sort.col === 'ip') return dir * ipKey(a.ip).localeCompare(ipKey(b.ip))
      if (sort.col === 'first') return dir * ((a.first_epoch ?? 0) - (b.first_epoch ?? 0))
      if (sort.col === 'last') return dir * ((a.last_epoch ?? 0) - (b.last_epoch ?? 0))
      if (sort.col === 'dauer') {
        const s = (c: HuntClient) => (c.last_epoch ?? 0) - (c.first_epoch ?? 0)
        return dir * (s(a) - s(b))
      }
      const d = dir * (a[sort.col] - b[sort.col])
      // A tie breaks by request count, otherwise rows jump on every redraw
      // -- 40 addresses with one hit each are not a rarity.
      return d || b.hits - a.hits
    })
  }, [clientSearch, only2xx, onlyCorrelated, result.clients, sort])

  useEffect(() => {
    setSelectedIps(new Set())
    setClientSearch('')
    setOnly2xx(false)
    setOnlyCorrelated(false)
    setTab('clients')
  }, [result.id])

  const selected = [...selectedIps]
  const allVisibleSelected = clients.length > 0 && clients.every((client) => selectedIps.has(client.ip))
  const setVisibleSelected = (checked: boolean) => {
    setSelectedIps((current) => {
      const next = new Set(current)
      clients.forEach((client) => {
        if (checked) next.add(client.ip)
        else next.delete(client.ip)
      })
      return next
    })
  }
  const setClientSelected = (ip: string, checked: boolean) => {
    setSelectedIps((current) => {
      const next = new Set(current)
      if (checked) next.add(ip)
      else next.delete(ip)
      return next
    })
  }

  // The origin names the pattern: "requested the exploit path" is the
  // statement that counts in the report -- not "collected from a list".
  // It is written into the case and therefore stays English.
  const collect = useMutation({
    mutationFn: (ips: string[]) => post<{ added: number }>(
      `/api/cases/${slug}/actors/collect`,
      { ips, origin: `pattern hit: ${result.name || result.pattern}` }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['iocs'] })
      qc.invalidateQueries({ queryKey: ['actors'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  if (!result.hits) {
    return (
      <Card className="px-5 py-8 text-center">
        <Radar size={28} className="mx-auto text-[var(--muted)]" />
        <div className="mt-3 text-[13px] font-semibold">{tr('hunt.result.noHit.title')}</div>
        <p className="mx-auto mt-1 max-w-lg text-[12px] text-[var(--muted)]">
          {tr('hunt.result.noHit.sub')}
        </p>
      </Card>
    )
  }
  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2.5">
        <Radar size={14} className="text-[var(--accent)]" />
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold">{tr('hunt.result.evidence')}</div>
          <div className="text-[11px] text-[var(--muted)]">{tr('hunt.result.evidence.sub')}</div>
        </div>
        <span className="text-[11px] text-[var(--muted)]">
          {tr('hunt.result.selected', { n: formatCount(selected.length) })}
        </span>
        <Button disabled={!selected.length} onClick={() => onTrace(selected)}>
          <Crosshair size={13} /> {tr('hunt.result.traceSelected')}
        </Button>
        <Button variant="primary" disabled={!selected.length || collect.isPending}
          onClick={() => collect.mutate(selected)}>
          <Box size={13} /> {tr('hunt.result.collectSelected')}
        </Button>
      </div>

      <HuntSummary result={result} />

      {collect.data && (
        <div className="border-b border-[var(--line)] bg-[rgba(12,163,12,0.08)] px-4 py-1.5 text-[12px] text-[var(--ok)] animate-fade-up">
          {tr('hunt.collected', { n: formatCount(collect.data.added) })}{' '}
          &ldquo;pattern hit: {result.name || result.pattern}&rdquo;
        </div>
      )}

      {result.truncated && (
        <div className="border-b border-[var(--line)] bg-[rgba(250,178,25,0.10)] px-4 py-1.5 text-[11.5px] text-[var(--sev-low)]">
          {tr('hunt.truncated')}
        </div>
      )}
      {result.clients_truncated && (
        <div className="border-b border-[var(--line)] bg-[rgba(250,178,25,0.08)] px-4 py-1.5 text-[11.5px] text-[var(--sev-low)]">
          {tr('hunt.result.clientsTruncated', {
            shown: formatCount(result.clients.length), total: formatCount(result.clients_total),
          })}
        </div>
      )}
      {result.uris_truncated && (
        <div className="border-b border-[var(--line)] bg-[rgba(250,178,25,0.08)] px-4 py-1.5 text-[11.5px] text-[var(--sev-low)]">
          {tr('hunt.result.urlsTruncated', {
            shown: formatCount(result.uris.length), total: formatCount(result.uri_total),
          })}
        </div>
      )}

      <div className="flex items-center gap-1 border-b border-[var(--line)] px-3 pt-2">
        {([
          ['clients', Users, tr('hunt.result.clients'), result.clients_total],
          ['urls', Link2, tr('hunt.result.urls'), result.uri_total],
          ['timeline', BarChart3, tr('hunt.result.timeline'), result.timeline.length],
        ] as const).map(([id, Icon, label, count]) => (
          <button key={id} type="button" onClick={() => setTab(id)}
            className={clsx('flex cursor-pointer items-center gap-1.5 border-b-2 px-3 py-2 text-[12px] font-medium',
              tab === id
                ? 'border-[var(--accent)] text-[var(--fg)]'
                : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]')}>
            <Icon size={13} /> {label} <span className="tabular opacity-60">{formatCount(count)}</span>
          </button>
        ))}
      </div>

      {tab === 'clients' && <>
        <div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2">
          <ListFilter size={13} className="text-[var(--muted)]" />
          <div className="relative min-w-44 flex-1 sm:max-w-64">
            <Search size={12} className="absolute left-2.5 top-2 text-[var(--muted)]" />
            <input value={clientSearch} onChange={(event) => setClientSearch(event.target.value)}
              placeholder={tr('hunt.result.searchClients')}
              className="w-full rounded-md border border-[var(--line)] bg-[var(--panel)] py-1.5 pl-7 pr-2 text-[11.5px] outline-none focus:border-[var(--accent)]/70" />
          </div>
          <label className="flex cursor-pointer items-center gap-1.5 text-[11.5px] text-[var(--muted)]">
            <input type="checkbox" checked={only2xx} onChange={(event) => setOnly2xx(event.target.checked)} />
            {tr('hunt.result.only2xx')}
          </label>
          <label className="flex cursor-pointer items-center gap-1.5 text-[11.5px] text-[var(--muted)]">
            <input type="checkbox" checked={onlyCorrelated} onChange={(event) => setOnlyCorrelated(event.target.checked)} />
            {tr('hunt.result.onlyCorrelated')}
          </label>
          <span className="ml-auto text-[11px] tabular text-[var(--muted)]">
            {formatCount(clients.length)} / {formatCount(result.clients_total)}
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
                <th className="w-9 px-3 py-2">
                  <input type="checkbox" checked={allVisibleSelected}
                    aria-label={tr('hunt.result.selectVisible')}
                    onChange={(event) => setVisibleSelected(event.target.checked)} />
                </th>
                <SortHead className="px-2 py-2" col="ip" sort={sort} onSort={setSort}>Client</SortHead>
                <SortHead className="px-2 py-2 text-right" col="hits" sort={sort} onSort={setSort}>{tr('hunt.requests')}</SortHead>
                <SortHead className="px-2 py-2 text-right" col="ok_hits" sort={sort} onSort={setSort}>2xx</SortHead>
                <SortHead className="px-2 py-2" col="first" sort={sort} onSort={setSort}>{tr('hunt.firstHit')}</SortHead>
                <SortHead className="px-2 py-2" col="last" sort={sort} onSort={setSort}>{tr('hunt.lastHit')}</SortHead>
                <SortHead className="px-2 py-2 text-right" col="dauer" sort={sort} onSort={setSort}>
                  {tr('hunt.duration')} <InfoDot body={tr('field.duration')} hint={tr('field.duration_why')} />
                </SortHead>
                <th className="w-20 px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {clients.map((client) => (
                <tr key={client.ip}
                  className="group border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]">
                  <td className="px-3 py-2">
                    <input type="checkbox" checked={selectedIps.has(client.ip)}
                      aria-label={client.ip}
                      onChange={(event) => setClientSelected(client.ip, event.target.checked)} />
                  </td>
                  <td className="px-2 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <IpFlag ip={client.ip} />
                      <span className="mono font-medium">{client.ip}</span>
                    </span>
                    <span className="ml-2 inline-flex flex-wrap gap-1 align-middle">
                      {client.ok_hits > 0 && <Tag tone="warn" hint={tr('hunt.result.clients2xx.hint')}>2xx</Tag>}
                      {client.triage === 'confirmed' && <Tag tone="danger">{tr('hunt.result.confirmed.short')}</Tag>}
                      {client.in_box && <Tag tone="accent">IOC</Tag>}
                      {client.finding_count > 0 && <Tag>{tr('hunt.result.findings', { n: formatCount(client.finding_count) })}</Tag>}
                    </span>
                  </td>
                  <td className="px-2 py-2 text-right tabular">{formatCount(client.hits)}</td>
                  <td className={clsx('px-2 py-2 text-right font-medium tabular',
                    client.ok_hits ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
                    {formatCount(client.ok_hits)}
                  </td>
                  <td className="mono px-2 py-2 text-[12px] tabular text-[var(--muted)]">{formatLogTime(client.first_epoch, client.tz)}</td>
                  <td className="mono px-2 py-2 text-[12px] tabular text-[var(--muted)]">{formatLogTime(client.last_epoch, client.tz)}</td>
                  <td className="mono px-2 py-2 text-right text-[12px] tabular">{formatSpan(client.first_epoch, client.last_epoch)}</td>
                  <td className="px-3 py-2 text-right">
                    <Button variant="ghost" onClick={() => onTrace([client.ip])}>
                      <Crosshair size={13} /> Trace
                    </Button>
                  </td>
                </tr>
              ))}
              {!clients.length && (
                <tr><td colSpan={8} className="px-4 py-10 text-center text-[12px] text-[var(--muted)]">{tr('hunt.result.noneFiltered')}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </>}

      {tab === 'urls' && (
        <div>
          <div className="border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2 text-[11.5px] text-[var(--muted)]">
            {result.uri_total > result.uris.length
              ? tr('hunt.topUrls', { n: formatCount(result.uris.length) })
              : tr('hunt.checkPattern')}
          </div>
          {result.uris.map((uri) => (
            <div key={uri.uri} className="flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2 text-[12px] last:border-0">
              <span className="mono min-w-0 flex-1 break-all">{uri.uri}</span>
              <span className="shrink-0 tabular text-[var(--muted)]">{formatCount(uri.hits)}× · {formatCount(uri.ok_hits)}× 2xx</span>
            </div>
          ))}
        </div>
      )}

      {tab === 'timeline' && <HuntTimeline result={result} />}
    </Card>
  )
}

function HuntTimeline({ result }: { result: HuntResult }) {
  const tr = useT()
  const maximum = Math.max(1, ...result.timeline.map((day) => day.requests))
  if (!result.timeline.length) {
    return <div className="px-4 py-10 text-center text-[12px] text-[var(--muted)]">{tr('hunt.result.noTimeline')}</div>
  }
  return (
    <div className="p-4">
      <div className="mb-4 flex items-center gap-2 text-[11.5px] text-[var(--muted)]">
        <Clock3 size={13} /> {tr('hunt.result.timeline.sub')}
      </div>
      <div className="flex h-44 items-end gap-1.5 border-b border-[var(--line)] px-1">
        {result.timeline.map((day) => (
          <Tooltip key={day.day}
            title={day.day}
            body={tr('hunt.result.timeline.day', {
              requests: formatCount(day.requests), ok: formatCount(day.ok), clients: formatCount(day.clients),
            })}>
            <div className="group flex h-full min-w-3 flex-1 items-end">
              <div className="relative w-full rounded-t bg-[var(--accent)]/45 transition-colors group-hover:bg-[var(--accent)]"
                style={{ height: `${Math.max(4, (day.requests / maximum) * 100)}%` }}>
                {day.ok > 0 && (
                  <div className="absolute inset-x-0 bottom-0 rounded-t bg-[var(--sev-high)]"
                    style={{ height: `${Math.max(3, (day.ok / day.requests) * 100)}%` }} />
                )}
              </div>
            </div>
          </Tooltip>
        ))}
      </div>
      <div className="mt-2 flex items-center justify-between text-[10.5px] text-[var(--muted)]">
        <span>{result.timeline[0]?.day}</span>
        <span className="flex gap-3">
          <span><i className="mr-1 inline-block size-2 rounded-sm bg-[var(--accent)]/45" />{tr('hunt.requests')}</span>
          <span><i className="mr-1 inline-block size-2 rounded-sm bg-[var(--sev-high)]" />2xx</span>
        </span>
        <span>{result.timeline[result.timeline.length - 1]?.day}</span>
      </div>
    </div>
  )
}


/** Several paths in one entry. A list rather than one field because the
 *  point is combining them -- and a comma-separated string would break on
 *  the first path that legitimately contains a comma. */
function PathList({ paths, onChange, onSubmit, dark }: {
  paths: string[]
  onChange: (next: string[]) => void
  onSubmit?: () => void
  dark?: boolean
}) {
  const tr = useT()
  const set = (i: number, value: string) =>
    onChange(paths.map((p, j) => (j === i ? value : p)))
  return (
    <div className="flex flex-col gap-1.5">
      {paths.map((value, i) => (
        <div key={i} className="flex items-center gap-1.5">
          <input
            value={value}
            onChange={(e) => set(i, e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && onSubmit) onSubmit() }}
            placeholder={tr('hunt.field.pattern.placeholder')}
            className={clsx('mono min-w-0 flex-1 rounded-lg border border-[var(--line)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70',
              dark ? 'bg-[var(--panel)]' : 'bg-[var(--panel-2)]')}
          />
          {paths.length > 1 && (
            <button onClick={() => onChange(paths.filter((_, j) => j !== i))}
              title={tr('hunt.path.remove')}
              className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] hover:bg-[var(--danger-soft)] hover:text-[var(--danger-text)]">
              <Trash2 size={14} />
            </button>
          )}
        </div>
      ))}
      <button onClick={() => onChange([...paths, ''])}
        className="inline-flex w-fit cursor-pointer items-center gap-1 text-[12px] text-[var(--accent-text)] hover:underline">
        <Plus size={13} /> {tr('hunt.path.add')}
      </button>
    </div>
  )
}

/** How several paths combine. OVER CLIENTS -- a URI cannot be two paths at
 *  once, so per request the question would be meaningless. */
function MatchPicker({ value, onChange }: {
  value: 'any' | 'all'
  onChange: (v: 'any' | 'all') => void
}) {
  const tr = useT()
  return (
    <div className="flex items-center gap-1.5">
      {(['any', 'all'] as const).map((mode) => (
        <Tooltip key={mode} hint={tr(`hunt.match.${mode}.hint`)}>
          <button onClick={() => onChange(mode)}
            className={clsx('cursor-pointer rounded-lg border px-2.5 py-1 text-[12px] font-medium transition-colors',
              value === mode
                ? 'border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--fg)]'
                : 'border-[var(--line)] text-[var(--muted)] hover:text-[var(--fg)]')}>
            {tr(`hunt.match.${mode}`)}
          </button>
        </Tooltip>
      ))}
    </div>
  )
}

/** What the row shows for the paths: the combination made readable. */
function joinPaths(p: HuntPattern): string {
  return p.patterns.join(p.match === 'all' ? ' AND ' : ' OR ')
}

/** Request predicates are part of the hypothesis, not an implementation
 * detail. Keeping them beside the URL prevents a filtered endpoint rule from
 * looking like a broad claim about every request to that endpoint. */
function PatternConditions({ pattern, compact = false }: {
  pattern: HuntPattern
  compact?: boolean
}) {
  const tr = useT()
  const methods = pattern.request?.methods ?? []
  const agents = pattern.request?.user_agents ?? []
  if (!methods.length && !agents.length) return null
  return (
    <span className="mt-1 flex flex-wrap gap-1">
      {!!methods.length && (
        <Tag hint={tr('hunt.condition.hint')}>
          {compact
            ? methods.join('/')
            : `${tr('hunt.condition.method')}: ${methods.join(' / ')}`}
        </Tag>
      )}
      {!!agents.length && (
        <Tag hint={tr('hunt.condition.hint')}>
          {compact
            ? `${tr('hunt.condition.userAgent')} ×${agents.length}`
            : `${tr('hunt.condition.userAgent')}: ${agents.join(' / ')}`}
        </Tag>
      )}
    </span>
  )
}
