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
import { plural, useT } from '../i18n'
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Box, ChevronDown, ChevronRight, ChevronUp, ChevronsUpDown, Crosshair,
  Download, HelpCircle, PencilLine, Play, Plus, Radar, ToggleLeft,
  ToggleRight, Trash2, Upload,
} from 'lucide-react'
import {
  api, del, downloadUrl, patch, post, type HuntClient, type HuntPattern,
  type HuntResult, type HuntRun,
} from '../api'
import { formatCount, formatLogTime, formatSpan } from '../format'
import {
  Button, Card, EmptyState, SeverityBadge, Tag,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { IpFlag } from '../components/IpFlag'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import type { ViewId } from '../App'

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
  // Open while one is still assembling; as the library grows one collapses
  // it and works with the results.
  const [libOpen, setLibOpen] = useState(true)

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
      setDescription(''); setError(''); refresh()
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
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['actors'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      qc.invalidateQueries({ queryKey: ['hunt-runs'] })
    },
  })

  const patterns = lib?.patterns ?? []
  // Only what is switched on gets run, so that is what the button counts.
  const runnable = patterns.filter((p) => p.enabled)
  const runByPattern = new Map((runs?.runs ?? []).map((r) => [r.pattern, r]))
  const shown = results ?? []

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title={tr('nav.hunt')}
          body={tr('hunt.title.body')}
          hint={tr('hunt.title.hint')}>
          <h1 className="mr-2 text-lg font-bold">{tr('nav.hunt')}</h1>
        </Tooltip>
        <Button variant="primary" disabled={!runnable.length || run.isPending}
          onClick={() => run.mutate([])}>
          <Play size={14} />
          {run.isPending
            ? tr('hunt.searching')
            : tr('hunt.runAll', { n: formatCount(runnable.length) })}
        </Button>
        <Button onClick={() => setShowImport(!showImport)}>
          <Upload size={14} /> {tr('hunt.import')}
        </Button>
        <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] font-medium hover:border-[var(--accent)]/60"
          href={downloadUrl('/api/patterns/export')}>
          <Download size={14} /> {tr('hunt.backup')}
        </a>
        {run.data && (
          <span className="text-[12px] text-[var(--muted)]">
            {run.data.findings > 0
              ? <>{tr('hunt.findingsWritten', { n: formatCount(run.data.findings) })} —{' '}
                <button className="cursor-pointer text-[var(--accent-text)] hover:underline"
                  onClick={() => gotoView('findings')}>{tr('hunt.seeInList')}</button></>
              : tr('hunt.noHits')}
          </span>
        )}
      </div>

      {/* ---- add a pattern ---- */}
      <Card className="flex flex-wrap items-end gap-2 px-4 py-3">
        <div className="flex basis-full flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('hunt.field.pattern')}
          </span>
          <PathList paths={paths} onChange={setPaths}
            onSubmit={() => { if (paths.some((p) => p.trim())) add.mutate() }} />
          {paths.filter((p) => p.trim()).length > 1 && (
            <MatchPicker value={match} onChange={setMatch} />
          )}
        </div>
        <label className="flex w-56 flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('hunt.field.name')}
          </span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Joomla JCE editor RCE"
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
        </label>
        <label className="flex w-48 flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('hunt.field.cve')}
          </span>
          <input
            value={cve}
            onChange={(e) => setCve(e.target.value)}
            placeholder="CVE-2026-48907"
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
        </label>
        <label className="flex min-w-72 flex-1 basis-full flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('hunt.field.description')}
          </span>
          {/* Its own row: this is a sentence, not a tag. What a hit here
              proves is the thing nobody remembers six months later, and the
              note field beside the name is too short to hold it. */}
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={2}
            placeholder={tr('hunt.field.description.placeholder')}
            className="w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
        </label>
        <Button variant="primary"
          disabled={!paths.some((p) => p.trim())} onClick={() => add.mutate()}>
          <Plus size={14} /> {tr('hunt.store')}
        </Button>
      </Card>

      {showImport && (
        <Card className="flex flex-col gap-2 px-4 py-3">
          <div className="text-[12px] text-[var(--muted)]">
            {tr('hunt.import.a')} <span className="mono">pattern | name | note</span>.{' '}
            {tr('hunt.import.b')} <span className="mono">#</span> {tr('hunt.import.c')}
          </div>
          <textarea
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            rows={5}
            placeholder={`# ${tr('hunt.import.example')}\n/administrator/components/com_adsmanager/ | AdsManager LFI\nwp-content/plugins/revslider/temp/ | RevSlider Upload`}
            className="mono w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12px] outline-none focus:border-[var(--accent)]/70"
          />
          <div className="flex gap-2">
            <Button variant="primary" disabled={!importText.trim()}
              onClick={() => bulk.mutate()}>{tr('hunt.read')}</Button>
            <Button variant="ghost" onClick={() => setShowImport(false)}>{tr('common.cancel')}</Button>
          </div>
        </Card>
      )}

      {error && (
        <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)]">
          {error}
        </div>
      )}

      {/* ---- the library ----
          Collapsible, because it grows with every case: whoever has
          collected twenty patterns wants to see the results while assessing,
          not scroll past the list they came from first. */}
      <Card className="overflow-hidden">
        <button onClick={() => setLibOpen(!libOpen)}
          className="flex w-full cursor-pointer items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2 text-left transition-colors hover:bg-[var(--panel)]">
          {libOpen ? <ChevronDown size={14} className="shrink-0 text-[var(--muted)]" />
                   : <ChevronRight size={14} className="shrink-0 text-[var(--muted)]" />}
          <Radar size={14} className="shrink-0 text-[var(--muted)]" />
          <span className="shrink-0 text-[12px] font-semibold">
            {tr('hunt.library', { n: formatCount(runnable.length) })}
          </span>
          <InfoDot
            title={tr('hunt.library.title')}
            body={tr('hunt.library.body', { path: lib?.path ?? '—' })}
            hint={tr('hunt.library.hint')} />
          <span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]">
            {lib?.path}
          </span>
          <span className="shrink-0 text-[11px] text-[var(--muted)]">
            {libOpen ? tr('common.collapse') : tr('common.expand')}
          </span>
        </button>
        {libOpen && patterns.map((p) => {
          const result = shown.find((r) => r.id === p.id)
          const last = runByPattern.get(joinPaths(p))
          if (editing === p.id) {
            return <PatternEditor key={p.id} slug={slug} entry={p}
              onDone={() => { setEditing(null); refresh() }} />
          }
          const shipped = p.source === 'bundled'
          return (
            <div key={p.id}
              className={clsx('flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2 last:border-0 hover:bg-[var(--panel-2)]',
                !p.enabled && 'opacity-45')}>
              <div className="min-w-0 flex-1">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="truncate text-[13px] font-medium">
                    {p.name || <span className="mono">{p.patterns[0]}</span>}
                  </span>
                  {/* Where a pattern came from is part of what a hit means:
                      one this version ships can be checked by whoever reads
                      the report, one written here cannot. */}
                  {shipped && (
                    <Tag hint={p.description || tr('hunt.bundled.hint')}>
                      {tr('hunt.bundled')}
                    </Tag>
                  )}
                  {p.cve && <Tag>{p.cve}</Tag>}
                  {p.patterns.length > 1 && (
                    <Tag tone={p.match === 'all' ? 'accent' : undefined}
                      hint={tr(`hunt.match.${p.match}.hint`)}>
                      {tr(`hunt.match.${p.match}`)}
                    </Tag>
                  )}
                </div>
                <div className="mono truncate text-[11px] text-[var(--muted)]"
                  title={p.patterns.join('\n')}>
                  {joinPaths(p)}
                </div>
                {/* Shown for both halves. What a hit proves is the thing the
                    analyst wrote it down for, and it is no use hidden behind
                    a hover on a tag that only shipped patterns carry. */}
                {p.description && (
                  <div className="mt-0.5 line-clamp-2 text-[11.5px] text-[var(--muted)]"
                    title={p.description}>
                    {p.description}
                  </div>
                )}
              </div>
              {last && (
                <Tooltip title={tr('hunt.lastRun', { at: last.ran_at.replace('T', ' ') })}
                  hint={last.hits
                    ? tr('hunt.lastRun.hint', {
                        hits: formatCount(last.hits), clients: formatCount(last.clients),
                        ok: formatCount(last.ok_clients), okHits: formatCount(last.ok_hits),
                        uris: formatCount(last.uris),
                        from: formatLogTime(last.first_epoch, last.tz),
                        to: formatLogTime(last.last_epoch, last.tz),
                        span: formatSpan(last.first_epoch, last.last_epoch),
                      })
                    : tr('hunt.lastRun.none')}>
                  <span className={clsx('shrink-0 text-[11px] tabular',
                    last.ok_hits ? 'text-[var(--sev-high)]'
                      : last.hits ? 'text-[var(--sev-low)]' : 'text-[var(--muted)]')}>
                    {last.hits ? tr('hunt.hits', { n: formatCount(last.hits) }) : tr('hunt.noHit')}
                  </span>
                </Tooltip>
              )}
              {p.enabled && (
                <Button variant="ghost" onClick={() => run.mutate([p.id])}>
                  <Play size={13} /> {tr('hunt.search')}
                </Button>
              )}
              {/* A bundled pattern is not editable. Changing it while it kept
                  its id and its CVE would make the same identifier mean two
                  things on two machines. */}
              {!shipped && (
                <Tooltip hint={tr('hunt.edit.hint')}>
                  <button
                    aria-label={tr('hunt.edit.hint')}
                    className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel)] hover:text-[var(--accent)]"
                    onClick={() => setEditing(p.id)}>
                    <PencilLine size={14} />
                  </button>
                </Tooltip>
              )}
              {shipped ? (
                <Tooltip hint={p.enabled ? tr('hunt.disable.hint')
                                         : tr('hunt.enable.hint')}>
                  <button
                    aria-label={p.enabled ? tr('hunt.disable.hint') : tr('hunt.enable.hint')}
                    className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel)] hover:text-[var(--accent)]"
                    onClick={() => toggle.mutate({ id: p.id, enabled: !p.enabled })}>
                    {p.enabled ? <ToggleRight size={16} className="text-[var(--accent)]" />
                               : <ToggleLeft size={16} />}
                  </button>
                </Tooltip>
              ) : (
                <Tooltip hint={tr('hunt.delete.hint')}>
                  <button
                    aria-label={tr('hunt.delete.hint')}
                    className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--danger-soft)] hover:text-[var(--danger-text)]"
                    onClick={() => remove.mutate(p.id)}>
                    <Trash2 size={14} />
                  </button>
                </Tooltip>
              )}
              {result && <ResultBadge result={result} />}
            </div>
          )
        })}
        {libOpen && !patterns.length && (
          <EmptyState icon={<Radar size={36} />} title={tr('hunt.empty.title')}
            sub={tr('hunt.empty.sub')} />
        )}
      </Card>

      {/* ---- the results ---- */}
      {shown.map((r) => (
        <ResultCard key={r.id} slug={slug} result={r}
          onTrace={(ips) => {
            setTraceMarks({ exact: r.uris.map((u) => u.uri),
                            reason: tr('hunt.traceReason') })
            setTraceIps(ips)
          }} />
      ))}

      <TraceWindow slug={slug} ips={traceIps} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
    </div>
  )
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

function ResultBadge({ result }: { result: HuntResult }) {
  const tr = useT()
  if (!result.hits) {
    return <Tag>{tr('hunt.noHit')}</Tag>
  }
  return (
    <Tag tone={result.ok_hits ? 'danger' : 'warn'}>
      {plural(tr, result.clients.length, 'hunt.client.one', 'hunt.client.many',
              { n: formatCount(result.clients.length) })}
    </Tag>
  )
}

/** The key figures of a search in one block -- what travels into the report.
 *
 *  The decisive number is not how often someone knocked, but how many
 *  addresses got through: 300 requests from 40 addresses of which exactly
 *  one got a 2xx is a completely different finding from 300 requests with
 *  300 successes. And the span separates the one campaign (minutes) from the
 *  background noise that has been running for months. */
function HuntSummary({ result }: { result: HuntResult }) {
  const tr = useT()
  const durch = result.ok_clients > 0
  return (
    <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b border-[var(--line)] px-4 py-2.5">
      {/* The finding, in the size it deserves. */}
      <Tooltip hint={tr('hunt.gotThrough.hint')}>
        <div className="flex items-baseline gap-1.5">
          <span className={clsx('text-[19px] font-bold leading-none tabular',
            durch ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
            {formatCount(result.ok_clients)}
          </span>
          {/* The noun follows the total, the verb the first number:
              "1 of 2 addresses GOT through". */}
          <span className="flex items-center gap-1 text-[13px] text-[var(--muted)]">
            {plural(tr, result.clients_total, 'hunt.gotThrough.one', 'hunt.gotThrough.many',
                    { n: formatCount(result.clients_total) })}
            {/* Visible, otherwise nobody hovers over a key figure: the
                remaining facts of the line explain themselves on hover. */}
            <HelpCircle size={11} className="shrink-0 opacity-50" />
          </span>
        </div>
      </Tooltip>

      {/* Everything else is evidence for it and stands next to it as a
          running line -- the way one writes it into the report. */}
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
  const [showUris, setShowUris] = useState(false)
  // The default as delivered by the server: successes first. That is the
  // order one wants to read the list in to begin with.
  const [sort, setSort] = useState<Sort>({ col: 'ok_hits', desc: true })

  const sorted = useMemo(() => {
    const dir = sort.desc ? -1 : 1
    return [...result.clients].sort((a, b) => {
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
  }, [result.clients, sort])

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

  if (!result.hits) return null
  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2.5">
        <SeverityBadge severity={result.ok_hits ? 0 : 2} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[13.5px] font-semibold">
            {result.name || result.pattern}
          </div>
          <div className="mono truncate text-[11px] text-[var(--muted)]">{result.pattern}</div>
        </div>
        {result.clients.length > 1 && (
          <Button onClick={() => onTrace(result.clients.map((c) => c.ip))}>
            <Crosshair size={13} /> {tr('hunt.traceAll')}
          </Button>
        )}
        <Tooltip hint={tr('hunt.collectAll.hint')}>
          <Button variant="primary" disabled={collect.isPending}
            onClick={() => collect.mutate(result.clients.map((c) => c.ip))}>
            <Box size={13} /> {tr('hunt.collectAll', { n: formatCount(result.clients.length) })}
          </Button>
        </Tooltip>
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

      <table className="w-full border-collapse text-[13px]">
        <thead>
          <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
            <SortHead className="px-4 py-2" col="ip" sort={sort} onSort={setSort}>
              Client
            </SortHead>
            <SortHead className="px-2 py-2 text-right" col="hits" sort={sort} onSort={setSort}>
              {tr('hunt.requests')}
            </SortHead>
            <SortHead className="px-2 py-2 text-right" col="ok_hits" sort={sort} onSort={setSort}>
              {tr('hunt.ofWhich2xx')}
            </SortHead>
            <SortHead className="px-2 py-2" col="first" sort={sort} onSort={setSort}>
              {tr('hunt.firstHit')}
            </SortHead>
            <SortHead className="px-2 py-2" col="last" sort={sort} onSort={setSort}>
              {tr('hunt.lastHit')}
            </SortHead>
            <SortHead className="px-2 py-2 text-right" col="dauer" sort={sort} onSort={setSort}>
              {tr('hunt.duration')} <InfoDot body={tr('field.duration')} hint={tr('field.duration_why')} />
            </SortHead>
            <th className="w-28 px-4 py-2" />
          </tr>
        </thead>
        <tbody>
          {sorted.map((c) => (
            <tr key={c.ip}
              className="group border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]">
              <td className="px-4 py-1.5">
                <span className="inline-flex items-center gap-1.5">
                  <IpFlag ip={c.ip} />
                  <span className="mono font-medium">{c.ip}</span>
                </span>
                {c.ok_hits > 0 && (
                  <Tag tone="danger"
                    hint={tr('hunt.successful.hint')}>
                    {tr('hunt.successful')}
                  </Tag>
                )}
              </td>
              <td className="px-2 py-1.5 text-right tabular">{formatCount(c.hits)}</td>
              <td className={clsx('px-2 py-1.5 text-right tabular',
                c.ok_hits ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
                {formatCount(c.ok_hits)}
              </td>
              {/* To the second: on a pattern hit the time of day is half
                  the statement -- it says whether the requests came in one
                  burst or spread over weeks. */}
              <td className="mono px-2 py-1.5 text-[12px] tabular text-[var(--muted)]">
                {formatLogTime(c.first_epoch, c.tz)}
              </td>
              <td className="mono px-2 py-1.5 text-[12px] tabular text-[var(--muted)]">
                {formatLogTime(c.last_epoch, c.tz)}
              </td>
              {/* The length of the attack: 40 requests in two minutes are a
                  tool, 40 across three weeks are something else. */}
              <td className="mono px-2 py-1.5 text-right text-[12px] tabular">
                {formatSpan(c.first_epoch, c.last_epoch)}
              </td>
              <td className="px-4 py-1.5 text-right">
                <div className="flex items-center justify-end gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
                  <Tooltip hint={tr('hunt.collectOne.hint')}>
                    <Button variant="ghost" disabled={collect.isPending}
                      onClick={() => collect.mutate([c.ip])}>
                      <Box size={13} /> IOC
                    </Button>
                  </Tooltip>
                  <Button variant="ghost" onClick={() => onTrace([c.ip])}>
                    <Crosshair size={13} /> Trace
                  </Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <button onClick={() => setShowUris(!showUris)}
        className="flex w-full cursor-pointer items-center gap-2 border-t border-[var(--line)] px-4 py-1.5 text-[11.5px] text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]">
        {showUris ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        {plural(tr, result.uri_total, 'hunt.urlsHit.one', 'hunt.urlsHit.many',
                { n: formatCount(result.uri_total) })}
        <span className="opacity-70">
          {result.uri_total > result.uris.length
            ? `— ${tr('hunt.topUrls', { n: formatCount(result.uris.length) })}`
            : `— ${tr('hunt.checkPattern')}`}
        </span>
      </button>
      {showUris && (
        <div className="border-t border-[var(--line)]">
          {result.uris.map((u) => (
            <div key={u.uri}
              className="flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-1 text-[11.5px] last:border-0">
              <span className="mono min-w-0 flex-1 truncate" title={u.uri}>{u.uri}</span>
              <span className="shrink-0 tabular text-[var(--muted)]">
                {formatCount(u.hits)}× · {formatCount(u.ok_hits)}× 2xx
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
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
