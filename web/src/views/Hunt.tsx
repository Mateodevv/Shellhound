// Hunt.tsx — die Muster-Jagd: hinterlegte Exploit-Pfade gegen den Log-Index.
//
// Die Gegenrichtung zu allem anderen im Werkzeug. Findings und Actors zeigen,
// was die MITGELIEFERTEN Regeln gefunden haben; hier bringt der Analyst sein
// eigenes Wissen ein — „diesen Pfad ruft nur auf, wer diesen Exploit fährt" —
// und das Werkzeug sagt, wer ihn abgerufen hat.
//
// DIE BIBLIOTHEK GEHÖRT DEM WORKSPACE, NICHT DEM FALL: einmal angelegt, steht
// ein Muster in jedem weiteren Fall bereit. Der Fall protokolliert nur, wonach
// in ihm gesucht wurde — auch erfolglos, denn „wir haben darauf geprüft, es
// war nichts" steht sonst nirgends.
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Box, ChevronDown, ChevronRight, Crosshair, Download, PencilLine, Play, Plus,
  Radar, Trash2, Upload,
} from 'lucide-react'
import {
  api, del, downloadUrl, patch, post, type HuntPattern, type HuntResult,
  type HuntRun,
} from '../api'
import { formatCount, formatDay } from '../format'
import {
  Button, Card, EmptyState, SeverityBadge, Tag,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { TraceWindow } from '../components/TraceWindow'
import type { ViewId } from '../App'

export function Hunt({ slug, gotoView }: { slug: string; gotoView: (v: ViewId) => void }) {
  const qc = useQueryClient()
  const [pattern, setPattern] = useState('')
  const [label, setLabel] = useState('')
  const [note, setNote] = useState('')
  const [importText, setImportText] = useState('')
  const [showImport, setShowImport] = useState(false)
  const [results, setResults] = useState<HuntResult[] | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const [error, setError] = useState('')

  const { data: lib } = useQuery({
    queryKey: ['patterns'],
    queryFn: () => api<{ patterns: HuntPattern[]; path: string }>('/api/patterns'),
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
    mutationFn: () => post('/api/patterns', { pattern, label, note }),
    onSuccess: () => { setPattern(''); setLabel(''); setNote(''); setError(''); refresh() },
    onError: (e: Error) => setError(e.message),
  })
  const bulk = useMutation({
    mutationFn: () => post<{ added: number; skipped: number; invalid: number }>(
      '/api/patterns', { text: importText }),
    onSuccess: (r) => {
      setImportText('')
      setShowImport(false)
      setError(r.invalid
        ? `${r.added} übernommen, ${r.skipped} schon bekannt, ${r.invalid} unbrauchbar.`
        : '')
      refresh()
    },
    onError: (e: Error) => setError(e.message),
  })
  const remove = useMutation({
    mutationFn: (id: string) => del(`/api/patterns/${id}`),
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
  const runByPattern = new Map((runs?.runs ?? []).map((r) => [r.pattern, r]))
  const shown = results ?? []

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title="Muster-Jagd"
          body="Hinterlegte URL-Pfade — typischerweise die Aufrufe, die zu einem bekannten Exploit gehören. Das Werkzeug sucht im Log-Index, wer sie abgerufen hat."
          hint="Die Muster gehören dem Workspace: einmal angelegt, stehen sie in jedem weiteren Fall bereit. Treffer werden zu Findings auf dem Client — mit 2xx beantwortet HIGH, reine Versuche LOW.">
          <h1 className="mr-2 text-lg font-bold">Muster-Jagd</h1>
        </Tooltip>
        <Button variant="primary" disabled={!patterns.length || run.isPending}
          onClick={() => run.mutate([])}>
          <Play size={14} />
          {run.isPending
            ? 'sucht…'
            : `Alle ${formatCount(patterns.length)} Muster laufen lassen`}
        </Button>
        <Button onClick={() => setShowImport(!showImport)}>
          <Upload size={14} /> Liste einlesen
        </Button>
        <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] font-medium hover:border-[var(--accent)]/60"
          href={downloadUrl('/api/patterns/export')}>
          <Download size={14} /> Bibliothek sichern
        </a>
        {run.data && (
          <span className="text-[12px] text-[var(--muted)]">
            {run.data.findings > 0
              ? <>{formatCount(run.data.findings)} Finding(s) geschrieben —{' '}
                <button className="cursor-pointer text-[var(--accent-text)] hover:underline"
                  onClick={() => gotoView('findings')}>in der Arbeitsliste ansehen</button></>
              : 'keine Treffer — im Fall protokolliert'}
          </span>
        )}
      </div>

      {/* ---- ein Muster anlegen ---- */}
      <Card className="flex flex-wrap items-end gap-2 px-4 py-3">
        <label className="flex min-w-72 flex-1 flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            URL-Muster
          </span>
          <input
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && pattern.trim()) add.mutate() }}
            placeholder="option=com_jce&task=plugin   ·   * ist Platzhalter"
            className="mono w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
        </label>
        <label className="flex w-56 flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            Name
          </span>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="JCE imgmanager RCE"
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
        </label>
        <label className="flex w-48 flex-col gap-1">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            Notiz
          </span>
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="CVE-2018-17057"
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
        </label>
        <Button variant="primary" disabled={!pattern.trim()} onClick={() => add.mutate()}>
          <Plus size={14} /> Hinterlegen
        </Button>
      </Card>

      {showImport && (
        <Card className="flex flex-col gap-2 px-4 py-3">
          <div className="text-[12px] text-[var(--muted)]">
            Eine Zeile je Muster, optional <span className="mono">Muster | Name | Notiz</span>.
            Zeilen mit <span className="mono">#</span> sind Kommentare. Eine gesicherte
            Bibliothek (JSON) wird ebenso erkannt — bekannte Muster werden übersprungen.
          </div>
          <textarea
            value={importText}
            onChange={(e) => setImportText(e.target.value)}
            rows={5}
            placeholder={'# aus dem Team-Repo\n/administrator/components/com_adsmanager/ | AdsManager LFI\nwp-content/plugins/revslider/temp/ | RevSlider Upload'}
            className="mono w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12px] outline-none focus:border-[var(--accent)]/70"
          />
          <div className="flex gap-2">
            <Button variant="primary" disabled={!importText.trim()}
              onClick={() => bulk.mutate()}>Einlesen</Button>
            <Button variant="ghost" onClick={() => setShowImport(false)}>Abbrechen</Button>
          </div>
        </Card>
      )}

      {error && (
        <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)]">
          {error}
        </div>
      )}

      {/* ---- die Bibliothek ---- */}
      <Card className="overflow-hidden">
        <div className="flex items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2">
          <Radar size={14} className="text-[var(--muted)]" />
          <span className="text-[12px] font-semibold">
            Bibliothek — {formatCount(patterns.length)} Muster
          </span>
          <Tooltip hint={`Gespeichert unter ${lib?.path ?? ''} — die Datei gehört zum Workspace, nicht zum Fall, und gilt deshalb für jeden Fall darin.`}>
            <span className="mono truncate text-[11px] text-[var(--muted)]">
              {lib?.path}
            </span>
          </Tooltip>
        </div>
        {patterns.map((p) => {
          const result = shown.find((r) => r.id === p.id)
          const last = runByPattern.get(p.pattern)
          if (editing === p.id) {
            return <PatternEditor key={p.id} slug={slug} entry={p}
              onDone={() => { setEditing(null); refresh() }} />
          }
          return (
            <div key={p.id}
              className="flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2 last:border-0 hover:bg-[var(--panel-2)]">
              <div className="min-w-0 flex-1">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="truncate text-[13px] font-medium">
                    {p.label || <span className="mono">{p.pattern}</span>}
                  </span>
                  {p.note && <Tag>{p.note}</Tag>}
                </div>
                <div className="mono truncate text-[11px] text-[var(--muted)]" title={p.pattern}>
                  {p.pattern}
                </div>
              </div>
              {last && (
                <Tooltip title={`zuletzt gesucht: ${last.ran_at.replace('T', ' ')}`}
                  hint={last.hits
                    ? `${formatCount(last.hits)} Treffer bei ${formatCount(last.clients)} Client(s), davon ${formatCount(last.ok_hits)}× mit 2xx beantwortet.`
                    : 'In diesem Fall kein Treffer — das ist im Fall protokolliert und damit belegbar.'}>
                  <span className={clsx('shrink-0 text-[11px] tabular',
                    last.ok_hits ? 'text-[var(--sev-high)]'
                      : last.hits ? 'text-[var(--sev-low)]' : 'text-[var(--muted)]')}>
                    {last.hits ? `${formatCount(last.hits)} Treffer` : 'kein Treffer'}
                  </span>
                </Tooltip>
              )}
              <Button variant="ghost" onClick={() => run.mutate([p.id])}>
                <Play size={13} /> Suchen
              </Button>
              <Tooltip hint="Muster, Name oder Notiz ändern — gilt danach für alle Fälle.">
                <button
                  className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel)] hover:text-[var(--accent)]"
                  onClick={() => setEditing(p.id)}>
                  <PencilLine size={14} />
                </button>
              </Tooltip>
              <Tooltip hint="Entfernt das Muster aus der Bibliothek — auch für künftige Fälle. Bereits geschriebene Findings bleiben.">
                <button
                  className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--danger-soft)] hover:text-[var(--danger-text)]"
                  onClick={() => remove.mutate(p.id)}>
                  <Trash2 size={14} />
                </button>
              </Tooltip>
              {result && <ResultBadge result={result} />}
            </div>
          )
        })}
        {!patterns.length && (
          <EmptyState icon={<Radar size={36} />} title="Noch kein Muster hinterlegt"
            sub="Trage oben einen URL-Pfad ein, den du aus einem Exploit kennst — etwa den Aufruf, mit dem eine bekannte Lücke ausgelöst wird. Die Bibliothek gehört zum Workspace und steht danach in jedem Fall bereit." />
        )}
      </Card>

      {/* ---- die Ergebnisse ---- */}
      {shown.map((r) => (
        <ResultCard key={r.id} slug={slug} result={r} onTrace={setTraceIps} />
      ))}

      <TraceWindow slug={slug} ips={traceIps} onClose={() => setTraceIps(null)} />
    </div>
  )
}

/** Ein Muster nachbessern. Änderungen gelten für ALLE Fälle — die Bibliothek
 *  gehört dem Workspace, und genau das steht auch am Knopf. */
function PatternEditor({ slug, entry, onDone }: {
  slug: string
  entry: HuntPattern
  onDone: () => void
}) {
  const [pattern, setPattern] = useState(entry.pattern)
  const [label, setLabel] = useState(entry.label)
  const [note, setNote] = useState(entry.note)
  const [error, setError] = useState('')
  void slug

  const save = useMutation({
    mutationFn: () => patch(`/api/patterns/${entry.id}`, { pattern, label, note }),
    onSuccess: onDone,
    onError: (e: Error) => setError(e.message),
  })

  return (
    <div className="flex flex-col gap-2 border-b border-[var(--line-soft)] bg-[var(--panel-2)] px-4 py-3 last:border-0">
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex min-w-64 flex-1 flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            URL-Muster
          </span>
          <input value={pattern} onChange={(e) => setPattern(e.target.value)}
            className="mono w-full rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
        </label>
        <label className="flex w-48 flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            Name
          </span>
          <input value={label} onChange={(e) => setLabel(e.target.value)}
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
        </label>
        <label className="flex w-40 flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            Notiz
          </span>
          <input value={note} onChange={(e) => setNote(e.target.value)}
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70" />
        </label>
        <Button variant="primary" disabled={!pattern.trim() || save.isPending}
          onClick={() => save.mutate()}>
          Speichern
        </Button>
        <Button variant="ghost" onClick={onDone}>Abbrechen</Button>
      </div>
      <div className="text-[11px] text-[var(--muted)]">
        Die Änderung gilt für alle Fälle. Bereits geschriebene Findings bleiben
        stehen — sie halten fest, was zum Zeitpunkt der Suche galt.
      </div>
      {error && <div className="text-[12px] text-[var(--danger-text)]">{error}</div>}
    </div>
  )
}

function ResultBadge({ result }: { result: HuntResult }) {
  if (!result.hits) {
    return <Tag>kein Treffer</Tag>
  }
  return (
    <Tag tone={result.ok_hits ? 'danger' : 'warn'}>
      {formatCount(result.clients.length)} Client{result.clients.length === 1 ? '' : 's'}
    </Tag>
  )
}

/** Was ein Muster gefunden hat. Die getroffenen URIs stehen mit dabei: ein
 *  Muster, das zu weit greift, sieht man nur, wenn man sieht, WAS es traf. */
function ResultCard({ slug, result, onTrace }: {
  slug: string
  result: HuntResult
  onTrace: (ips: string[]) => void
}) {
  const qc = useQueryClient()
  const [showUris, setShowUris] = useState(false)

  // Die Herkunft nennt das Muster: "hat den Exploit-Pfad abgerufen" ist die
  // Aussage, die im Bericht zählt — nicht "aus einer Liste eingesammelt".
  const collect = useMutation({
    mutationFn: (ips: string[]) => post<{ added: number }>(
      `/api/cases/${slug}/actors/collect`,
      { ips, origin: `Muster-Treffer: ${result.label || result.pattern}` }),
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
            {result.label || result.pattern}
          </div>
          <div className="mono truncate text-[11px] text-[var(--muted)]">{result.pattern}</div>
        </div>
        <span className="text-[12px] text-[var(--muted)] tabular">
          {formatCount(result.hits)} Anfragen · {formatCount(result.ok_hits)}× 2xx ·{' '}
          {formatCount(result.clients.length)} Client(s)
        </span>
        {result.clients.length > 1 && (
          <Button onClick={() => onTrace(result.clients.map((c) => c.ip))}>
            <Crosshair size={13} /> alle tracen
          </Button>
        )}
        <Tooltip hint="Übernimmt alle hier gelisteten Adressen als Indikatoren — mit dem Muster als Herkunft, damit im Bericht steht, WARUM sie drinstehen.">
          <Button variant="primary" disabled={collect.isPending}
            onClick={() => collect.mutate(result.clients.map((c) => c.ip))}>
            <Box size={13} />
            {collect.data
              ? `${formatCount(collect.data.added)} übernommen`
              : `Alle ${formatCount(result.clients.length)} in die IOC Box`}
          </Button>
        </Tooltip>
      </div>

      {result.truncated && (
        <div className="border-b border-[var(--line)] bg-[rgba(250,178,25,0.10)] px-4 py-1.5 text-[11.5px] text-[var(--sev-low)]">
          Das Muster trifft sehr viele verschiedene URLs — die Auswertung wurde
          begrenzt. Ein engeres Muster liefert ein belastbareres Ergebnis.
        </div>
      )}

      <table className="w-full border-collapse text-[13px]">
        <thead>
          <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
            <th className="px-4 py-2">Client</th>
            <th className="px-2 py-2 text-right">Anfragen</th>
            <th className="px-2 py-2 text-right">davon 2xx</th>
            <th className="px-2 py-2">Zeitraum</th>
            <th className="w-28 px-4 py-2" />
          </tr>
        </thead>
        <tbody>
          {result.clients.map((c) => (
            <tr key={c.ip}
              className="group border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]">
              <td className="px-4 py-1.5">
                <span className="mono font-medium">{c.ip}</span>
                {c.ok_hits > 0 && (
                  <Tag tone="danger"
                    hint="Der Server hat auf diesen Aufruf mit Erfolg geantwortet — nicht nur ein Versuch ins Leere.">
                    erfolgreich
                  </Tag>
                )}
              </td>
              <td className="px-2 py-1.5 text-right tabular">{formatCount(c.hits)}</td>
              <td className={clsx('px-2 py-1.5 text-right tabular',
                c.ok_hits ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
                {formatCount(c.ok_hits)}
              </td>
              <td className="px-2 py-1.5 text-[12px] text-[var(--muted)]">
                {formatDay(c.first_epoch, c.tz)} → {formatDay(c.last_epoch, c.tz)}
              </td>
              <td className="px-4 py-1.5 text-right">
                <Button variant="ghost" className="opacity-0 group-hover:opacity-100"
                  onClick={() => onTrace([c.ip])}>
                  <Crosshair size={13} /> Trace
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <button onClick={() => setShowUris(!showUris)}
        className="flex w-full cursor-pointer items-center gap-2 border-t border-[var(--line)] px-4 py-1.5 text-[11.5px] text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]">
        {showUris ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        {formatCount(result.uris.length)} getroffene URL{result.uris.length === 1 ? '' : 's'}
        <span className="opacity-70">— prüfen, ob das Muster passt</span>
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
