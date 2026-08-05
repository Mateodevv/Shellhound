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
import { useT } from '../i18n'
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Box, ChevronDown, ChevronRight, ChevronUp, ChevronsUpDown, Crosshair,
  Download, HelpCircle, PencilLine, Play, Plus, Radar, Trash2, Upload,
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
  const [pattern, setPattern] = useState('')
  const [label, setLabel] = useState('')
  const [note, setNote] = useState('')
  const [importText, setImportText] = useState('')
  const [showImport, setShowImport] = useState(false)
  const [results, setResults] = useState<HuntResult[] | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // Die vom Muster getroffenen URLs — im Trace rot markiert, damit man den
  // Aufruf, um den es geht, nicht zwischen tausend anderen sucht.
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [editing, setEditing] = useState<string | null>(null)
  const [error, setError] = useState('')
  // Offen, solange man noch am Zusammenstellen ist; mit wachsender
  // Bibliothek klappt man sie zu und arbeitet mit den Ergebnissen.
  const [libOpen, setLibOpen] = useState(true)

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
          body={tr('hunt.title.body')}
          hint={tr('hunt.title.hint')}>
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
                  onClick={() => gotoView('findings')}>{tr('hunt.seeInList')}</button></>
              : tr('hunt.noHits')}
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

      {/* ---- die Bibliothek ----
          Zuklappbar, weil sie mit jedem Fall wächst: wer zwanzig Muster
          gesammelt hat, will beim Auswerten die Ergebnisse sehen und nicht
          erst an der Liste vorbeiscrollen, aus der sie stammen. */}
      <Card className="overflow-hidden">
        <button onClick={() => setLibOpen(!libOpen)}
          className="flex w-full cursor-pointer items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2 text-left transition-colors hover:bg-[var(--panel)]">
          {libOpen ? <ChevronDown size={14} className="shrink-0 text-[var(--muted)]" />
                   : <ChevronRight size={14} className="shrink-0 text-[var(--muted)]" />}
          <Radar size={14} className="shrink-0 text-[var(--muted)]" />
          <span className="shrink-0 text-[12px] font-semibold">
            Bibliothek — {formatCount(patterns.length)} Muster
          </span>
          <InfoDot
            title="Die Muster-Bibliothek"
            body={`Gespeichert unter ${lib?.path ?? '—'}.`}
            hint="Die Datei gehört zum WORKSPACE, nicht zum Fall: einmal angelegt, steht ein Muster in jedem weiteren Fall darin bereit. Der einzelne Fall protokolliert nur, wonach in ihm gesucht wurde — auch erfolglos." />
          <span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]">
            {lib?.path}
          </span>
          <span className="shrink-0 text-[11px] text-[var(--muted)]">
            {libOpen ? 'zuklappen' : 'aufklappen'}
          </span>
        </button>
        {libOpen && patterns.map((p) => {
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
                    ? `${formatCount(last.hits)} Treffer bei ${formatCount(last.clients)} Client(s), davon ${formatCount(last.ok_clients)} mit 2xx beantwortet (${formatCount(last.ok_hits)} Anfragen). Getroffene URLs: ${formatCount(last.uris)}. Zeitraum: ${formatLogTime(last.first_epoch, last.tz)} → ${formatLogTime(last.last_epoch, last.tz)} (${formatSpan(last.first_epoch, last.last_epoch)}).`
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
              <Tooltip hint={tr('hunt.edit.hint')}>
                <button
                  className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel)] hover:text-[var(--accent)]"
                  onClick={() => setEditing(p.id)}>
                  <PencilLine size={14} />
                </button>
              </Tooltip>
              <Tooltip hint={tr('hunt.delete.hint')}>
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
        {libOpen && !patterns.length && (
          <EmptyState icon={<Radar size={36} />} title={tr('hunt.empty.title')}
            sub={tr('hunt.empty.sub')} />
        )}
      </Card>

      {/* ---- die Ergebnisse ---- */}
      {shown.map((r) => (
        <ResultCard key={r.id} slug={slug} result={r}
          onTrace={(ips) => {
            setTraceMarks({ exact: r.uris.map((u) => u.uri),
                            reason: 'dieser Aufruf passt auf das Muster' })
            setTraceIps(ips)
          }} />
      ))}

      <TraceWindow slug={slug} ips={traceIps} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
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

/** Die Kennzahlen einer Suche in einem Block — was in den Bericht wandert.
 *
 *  Die entscheidende Zahl ist nicht, wie oft geklopft wurde, sondern wie
 *  viele Adressen durchkamen: 300 Anfragen von 40 Adressen, von denen genau
 *  eine eine 2xx bekam, ist ein völlig anderer Befund als 300 Anfragen mit
 *  300 Erfolgen. Und die Spanne trennt die eine Kampagne (Minuten) vom
 *  Hintergrundrauschen, das seit Monaten mitläuft. */
function HuntSummary({ result }: { result: HuntResult }) {
  const tr = useT()
  const durch = result.ok_clients > 0
  return (
    <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 border-b border-[var(--line)] px-4 py-2.5">
      {/* Der Befund, in der Größe, die er verdient. */}
      <Tooltip
        hint="Bei wie vielen der getroffenen Adressen der Server mit 2xx geantwortet hat. Ein Versuch ins Leere ist kein Zugriff — deshalb steht diese Zahl hier und nicht die Zahl der Anfragen.">
        <div className="flex items-baseline gap-1.5">
          <span className={clsx('text-[19px] font-bold leading-none tabular',
            durch ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
            {formatCount(result.ok_clients)}
          </span>
          {/* Das Zahlwort richtet sich nach der Gesamtzahl, das Verb nach
              der ersten: „1 von 2 Adressen KAM durch". */}
          <span className="flex items-center gap-1 text-[13px] text-[var(--muted)]">
            von {formatCount(result.clients_total)}{' '}
            {result.clients_total === 1 ? 'Adresse' : tr('hunt.addresses')}{' '}
            {result.ok_clients === 1 ? 'kam' : 'kamen'} durch
            {/* Sichtbar, sonst hovert niemand über einer Kennzahl: die
                übrigen Angaben der Zeile erklären sich beim Überfahren. */}
            <HelpCircle size={11} className="shrink-0 opacity-50" />
          </span>
        </div>
      </Tooltip>

      {/* Alles Weitere ist Beleg dazu und steht als Fließzeile daneben —
          so, wie man es in den Bericht schreibt. */}
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 text-[12px] text-[var(--muted)]">
        <Tooltip hint="Alle Anfragen auf die getroffenen URLs, und wie viele davon erfolgreich beantwortet wurden.">
          <span>
            <span className="mono tabular text-[var(--fg)]">{formatCount(result.hits)}</span> Anfragen,
            davon <span className={clsx('mono tabular',
              result.ok_hits ? 'text-[var(--sev-high)]' : '')}>
              {formatCount(result.ok_hits)}×
            </span> mit 2xx
          </span>
        </Tooltip>
        <span className="opacity-40">·</span>
        <Tooltip hint="Zeiten aus dem Log, in dessen eigener Zeitzone — nicht die Uhr dieses Rechners. Minuten sprechen für einen einzelnen Zugriff, Monate eher für Hintergrundrauschen.">
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
        <Tooltip hint="Wie viele verschiedene URLs das Muster überhaupt getroffen hat. Eine hohe Zahl heißt meist: das Muster greift zu weit.">
          <span>
            <span className="mono tabular text-[var(--fg)]">
              {formatCount(result.uri_total)}
            </span> URL{result.uri_total === 1 ? '' : 's'}
          </span>
        </Tooltip>
      </div>
    </div>
  )
}

type SortCol = 'ip' | 'hits' | 'ok_hits' | 'first' | 'last' | 'dauer'
type Sort = { col: SortCol; desc: boolean }

/** Eine Adresse als Zahl, damit 2 vor 10 steht. IPv6 fällt auf den
 *  Textvergleich zurück — dort ist die Reihenfolge ohnehin nur eine
 *  Gruppierung, keine Aussage. */
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

/** Was ein Muster gefunden hat. Die getroffenen URIs stehen mit dabei: ein
 *  Muster, das zu weit greift, sieht man nur, wenn man sieht, WAS es traf. */
function ResultCard({ slug, result, onTrace }: {
  slug: string
  result: HuntResult
  onTrace: (ips: string[]) => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const [showUris, setShowUris] = useState(false)
  // Voreinstellung wie vom Server geliefert: Erfolge zuerst. Das ist die
  // Reihenfolge, in der man die Liste zuerst lesen will.
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
      // Gleichstand bricht nach Anfragen, sonst springen Zeilen bei jedem
      // Neuzeichnen -- 40 Adressen mit je einem Treffer sind keine Seltenheit.
      return d || b.hits - a.hits
    })
  }, [result.clients, sort])

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
        {result.clients.length > 1 && (
          <Button onClick={() => onTrace(result.clients.map((c) => c.ip))}>
            <Crosshair size={13} /> alle tracen
          </Button>
        )}
        <Tooltip hint={tr('hunt.collectAll.hint')}>
          <Button variant="primary" disabled={collect.isPending}
            onClick={() => collect.mutate(result.clients.map((c) => c.ip))}>
            <Box size={13} /> Alle {formatCount(result.clients.length)} in die IOC Box
          </Button>
        </Tooltip>
      </div>

      <HuntSummary result={result} />

      {collect.data && (
        <div className="border-b border-[var(--line)] bg-[rgba(12,163,12,0.08)] px-4 py-1.5 text-[12px] text-[var(--ok)] animate-fade-up">
          {formatCount(collect.data.added)} Adresse(n) in die IOC Box übernommen —
          Herkunft: „Muster-Treffer: {result.label || result.pattern}"
        </div>
      )}

      {result.truncated && (
        <div className="border-b border-[var(--line)] bg-[rgba(250,178,25,0.10)] px-4 py-1.5 text-[11.5px] text-[var(--sev-low)]">
          Das Muster trifft sehr viele verschiedene URLs — die Auswertung wurde
          begrenzt. Ein engeres Muster liefert ein belastbareres Ergebnis.
        </div>
      )}

      <table className="w-full border-collapse text-[13px]">
        <thead>
          <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
            <SortHead className="px-4 py-2" col="ip" sort={sort} onSort={setSort}>
              Client
            </SortHead>
            <SortHead className="px-2 py-2 text-right" col="hits" sort={sort} onSort={setSort}>
              Anfragen
            </SortHead>
            <SortHead className="px-2 py-2 text-right" col="ok_hits" sort={sort} onSort={setSort}>
              davon 2xx
            </SortHead>
            <SortHead className="px-2 py-2" col="first" sort={sort} onSort={setSort}>
              Erster Treffer
            </SortHead>
            <SortHead className="px-2 py-2" col="last" sort={sort} onSort={setSort}>
              Letzter Treffer
            </SortHead>
            <SortHead className="px-2 py-2 text-right" col="dauer" sort={sort} onSort={setSort}>
              Dauer <InfoDot body={tr('field.duration')} hint={tr('field.duration_why')} />
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
                    erfolgreich
                  </Tag>
                )}
              </td>
              <td className="px-2 py-1.5 text-right tabular">{formatCount(c.hits)}</td>
              <td className={clsx('px-2 py-1.5 text-right tabular',
                c.ok_hits ? 'text-[var(--sev-high)]' : 'text-[var(--muted)]')}>
                {formatCount(c.ok_hits)}
              </td>
              {/* Auf die Sekunde: bei einem Muster-Treffer ist die Uhrzeit
                  die halbe Aussage — sie sagt, ob die Aufrufe in einem
                  Schwung kamen oder über Wochen verteilt. */}
              <td className="mono px-2 py-1.5 text-[12px] tabular text-[var(--muted)]">
                {formatLogTime(c.first_epoch, c.tz)}
              </td>
              <td className="mono px-2 py-1.5 text-[12px] tabular text-[var(--muted)]">
                {formatLogTime(c.last_epoch, c.tz)}
              </td>
              {/* Die Angriffslänge: 40 Aufrufe in zwei Minuten sind ein
                  Werkzeug, 40 über drei Wochen sind etwas anderes. */}
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
        {formatCount(result.uri_total)} getroffene URL{result.uri_total === 1 ? '' : 's'}
        <span className="opacity-70">
          {result.uri_total > result.uris.length
            ? `— die ${formatCount(result.uris.length)} häufigsten, zum Prüfen ob das Muster passt`
            : '— prüfen, ob das Muster passt'}
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
