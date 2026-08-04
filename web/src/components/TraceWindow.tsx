// TraceWindow.tsx — was ein Client (oder eine Handvoll davon) getan hat:
// jeder Request aus dem Log-Index.
//
// Der Trace ist eine ABFRAGE gegen den Index, kein Log-Durchlauf — deshalb
// darf er überall aufgehen, wo eine IP-Adresse steht: in der Actors-Liste,
// im Artefakt-Detail, neben einem Hunt-Treffer. `layer` entscheidet, auf
// welcher Ebene er liegt, wenn er AUS einem anderen Fenster geöffnet wird.
//
// Oben der VERLAUF dieser Auswahl (dieselbe Kurve wie im Dashboard, nur auf
// die Clients eingeschränkt): erst daran sieht man, ob die Requests über
// Wochen verteilt sind oder in neun Minuten passiert sind. Er beschreibt
// immer den ganzen Zeitraum, nie die gerade angezeigte Seite.
//
// Gefiltert und sortiert wird in SQL, nicht im Browser — sonst würde eine
// Suche nur die 500 Zeilen der aktuellen Seite durchsuchen und alles davor
// und danach übersehen.
import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Crosshair, Download } from 'lucide-react'
import { downloadUrl, post, type TraceRow } from '../api'
import { formatCount, formatLogTime } from '../format'
import { Button, Modal, SearchInput } from './ui'
import { Tooltip } from './Tooltip'
import { TimelineChart, type TimelinePoint } from './TimelineChart'

const CLIENT_COLORS = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#9085e9']

const STATUS_FILTERS = [
  { id: '', label: 'alle' },
  { id: '2xx', label: '2xx' },
  { id: '3xx', label: '3xx' },
  { id: '4xx', label: '4xx' },
  { id: '5xx', label: '5xx' },
] as const

const SORTS = [
  { id: 'time', label: 'Zeit ↑ (Verlauf)' },
  { id: 'time_desc', label: 'Zeit ↓ (neueste zuerst)' },
  { id: 'status', label: 'Status' },
  { id: 'size', label: 'Größe' },
  { id: 'uri', label: 'URI' },
] as const

/** Was im Trace rot markiert wird — und warum.
 *
 *  `exact` für Stellen, an denen die auslösenden URIs BEKANNT sind (die
 *  Beispiel-URI eines Alarms, die vom Muster getroffenen URLs). `contains`
 *  für die Fälle, in denen es um eine DATEI geht: dort kennt man den Pfad,
 *  aber nicht jede Query-Variante, mit der sie aufgerufen wurde. */
export interface TraceMarks {
  exact?: string[]
  contains?: string[]
  reason?: string
}

export function TraceWindow({ slug, ips, onClose, layer = 0, marks }: {
  slug: string
  ips: string[] | null
  onClose: () => void
  layer?: number
  /** Ohne diese Markierung sucht man die auslösende Zeile unter tausenden
   *  von Hand. */
  marks?: TraceMarks
}) {
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')
  const [method, setMethod] = useState('')
  const [sort, setSort] = useState('time')
  const pageSize = 500

  // Ein neuer Trace startet auf Seite 1 und ohne Filter des vorigen.
  useEffect(() => {
    setPage(0); setSearch(''); setStatus(''); setMethod(''); setSort('time')
  }, [ips])
  // Ein Filter verkleinert die Menge — auf Seite 7 stünde man sonst im Leeren.
  useEffect(() => { setPage(0) }, [search, status, method, sort])

  const { data, isFetching } = useQuery({
    queryKey: ['trace', slug, ips, page, search, status, method, sort],
    queryFn: () => post<{ total: number; rows: TraceRow[]; methods: string[] }>(
      `/api/cases/${slug}/trace`,
      { ips, limit: pageSize, offset: page * pageSize, search, status, method, sort }),
    enabled: !!ips?.length,
  })

  // Der Verlauf hängt NUR an der Auswahl: er darf sich beim Blättern und
  // Filtern nicht ändern, sonst beschriebe er nicht mehr den Zeitraum.
  const { data: timeline } = useQuery({
    queryKey: ['trace-timeline', slug, ips],
    queryFn: () => post<{ timeline: TimelinePoint[] }>(
      `/api/cases/${slug}/trace/timeline`, { ips }),
    enabled: !!ips?.length,
  })

  const colorByClient = useMemo(() => {
    const map = new Map<string, string>()
    ips?.forEach((ip, i) => map.set(ip, CLIENT_COLORS[i % CLIENT_COLORS.length]))
    return map
  }, [ips])

  const istMarkiert = useMemo(() => {
    const exakt = new Set((marks?.exact ?? []).filter(Boolean)
      .map((u) => u.toLowerCase()))
    const teile = (marks?.contains ?? []).filter(Boolean)
      .map((u) => u.toLowerCase().replace(/\\/g, '/'))
    if (!exakt.size && !teile.length) return null
    return (uri: string) => {
      const u = (uri || '').toLowerCase()
      return exakt.has(u) || teile.some((t) => u.includes(t))
    }
  }, [marks])

  if (!ips) return null
  const filtering = Boolean(search || status || method)
  const points = timeline?.timeline ?? []
  const markedRows = istMarkiert
    ? (data?.rows.filter((r) => istMarkiert(r.uri)).length ?? 0)
    : 0

  return (
    <Modal open onClose={onClose} layer={layer}
      title={<span className="flex items-center gap-2">
        <Crosshair size={16} className="text-[var(--accent)]" />
        Trace: {ips.length === 1 ? ips[0] : `${ips.length} Clients`}
        {data && <span className="text-[12px] font-normal text-[var(--muted)]">
          {formatCount(data.total)} Requests {isFetching && '· lädt…'}
        </span>}
      </span>}>

      {points.length > 1 && (
        <div className="mb-3 rounded-xl border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2">
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            Verlauf dieser Auswahl
            <span className="ml-2 font-normal normal-case opacity-70">
              — unabhängig von Filter und Seite
            </span>
          </div>
          <TimelineChart data={points} height={160} />
        </div>
      )}

      {istMarkiert && (
        <div className="mb-2 flex flex-wrap items-center gap-2 rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-1.5 text-[12px]">
          <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: 'var(--sev-high)' }} />
          <span className="text-[var(--danger-text)]">
            {markedRows > 0
              ? `${formatCount(markedRows)} Zeile(n) auf dieser Seite rot markiert`
              : 'Auf dieser Seite keine markierte Zeile'}
          </span>
          <span className="text-[var(--muted)]">
            — {marks?.reason ?? 'das ist der Aufruf, der zum Flaggen geführt hat'}.
          </span>
        </div>
      )}

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <SearchInput value={search} onChange={setSearch} placeholder="URI oder User-Agent…" />
        <div className="inline-flex overflow-hidden rounded-lg border border-[var(--line)]">
          {STATUS_FILTERS.map((f) => (
            <button key={f.id}
              onClick={() => setStatus(f.id)}
              className={clsx(
                'cursor-pointer px-2.5 py-1.5 text-[12px] font-medium transition-colors',
                status === f.id
                  ? 'bg-[var(--accent)] text-white'
                  : 'bg-[var(--panel-2)] text-[var(--muted)] hover:text-[var(--fg)]')}>
              {f.label}
            </button>
          ))}
        </div>
        {(data?.methods.length ?? 0) > 1 && (
          <select value={method} onChange={(e) => setMethod(e.target.value)}
            className="cursor-pointer rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1.5 text-xs outline-none">
            <option value="">Methode: alle</option>
            {data?.methods.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        )}
        <select value={sort} onChange={(e) => setSort(e.target.value)}
          className="cursor-pointer rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1.5 text-xs outline-none">
          {SORTS.map((s) => (
            <option key={s.id} value={s.id}>Sortierung: {s.label}</option>
          ))}
        </select>
        {filtering && (
          <Tooltip hint="Der Filter läuft über den ganzen Trace, nicht nur über die angezeigte Seite.">
            <Button variant="ghost"
              onClick={() => { setSearch(''); setStatus(''); setMethod('') }}>
              Filter zurücksetzen
            </Button>
          </Tooltip>
        )}
        <a
          className="ml-auto inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] font-medium hover:border-[var(--accent)]/60"
          href={downloadUrl(`/api/cases/${slug}/trace.csv?ips=${ips.join(',')}`)}
        >
          <Download size={14} /> Vollständig als CSV
        </a>
      </div>

      {data && data.total > pageSize && (
        <div className="mb-2 flex items-center gap-2 text-[12px] text-[var(--muted)]">
          <Button variant="ghost" disabled={page === 0} onClick={() => setPage(page - 1)}>←</Button>
          Seite {page + 1} / {Math.ceil(data.total / pageSize)}
          <Button variant="ghost" disabled={(page + 1) * pageSize >= data.total}
            onClick={() => setPage(page + 1)}>→</Button>
          {filtering && <span className="opacity-70">gefiltert</span>}
        </div>
      )}

      <div className="overflow-x-auto rounded-lg border border-[var(--line)]">
        <table className="w-full border-collapse text-[12px]">
          <thead>
            <tr className="border-b border-[var(--line)] text-left text-[10px] uppercase tracking-wider text-[var(--muted)]">
              {ips.length > 1 && <th className="px-2 py-1.5">Client</th>}
              <th className="px-2 py-1.5">Zeit</th>
              <th className="px-2 py-1.5">Methode</th>
              <th className="px-2 py-1.5">URI</th>
              <th className="px-2 py-1.5 text-right">Status</th>
              <th className="px-2 py-1.5">User-Agent</th>
            </tr>
          </thead>
          <tbody className="mono">
            {data?.rows.map((r, i) => {
              const hit = istMarkiert ? istMarkiert(r.uri) : false
              return (
              <tr key={i} className={clsx(
                'border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]',
                hit && 'bg-[var(--danger-soft)]')}
                style={hit ? { boxShadow: 'inset 3px 0 0 var(--sev-high)' } : undefined}>
                {ips.length > 1 && (
                  <td className="whitespace-nowrap px-2 py-1">
                    <span className="mr-1.5 inline-block h-2 w-2 rounded-full"
                      style={{ background: colorByClient.get(r.client) }} />
                    {r.client}
                  </td>
                )}
                <td className="whitespace-nowrap px-2 py-1 text-[var(--muted)]">
                  {formatLogTime(r.epoch, r.tz)}
                </td>
                <td className="px-2 py-1">{r.method}</td>
                <td className={clsx('max-w-[420px] truncate px-2 py-1',
                  hit && 'font-semibold text-[var(--danger-text)]')}
                  title={r.uri}>{r.uri}</td>
                <td className={clsx('px-2 py-1 text-right tabular',
                  r.status >= 500 ? 'text-[var(--sev-high)]'
                    : r.status >= 400 ? 'text-[var(--sev-medium)]'
                      : r.status >= 300 ? 'text-[var(--sev-low)]' : 'text-[var(--ok)]')}>
                  {r.status}
                </td>
                <td className="max-w-[220px] truncate px-2 py-1 text-[var(--muted)]" title={r.agent}>
                  {r.agent}
                </td>
              </tr>
              )
            })}
          </tbody>
        </table>
        {data && !data.rows.length && (
          <div className="px-4 py-8 text-center text-[13px] text-[var(--muted)]">
            {filtering
              ? 'Kein Request passt zu diesem Filter — die Auswahl selbst hat aber Einträge.'
              : 'Keine Requests im Index für diese Auswahl.'}
          </div>
        )}
      </div>
    </Modal>
  )
}
