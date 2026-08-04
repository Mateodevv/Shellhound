// CaseChain.tsx — die Chronologie des Falls.
//
// Jede andere Ansicht beantwortet „was": welche Datei, welcher Client,
// welches Konto. Diese beantwortet „in welcher Reihenfolge" — der erste
// Absatz jedes Berichts, den man bisher abtippte, indem man zwischen drei
// Ansichten hin- und hersprang und Zeitstempel im Kopf sortierte.
//
// SIE ORDNET GEMESSENE TATSACHEN UND BEHAUPTET KEINE URSACHE. Was hier
// steht, ist eine Beobachtung mit Zeitstempel und Herkunft; welche davon
// auseinander folgt, entscheidet der Analyst. Deshalb steht an jeder Zeile,
// WORAUS die Zeit stammt, und deshalb stehen die Lücken so sichtbar wie die
// Ereignisse: „dazwischen ist nichts belegt" ist eine Aussage des Falls.
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  AlertTriangle, ArrowRight, CircleHelp, Clock, Crosshair, Database, DoorOpen,
  FileWarning, LogIn, UserPlus,
} from 'lucide-react'
import { api, post, type CaseChain as ChainData, type ChainEvent } from '../api'
import { formatLogTime, formatSpan } from '../format'
import { Button, Card, Collapsible, SeverityBadge } from './ui'
import { InfoDot, Tooltip } from './Tooltip'

const KIND_ICON: Record<ChainEvent['kind'], typeof DoorOpen> = {
  erstkontakt: DoorOpen,
  versuch: CircleHelp,
  erfolg: FileWarning,
  alarm: AlertTriangle,
  'letzter-zugriff': LogIn,
  konto: UserPlus,
}

const KIND_LABEL: Record<ChainEvent['kind'], string> = {
  erstkontakt: 'Erstkontakt',
  versuch: 'nur Versuche',
  erfolg: 'erfolgreich',
  alarm: 'Alarm',
  'letzter-zugriff': 'letzte Aktivität',
  konto: 'Konto',
}

const SOURCE_HINT: Record<ChainEvent['source'], string> = {
  log: 'Zeit aus dem Access-Log, in der Zeitzone des Logs.',
  dump: 'Zeit aus dem Datenbank-Export, in der Zeitzone des Datenbankservers.',
}

/** Der Uhren-Abgleich: ein vom Analysten gesetzter Versatz je Quelle.
 *
 *  Log-Server und Datenbank-Server können verschiedene Uhren führen, und
 *  bei „Konto 03:17, Erstkontakt 09:12" kann ein 6-Stunden-Versatz die
 *  Reihenfolge der Geschichte drehen. Das Werkzeug rät nicht — der Versatz
 *  ist eine Aussage des Analysten und steht sichtbar in der Kette. */
function ClockEditor({ slug, offsets, onClose }: {
  slug: string
  offsets: { logs: number; dump: number }
  onClose: () => void
}) {
  const qc = useQueryClient()
  // In Stunden bedient, in Sekunden gespeichert: Uhren gehen um Zeitzonen
  // auseinander, nicht um Sekunden — und halbe Stunden gibt es (Indien).
  const [logs, setLogs] = useState(String(offsets.logs / 3600))
  const [dump, setDump] = useState(String(offsets.dump / 3600))
  useEffect(() => {
    setLogs(String(offsets.logs / 3600))
    setDump(String(offsets.dump / 3600))
  }, [offsets])
  const save = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/clock`, {
      logs: Math.round(parseFloat(logs.replace(',', '.') || '0') * 3600),
      dump: Math.round(parseFloat(dump.replace(',', '.') || '0') * 3600),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['chain'] })
      onClose()
    },
  })
  const feld = (wert: string, setz: (v: string) => void, label: string) => (
    <label className="flex items-center gap-1.5 text-[12px]">
      {label}
      <input value={wert} onChange={(e) => setz(e.target.value)}
        className="mono w-16 rounded-md border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1 text-right text-[12px] outline-none focus:border-[var(--accent)]/70" />
      <span className="text-[var(--muted)]">h</span>
    </label>
  )
  return (
    <div className="mb-3 flex flex-wrap items-center gap-3 rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-2 animate-fade-up">
      <Clock size={13} className="text-[var(--muted)]" />
      <span className="text-[12px] font-medium">Uhren-Abgleich</span>
      {feld(logs, setLogs, 'Log')}
      {feld(dump, setDump, 'DB-Export')}
      <span className="text-[11px] text-[var(--muted)]">
        positiv = Quelle ging nach, ihre Zeiten werden vorgestellt
      </span>
      <div className="ml-auto flex gap-1.5">
        <Button variant="primary" disabled={save.isPending} onClick={() => save.mutate()}>
          Übernehmen
        </Button>
        <Button variant="ghost" onClick={onClose}>Abbrechen</Button>
      </div>
    </div>
  )
}

export function CaseChain({ slug, onOpen, onTrace }: {
  slug: string
  /** Ein Artefakt öffnen — dieselbe Ansicht wie aus Findings. */
  onOpen: (artifact: string, kind: string) => void
  onTrace: (ip: string) => void
}) {
  // Sie steht offen, weil sie der erste Absatz des Berichts ist. Zuklappen
  // ist für die Fälle, in denen man die Kennzahlen darüber vergleichen will,
  // ohne 40 Zeilen dazwischen.
  const [open, setOpen] = useState(true)
  const [clockOpen, setClockOpen] = useState(false)
  const { data } = useQuery({
    queryKey: ['chain', slug],
    queryFn: () => api<ChainData>(`/api/cases/${slug}/chain`),
  })
  if (!data) return null
  if (!data.events.length && !data.gaps.length && !data.undated.length) return null

  const first = data.events[0]?.at ?? null
  const last = data.events[data.events.length - 1]?.at ?? null
  const adjusted = data.offsets && (data.offsets.logs !== 0 || data.offsets.dump !== 0)

  return (
    <Collapsible
      open={open}
      onToggle={() => setOpen(!open)}
      count={data.events.length || undefined}
      title={
        <>
          Chronologie
          <InfoDot
            title="Chronologie des Falls"
            body="Die bestätigten Artefakte in ihrer zeitlichen Abfolge — der erste Absatz des Berichts."
            hint="Sie ordnet GEMESSENE Tatsachen und behauptet keine Ursache: an jeder Zeile steht, ob die Zeit aus dem Access-Log oder aus dem Datenbank-Export stammt. Welche Beobachtung aus welcher folgt, entscheidest du." />
        </>
      }
      sub={data.events.length
        ? `${data.events.length} datierte Beobachtung(en) aus ${data.confirmed} bestätigten Artefakten, über ${formatSpan(first, last)}. Geordnet wird, was gemessen wurde — welche Beobachtung aus welcher folgt, entscheidest du.`
        : 'Sobald Artefakte als True Positive bestätigt sind, steht hier ihre zeitliche Abfolge.'}
      right={
        <Tooltip title="Uhren-Abgleich"
          body="Log-Server und Datenbank-Server können verschiedene Uhren führen — ein Versatz kann die Reihenfolge der Geschichte drehen."
          hint="Der Versatz ist deine Aussage, nicht eine Vermutung des Werkzeugs. Er wird im Fall gespeichert und in der Kette ausgewiesen.">
          <Button variant="ghost" onClick={() => setClockOpen(!clockOpen)}>
            <Clock size={13} />
            {adjusted
              ? `Uhren ${data.offsets.logs ? `Log ${data.offsets.logs > 0 ? '+' : ''}${data.offsets.logs / 3600}h` : ''}${data.offsets.logs && data.offsets.dump ? ' · ' : ''}${data.offsets.dump ? `DB ${data.offsets.dump > 0 ? '+' : ''}${data.offsets.dump / 3600}h` : ''}`
              : 'Uhren'}
          </Button>
        </Tooltip>
      }
    >
      {clockOpen && (
        <ClockEditor slug={slug} offsets={data.offsets ?? { logs: 0, dump: 0 }}
          onClose={() => setClockOpen(false)} />
      )}
      <Card className="overflow-hidden">
        {data.events.map((e, i) => {
          const Icon = KIND_ICON[e.kind] ?? CircleHelp
          const prev = data.events[i - 1]
          // Gleiche Sekunde = ein Moment, keine zwei. Die Zeit steht dann
          // nur einmal da, sonst liest sich eine Beobachtung wie zwei.
          const sameMoment = prev?.at === e.at
          const gapBefore = prev && e.at - prev.at > 3600
          return (
            <div key={i}>
              {gapBefore && (
                <div className="flex items-center gap-2 border-b border-[var(--line-soft)] bg-[var(--panel-2)] px-4 py-1 text-[11px] text-[var(--muted)]">
                  <span className="ml-[104px]">
                    ↕ {formatSpan(prev.at, e.at)} ohne belegte Beobachtung
                  </span>
                </div>
              )}
              <div className="flex items-start gap-3 border-b border-[var(--line-soft)] px-4 py-2 last:border-0 hover:bg-[var(--panel-2)]">
                <Tooltip hint={SOURCE_HINT[e.source]}>
                  <span className={clsx('mono w-[96px] shrink-0 pt-0.5 text-[11px] tabular',
                    sameMoment ? 'text-transparent' : 'text-[var(--muted)]')}>
                    {formatLogTime(e.at, 0).slice(0, 16)}
                  </span>
                </Tooltip>
                <Tooltip hint={KIND_LABEL[e.kind]}>
                  <Icon size={14} className={clsx('mt-0.5 shrink-0',
                    e.severity === 0 ? 'text-[var(--sev-high)]'
                      : e.severity === 1 ? 'text-[var(--sev-medium)]'
                        : 'text-[var(--muted)]')} />
                </Tooltip>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[13px] font-medium">{e.title}</span>
                    {e.severity != null && e.severity <= 1 && (
                      <SeverityBadge severity={e.severity} />
                    )}
                    <span className="rounded border border-[var(--line)] px-1 text-[10px] uppercase tracking-wide text-[var(--muted)]">
                      {e.source === 'log' ? 'Log' : 'DB-Export'}
                    </span>
                  </div>
                  {e.detail && (
                    <div className="mt-0.5 text-[11.5px] leading-snug text-[var(--muted)]">
                      {e.detail}
                    </div>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  {e.ip && (
                    <button onClick={() => onTrace(e.ip)}
                      className="inline-flex cursor-pointer items-center gap-1 rounded-md border border-transparent px-1.5 py-0.5 text-[11px] text-[var(--muted)] hover:border-[var(--accent)]/60 hover:text-[var(--fg)]">
                      <Crosshair size={12} /> Trace
                    </button>
                  )}
                  {e.artifact && (
                    <button onClick={() => onOpen(e.artifact, e.artifact_kind)}
                      className="inline-flex cursor-pointer items-center gap-1 rounded-md border border-transparent px-1.5 py-0.5 text-[11px] text-[var(--muted)] hover:border-[var(--accent)]/60 hover:text-[var(--fg)]">
                      Artefakt <ArrowRight size={12} />
                    </button>
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </Card>

      {/* Was der Fall NICHT belegt, gehört genauso in den Bericht wie das,
          was er belegt — und es steht sonst nirgends. */}
      {data.gaps.length > 0 && (
        <div className="mt-2 flex flex-col gap-1.5">
          {data.gaps.map((g) => (
            <div key={g}
              className="flex items-start gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12px] text-[var(--muted)]">
              <CircleHelp size={13} className="mt-0.5 shrink-0" />
              <span>{g}</span>
            </div>
          ))}
        </div>
      )}

      {data.undated.length > 0 && (
        <div className="mt-2 rounded-lg border border-[var(--line)] px-3 py-2">
          <div className="mb-1 flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-[var(--muted)]">
            <Database size={12} /> bestätigt, aber ohne Zeitbezug
          </div>
          {data.undated.map((u) => (
            <button key={u.artifact} onClick={() => onOpen(u.artifact, u.artifact_kind)}
              className="flex w-full cursor-pointer items-baseline gap-2 rounded px-1 py-0.5 text-left text-[12px] hover:bg-[var(--panel-2)]">
              <span className="mono shrink-0 truncate">{u.artifact}</span>
              <span className="min-w-0 text-[11.5px] text-[var(--muted)]">— {u.why}</span>
            </button>
          ))}
        </div>
      )}
    </Collapsible>
  )
}
