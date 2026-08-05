// Actors.tsx — every client the logs saw, mit Aktivitäts-Sparkline und
// Klassifikations-Badges. Traces sind Abfragen gegen den Index: 20 Clients
// auswählen und der kombinierte Trace steht sofort.
//
// ARBEITSTEILUNG mit Findings: dort wird entschieden, hier wird GEJAGT —
// die Grundgesamtheit aller Clients, auch derer, auf die keine Regel
// angesprochen hat. Was in Findings längst entschieden ist, trägt hier
// sein Badge und lässt sich im selben Artefakt-Fenster öffnen; niemand
// soll in dieser Liste neu bewerten, was drüben schon beantwortet ist.
import { useT, type Translate } from '../i18n'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Box, Crosshair, Download, FileSearch, Users,
} from 'lucide-react'
import {
  api, downloadUrl, post, type Actor, type ActorsResponse, type CaseDetail,
} from '../api'
import {
  formatCount, formatDay, formatLogTime, formatSpan, relativeTime,
  type EvidenceRoot,
} from '../format'
import {
  Button, Chip, EmptyState, SearchInput, Tag, TriageBadge,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { explain } from '../explain'
import { Sparkline } from '../components/Sparkline'
import { IpFlag } from '../components/IpFlag'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import type { ViewId } from '../App'

// Jeder Chip ist ein AUSBLENDE-Schalter: Klick versteckt die Klasse, der
// nächste Klick holt sie zurück, mehrere stapeln sich. So arbeitet man sich
// durch die Grundgesamtheit: Scanner weg, Brute-Force weg — was übrig
// bleibt, ist das, was noch keine Regel benannt hat.
// Nur die Schlüssel stehen hier: übersetzt wird beim Rendern, sonst wäre
// die Sprache beim Laden des Moduls eingefroren.
const FLAGS = [
  { id: 'quiet', key: 'quiet' },
  { id: 'alerted', key: 'alerted' },
  { id: 'scanner', key: 'scanner' },
  { id: 'bruteforce', key: 'brute' },
  { id: 'probes', key: 'probes' },
] as const

// key -> Erklärung im Glossar; label -> was auf dem Badge steht.
// Die Abzeichen eines Clients. `key` zeigt auf die Erklärung im Katalog,
// `label` wird beim Rendern übersetzt -- deshalb bekommt die Funktion den
// Übersetzer herein statt ihn zu importieren.
function actorBadges(a: Actor, tr: Translate) {
  const badges: { key: string; label: string; tone: 'danger' | 'warn' | 'accent' | undefined }[] = []
  if (a.login_redirects > 0 && a.login_posts >= 30)
    badges.push({ key: 'loginSuccess', label: tr('badge.loginSuccess'), tone: 'danger' })
  if (a.upload_php_ok > 0)
    badges.push({ key: 'shellAccess', label: tr('badge.shellAccess'), tone: 'danger' })
  if (a.login_posts >= 30)
    badges.push({ key: 'bruteForce', label: tr('badge.bruteForce', { n: a.login_posts }), tone: 'warn' })
  // dezent (kein tone): ein Scanner-Besuch ist Kontext, kein Vorfall.
  if (a.scanner_uas !== '[]')
    badges.push({ key: 'scanner', label: tr('badge.scanner'), tone: undefined })
  if (a.sqli_ok > 0)
    badges.push({ key: 'sqliOk', label: tr('badge.sqliOk', { n: a.sqli_ok }), tone: 'warn' })
  else if (a.sqli_attempts > 0)
    badges.push({ key: 'sqliAttempts', label: tr('badge.sqliAttempts', { n: a.sqli_attempts }), tone: undefined })
  if (a.traversal_ok > 0)
    badges.push({ key: 'traversal', label: tr('badge.traversal'), tone: 'warn' })
  return badges
}

export function Actors({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  // Default: nichts ausgeblendet — das Einzigartige dieser Seite ist die
  // Grundgesamtheit. Ausblenden ist die Handbewegung des Jagens.
  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const [sort, setSort] = useState('requests')
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // Die URIs, die bei DIESEN Clients den Alarm ausgelöst haben — der Trace
  // markiert sie rot, damit man die auslösende Zeile nicht sucht.
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)

  const t = useTriage(slug)

  const hide = [...hidden].join(',')
  const { data } = useQuery({
    queryKey: ['actors', slug, search, hide, sort],
    queryFn: () => api<ActorsResponse>(
      `/api/cases/${slug}/actors?search=${encodeURIComponent(search)}&hide=${hide}&sort=${sort}&limit=200`),
  })

  // Die Evidence-Wurzeln, damit Datei-Pfade in Vorschlägen lesbar sind —
  // derselbe Query-Key wie in der Shell, also praktisch immer schon geladen.
  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))

  const collect = useMutation({
    mutationFn: (ips: string[]) => post(`/api/cases/${slug}/actors/collect`, { ips }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['actors'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
      setChecked(new Set())
    },
  })

  const actors = data?.actors ?? []
  const toggleAll = () => {
    if (checked.size === actors.length) setChecked(new Set())
    else setChecked(new Set(actors.map((a) => a.ip)))
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title="Actors"
          body={tr('actors.title.body')}
          hint={tr('actors.title.hint')}>
          <h1 className="mr-2 text-lg font-bold">Actors</h1>
        </Tooltip>
        {FLAGS.map((f) => (
          <Tooltip key={f.id}
            hint={hidden.has(f.id)
              ? `${tr('actors.flag.hidden')} ${tr(`actors.flag.${f.key}.hint`)}`
              : `${tr('actors.flag.hide')} ${tr(`actors.flag.${f.key}.hint`)}`}>
            <Chip active={false} dimmed={hidden.has(f.id)}
              onClick={() => setHidden((prev) => {
                const next = new Set(prev)
                if (next.has(f.id)) next.delete(f.id)
                else next.add(f.id)
                return next
              })}>
              {tr(`actors.flag.${f.key}`)}
            </Chip>
          </Tooltip>
        ))}
        <select
          value={sort}
          onChange={(e) => setSort(e.target.value)}
          className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1.5 text-xs outline-none cursor-pointer"
        >
          <option value="requests">{tr('actors.sort.requests')}</option>
          <option value="last">{tr('actors.sort.last')}</option>
          <option value="first">{tr('actors.sort.first')}</option>
          <option value="errors">{tr('actors.sort.errors')}</option>
        </select>
        <div className="ml-auto flex items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={tr('actors.search')} />
        </div>
      </div>


      {checked.size > 0 && (
        <div className="flex items-center gap-2 rounded-xl border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-4 py-2 animate-fade-up">
          <span className="text-[13px] font-semibold">{checked.size} ausgewählt</span>
          <Button variant="primary"
            onClick={() => {
              setTraceMarks({
                exact: actors.filter((a) => checked.has(a.ip))
                  .flatMap((a) => a.alerts.map((al) => al.example)).filter(Boolean),
                reason: tr('marks.alertTrigger'),
              })
              setTraceIps([...checked])
            }}>
            <Crosshair size={14} /> Trace ({checked.size} Clients)
          </Button>
          <Tooltip hint="Übernimmt die Adressen als Indikatoren — getaggt mit dem, was die Logs sie tun gesehen haben (Scanner, Brute-Force, erfolgreich).">
            <Button onClick={() => collect.mutate([...checked])}>
              <Box size={14} /> In IOC Box
            </Button>
          </Tooltip>
          <a
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] font-medium hover:border-[var(--accent)]/60"
            href={downloadUrl(`/api/cases/${slug}/trace.csv?ips=${[...checked].join(',')}`)}
          >
            <Download size={14} /> Trace als CSV
          </a>
          <Button variant="ghost" onClick={() => setChecked(new Set())}>Auswahl leeren</Button>
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--panel)]">
        <table className="w-full border-collapse text-[13px]">
          <thead>
            <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
              <th className="w-8 px-3 py-2">
                <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                  checked={checked.size > 0 && checked.size === actors.length}
                  onChange={toggleAll} />
              </th>
              <th className="px-2 py-2">{tr('table.client')}</th>
              <th className="px-2 py-2">
                <span className="inline-flex items-center gap-1">Aktivität <InfoDot body={tr('field.sparkline')} /></span>
              </th>
              <th className="px-2 py-2 text-right">
                <span className="inline-flex items-center gap-1">Requests <InfoDot body={tr('field.requests')} /></span>
              </th>
              <th className="px-2 py-2">
                <span className="inline-flex items-center gap-1">Zeitraum <InfoDot body={tr('field.timespan')} /></span>
              </th>
              <th className="px-2 py-2 text-right">
                <span className="inline-flex items-center gap-1">
                  Dauer <InfoDot body={tr('field.duration')} hint={tr('field.duration_why')} />
                </span>
              </th>
              <th className="px-2 py-2">{tr('table.behaviour')}</th>
              <th className="px-2 py-2 text-right">
                <span className="inline-flex items-center gap-1">Fehler <InfoDot body={tr('field.errors')} /></span>
              </th>
              <th className="w-24 px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {actors.map((a) => {
              const badges = actorBadges(a, tr)
              return (
                <tr key={a.ip_id}
                  className="group border-b border-[var(--line-soft)] transition-colors last:border-0 hover:bg-[var(--panel-2)]">
                  <td className="px-3 py-2">
                    <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                      checked={checked.has(a.ip)}
                      onChange={(e) => {
                        const next = new Set(checked)
                        if (e.target.checked) next.add(a.ip)
                        else next.delete(a.ip)
                        setChecked(next)
                      }} />
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex items-center gap-2">
                      <IpFlag ip={a.ip} />
                      <span className="mono font-medium">{a.ip}</span>
                      {a.in_box && <Tag tone="accent" explain={tr('actors.inBox')}>IOC</Tag>}
                      {/* Was in Findings entschieden wurde, gilt auch hier —
                          sonst bewertet man dieselbe Adresse zweimal. */}
                      {a.triage && a.triage !== 'new' && (
                        <TriageBadge state={a.triage} label={tr(`triage.${a.triage}`)} />
                      )}
                    </div>
                  </td>
                  <td className="px-2 py-2">
                    <Sparkline data={a.sparkline}
                      color={badges.some((b) => b.tone === 'danger') ? 'var(--sev-high)' : 'var(--accent)'} />
                  </td>
                  <td className="px-2 py-2 text-right tabular">{formatCount(a.requests)}</td>
                  <td className="px-2 py-2 text-[12px] text-[var(--muted)]">
                    <Tooltip title={tr('actors.firstLast')}
                      body={`${formatDay(a.first_epoch, a.tz)} bis ${formatDay(a.last_epoch, a.tz)} (${relativeTime(a.last_epoch ? new Date(a.last_epoch * 1000).toISOString() : null)} zuletzt)`}>
                      <span>{formatDay(a.first_epoch, a.tz)} → {formatDay(a.last_epoch, a.tz)}</span>
                    </Tooltip>
                  </td>
                  {/* Wie lange dieser Client aktiv war. Vier Minuten sind ein
                      Werkzeuglauf, vier Wochen sind ein Dauergast — dieselbe
                      Requestzahl bedeutet in beiden Fällen etwas anderes. */}
                  <td className="mono px-2 py-2 text-right text-[12px] tabular text-[var(--muted)]">
                    <Tooltip title={tr('actors.durationTitle')}
                      body={`${formatLogTime(a.first_epoch, a.tz)} bis ${formatLogTime(a.last_epoch, a.tz)}`}
                      hint={tr('field.duration_why')}>
                      <span>{formatSpan(a.first_epoch, a.last_epoch)}</span>
                    </Tooltip>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex max-w-[320px] flex-wrap gap-1">
                      {badges.length
                        ? badges.slice(0, 3).map((b, i) => (
                          <Tag key={i} tone={b.tone}
                            explain={explain(tr, `badge.${b.key}`)?.what} hint={explain(tr, `badge.${b.key}`)?.why}>
                            {b.label}
                          </Tag>
                        ))
                        : <span className="text-[12px] text-[var(--muted)]">{tr('actors.unremarkable')}</span>}
                    </div>
                  </td>
                  <td className={clsx('px-2 py-2 text-right tabular text-[12px]',
                    a.err4 + a.err5 > 0 ? 'text-[var(--sev-medium)]' : 'text-[var(--muted)]')}>
                    {formatCount(a.err4 + a.err5)}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <div className="flex items-center justify-end gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
                      {/* Nur Clients MIT Findings haben ein Artefakt — für
                          alle anderen gibt es nichts zu entscheiden. */}
                      {a.triage && (
                        <Tooltip hint={tr('actors.openArtifact')}>
                          <Button variant="ghost"
                            onClick={() => {
                              t.clearCollected()
                              setSelected({
                                artifact: a.ip, artifact_kind: 'client',
                                worst: 3, triage: a.triage!, triage_note: '',
                              })
                            }}>
                            <FileSearch size={13} /> Artefakt
                          </Button>
                        </Tooltip>
                      )}
                      <Button variant="ghost"
                        onClick={() => {
                          setTraceMarks({
                            exact: a.alerts.map((al) => al.example).filter(Boolean),
                            reason: tr('marks.alertTrigger'),
                          })
                          setTraceIps([a.ip])
                        }}>
                        <Crosshair size={13} /> Trace
                      </Button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {actors.length === 0 && (
          <EmptyState icon={<Users size={36} />}
            title={hidden.size ? tr('actors.empty.hidden') : tr('actors.empty.title')}
            sub={hidden.size
              ? tr('actors.empty.hiddenSub')
              : tr('actors.empty.sub')} />
        )}
      </div>
      {data && data.total > actors.length && (
        <div className="text-[12px] text-[var(--muted)]">
          {formatCount(actors.length)} von {formatCount(data.total)} Clients angezeigt — Filter/Suche verfeinern.
        </div>
      )}

      <ArtifactWindow
        slug={slug}
        artifact={selected}
        roots={roots}
        collected={t.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips, m) => { setTraceMarks(m); setTraceIps(ips) }}
        onClose={() => { setSelected(null); t.clearCollected() }}
        onTriage={(state, note) => {
          if (selected) t.decide([selected.artifact], state, note)
        }}
      />

      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />

      <FileViewer
        slug={slug}
        path={viewing?.path ?? null}
        focusLine={viewing?.line}
        layer={2}
        onClose={() => setViewing(null)}
      />

      <TriageFollowUp t={t} roots={roots} />
    </div>
  )
}

