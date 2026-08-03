// Actors.tsx — every client the logs saw, mit Aktivitäts-Sparkline und
// Klassifikations-Badges. Traces sind Abfragen gegen den Index: 20 Clients
// auswählen und der kombinierte Trace steht sofort.
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Box, Crosshair, Download, Users,
} from 'lucide-react'
import {
  api, downloadUrl, post, type Actor, type ActorsResponse,
} from '../api'
import { formatCount, formatDay, relativeTime } from '../format'
import {
  Button, Chip, EmptyState, SearchInput, Tag,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { BADGE_EXPLAIN, FIELD_EXPLAIN } from '../explain'
import { Sparkline } from '../components/Sparkline'
import { TraceWindow } from '../components/TraceWindow'
import type { ViewId } from '../App'

const FLAGS = [
  { id: '', label: 'Alle', hint: 'Jeder Client, den die Logs gesehen haben.' },
  { id: 'alerted', label: 'Auffällig', hint: 'Clients, bei denen etwas mit DIESEM System passiert ist — Shell-Zugriff, Brute-Force, erfolgreiche Angriffsmuster. Reine Scanner-Besuche zählen hier nicht mit.' },
  { id: 'scanner', label: 'Scanner', hint: 'Clients, die sich als Scan-Werkzeug ausgegeben haben. Passiert jedem Server rund um die Uhr — hier separat, damit es die echte Arbeit nicht zudeckt.' },
  { id: 'bruteforce', label: 'Brute-Force', hint: 'Clients mit vielen Login-Versuchen.' },
  { id: 'probes', label: 'Angriffs­muster', hint: 'Clients mit SQL-Injection-, Traversal- oder Upload-PHP-Mustern.' },
] as const

// key -> Erklärung im Glossar; label -> was auf dem Badge steht.
function actorBadges(a: Actor) {
  const badges: { key: string; label: string; tone: 'danger' | 'warn' | 'accent' | undefined }[] = []
  if (a.login_redirects > 0 && a.login_posts >= 30)
    badges.push({ key: 'Login erfolgreich?', label: 'Login erfolgreich?', tone: 'danger' })
  if (a.upload_php_ok > 0) badges.push({ key: 'Shell-Zugriff 2xx', label: 'Shell-Zugriff', tone: 'danger' })
  if (a.login_posts >= 30) badges.push({ key: 'Brute-Force', label: `Brute-Force ×${a.login_posts}`, tone: 'warn' })
  // dezent (kein tone): ein Scanner-Besuch ist Kontext, kein Vorfall.
  if (a.scanner_uas !== '[]') badges.push({ key: 'Scanner-UA', label: 'Scanner', tone: undefined })
  if (a.sqli_ok > 0) badges.push({ key: 'SQLi 2xx', label: `SQLi ×${a.sqli_ok}`, tone: 'warn' })
  else if (a.sqli_attempts > 0) badges.push({ key: 'SQLi-Versuche', label: `SQLi-Versuche ×${a.sqli_attempts}`, tone: undefined })
  if (a.traversal_ok > 0) badges.push({ key: 'Traversal 2xx', label: 'Traversal', tone: 'warn' })
  return badges
}

export function Actors({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [flag, setFlag] = useState<string>('alerted')
  const [sort, setSort] = useState('requests')
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [traceIps, setTraceIps] = useState<string[] | null>(null)

  const { data } = useQuery({
    queryKey: ['actors', slug, search, flag, sort],
    queryFn: () => api<ActorsResponse>(
      `/api/cases/${slug}/actors?search=${encodeURIComponent(search)}&flag=${flag}&sort=${sort}&limit=200`),
  })

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
          body="Jede IP-Adresse, die in den Logs auftaucht — mögliche Angreifer, Scanner und ganz normale Besucher."
          hint="Auswählen und »Trace« zeigt, was ein Client genau getan hat. Das läuft als Abfrage gegen den Index — auch 20 Clients auf einmal sind sofort da.">
          <h1 className="mr-2 text-lg font-bold">Actors</h1>
        </Tooltip>
        {FLAGS.map((f) => (
          <Tooltip key={f.id} hint={f.hint}>
            <Chip active={flag === f.id} onClick={() => setFlag(f.id)}>
              {f.label}
            </Chip>
          </Tooltip>
        ))}
        <select
          value={sort}
          onChange={(e) => setSort(e.target.value)}
          className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1.5 text-xs outline-none cursor-pointer"
        >
          <option value="requests">Sortierung: Requests</option>
          <option value="last">Sortierung: zuletzt gesehen</option>
          <option value="first">Sortierung: zuerst gesehen</option>
          <option value="errors">Sortierung: Fehler</option>
        </select>
        <div className="ml-auto flex items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder="IP suchen…" />
        </div>
      </div>

      {checked.size > 0 && (
        <div className="flex items-center gap-2 rounded-xl border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-4 py-2 animate-fade-up">
          <span className="text-[13px] font-semibold">{checked.size} ausgewählt</span>
          <Button variant="primary" onClick={() => setTraceIps([...checked])}>
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
              <th className="px-2 py-2">Client</th>
              <th className="px-2 py-2">
                <span className="inline-flex items-center gap-1">Aktivität <InfoDot body={FIELD_EXPLAIN.sparkline} /></span>
              </th>
              <th className="px-2 py-2 text-right">
                <span className="inline-flex items-center gap-1">Requests <InfoDot body={FIELD_EXPLAIN.requests} /></span>
              </th>
              <th className="px-2 py-2">
                <span className="inline-flex items-center gap-1">Zeitraum <InfoDot body={FIELD_EXPLAIN.timespan} /></span>
              </th>
              <th className="px-2 py-2">Verhalten</th>
              <th className="px-2 py-2 text-right">
                <span className="inline-flex items-center gap-1">Fehler <InfoDot body={FIELD_EXPLAIN.errors} /></span>
              </th>
              <th className="w-24 px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {actors.map((a) => {
              const badges = actorBadges(a)
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
                      <span className="mono font-medium">{a.ip}</span>
                      {a.in_box && <Tag tone="accent" explain="Diese Adresse liegt bereits in der IOC Box.">IOC</Tag>}
                    </div>
                  </td>
                  <td className="px-2 py-2">
                    <Sparkline data={a.sparkline}
                      color={badges.some((b) => b.tone === 'danger') ? 'var(--sev-high)' : 'var(--accent)'} />
                  </td>
                  <td className="px-2 py-2 text-right tabular">{formatCount(a.requests)}</td>
                  <td className="px-2 py-2 text-[12px] text-[var(--muted)]">
                    <Tooltip title="Erste und letzte Anfrage"
                      body={`${formatDay(a.first_epoch, a.tz)} bis ${formatDay(a.last_epoch, a.tz)} (${relativeTime(a.last_epoch ? new Date(a.last_epoch * 1000).toISOString() : null)} zuletzt)`}>
                      <span>{formatDay(a.first_epoch, a.tz)} → {formatDay(a.last_epoch, a.tz)}</span>
                    </Tooltip>
                  </td>
                  <td className="px-2 py-2">
                    <div className="flex max-w-[320px] flex-wrap gap-1">
                      {badges.length
                        ? badges.slice(0, 3).map((b, i) => (
                          <Tag key={i} tone={b.tone}
                            explain={BADGE_EXPLAIN[b.key]?.what} hint={BADGE_EXPLAIN[b.key]?.why}>
                            {b.label}
                          </Tag>
                        ))
                        : <span className="text-[12px] text-[var(--muted)]">unauffällig</span>}
                    </div>
                  </td>
                  <td className={clsx('px-2 py-2 text-right tabular text-[12px]',
                    a.err4 + a.err5 > 0 ? 'text-[var(--sev-medium)]' : 'text-[var(--muted)]')}>
                    {formatCount(a.err4 + a.err5)}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <Button variant="ghost" className="opacity-0 transition-opacity group-hover:opacity-100"
                      onClick={() => setTraceIps([a.ip])}>
                      <Crosshair size={13} /> Trace
                    </Button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {actors.length === 0 && (
          <EmptyState icon={<Users size={36} />}
            title={flag ? 'Kein Client in diesem Filter' : 'Noch keine Actors'}
            sub={flag
              ? 'Für diesen Filter gibt es keinen Treffer. Wechsle auf »Alle«, um jeden gesehenen Client zu sehen.'
              : 'Die Actors kommen aus den Access-Logs. Registriere die Logs als Evidence und starte die Analyse — danach steht hier jeder Client mit seiner Aktivität.'} />
        )}
      </div>
      {data && data.total > actors.length && (
        <div className="text-[12px] text-[var(--muted)]">
          {formatCount(actors.length)} von {formatCount(data.total)} Clients angezeigt — Filter/Suche verfeinern.
        </div>
      )}

      <TraceWindow slug={slug} ips={traceIps} onClose={() => setTraceIps(null)} />
    </div>
  )
}

