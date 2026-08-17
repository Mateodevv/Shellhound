// Actors.tsx -- every client the logs saw, with an activity sparkline and
// classification badges. Traces are queries against the index: select 20
// clients and the combined trace is there at once.
//
// DIVISION OF LABOUR with Findings: over there decisions are made, here one
// HUNTS -- the total population of all clients, including those no rule
// responded to. What has long been decided in Findings carries its badge
// here and opens in the same artifact window; nobody should re-assess in
// this list what has already been answered over there.
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

// Every chip is a HIDE switch: a click hides the class, the next click
// brings it back, several of them stack. That is how one works through the
// total population: scanners gone, brute force gone -- what remains is what
// no rule has named yet.
// Only the keys stand here: translation happens at render time, otherwise
// the language would be frozen at module load.
const FLAGS = [
  { id: 'quiet', key: 'quiet' },
  { id: 'alerted', key: 'alerted' },
  { id: 'scanner', key: 'scanner' },
  { id: 'bruteforce', key: 'brute' },
  { id: 'probes', key: 'probes' },
] as const

// The badges of a client. `key` points at the explanation in the catalogue,
// `label` is translated at render time -- which is why the function takes the
// translator in rather than importing it.
//
// `bfThreshold` comes from the server (see /actors): the same number decides
// the "inconspicuous" filter in SQL, and a badge row that disagrees with the
// filter above it is worse than either alone. The fallback only covers an
// older server that does not send it yet.
const BF_FALLBACK = 30

function actorBadges(a: Actor, tr: Translate, bfThreshold = BF_FALLBACK) {
  const badges: { key: string; label: string; tone: 'danger' | 'warn' | 'accent' | undefined }[] = []
  // THE SAME THREE CONDITIONS THE ENGINE USES. Joomla answers every login
  // POST with a redirect whether the credentials were right or wrong, so
  // `login_redirects` proved nothing and the engine stopped reading it --
  // and this badge did not follow, then followed only half way. `admin_ok`
  // says somebody got in; it cannot say who, and the site's own operator
  // gets in every working morning. The burst is what they do not share.
  if (a.admin_ok > 0 && a.login_posts >= bfThreshold
      && a.login_burst >= bfThreshold)
    badges.push({ key: 'loginSuccess', label: tr('badge.loginSuccess'), tone: 'danger' })
  if (a.cms_dir_php_ok > 0)
    badges.push({ key: 'cmsDirPhp', label: tr('badge.cmsDirPhp'), tone: 'danger' })
  if (a.upload_php_ok > 0)
    badges.push({ key: 'shellAccess', label: tr('badge.shellAccess'), tone: 'danger' })
  if (a.login_posts >= bfThreshold)
    badges.push({ key: 'bruteForce', label: tr('badge.bruteForce', { n: a.login_posts }), tone: 'warn' })
  // Understated (no tone): a scanner visit is context, not an incident.
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
  // Default: nothing hidden -- what makes this page unique is the total
  // population. Hiding is the hand movement of hunting.
  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const [sort, setSort] = useState('requests')
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // The URIs that triggered the alert for THESE clients -- the trace marks
  // them red so that one does not have to hunt for the triggering line.
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

  // The evidence roots, so that file paths in suggestions are readable --
  // the same query key as in the shell, so practically always loaded
  // already.
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
        <Tooltip title={tr('nav.actors')}
          body={tr('actors.title.body')}
          hint={tr('actors.title.hint')}>
          <h1 className="mr-2 text-lg font-bold">{tr('nav.actors')}</h1>
        </Tooltip>
        {FLAGS.map((f) => (
          <Tooltip key={f.id}
            hint={hidden.has(f.id)
              ? `${tr('actors.flag.hidden')} ${tr(`actors.flag.${f.key}.hint`)}`
              : `${tr('actors.flag.hide')} ${tr(`actors.flag.${f.key}.hint`)}`}>
            <Chip active={!hidden.has(f.id)} dimmed={hidden.has(f.id)}
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
          <span className="text-[13px] font-semibold">{tr('common.selected', { n: checked.size })}</span>
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
          <Tooltip hint={tr('actors.collect.hint')}>
            <Button onClick={() => collect.mutate([...checked])}>
              <Box size={14} /> {tr('actors.toIocBox')}
            </Button>
          </Tooltip>
          <a
            className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] font-medium hover:border-[var(--accent)]/60"
            href={downloadUrl(`/api/cases/${slug}/trace.csv?ips=${[...checked].join(',')}`)}
          >
            <Download size={14} /> {tr('actors.traceCsv')}
          </a>
          <Button variant="ghost" onClick={() => setChecked(new Set())}>{tr('common.clearSelection')}</Button>
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
                <span className="inline-flex items-center gap-1">{tr('table.activity')} <InfoDot body={tr('field.sparkline')} /></span>
              </th>
              <th className="px-2 py-2 text-right">
                <span className="inline-flex items-center gap-1">{tr('table.requests')} <InfoDot body={tr('field.requests')} /></span>
              </th>
              <th className="px-2 py-2">
                <span className="inline-flex items-center gap-1">{tr('field.period')} <InfoDot body={tr('field.timespan')} /></span>
              </th>
              <th className="px-2 py-2 text-right">
                <span className="inline-flex items-center gap-1">
                  {tr('hunt.duration')} <InfoDot body={tr('field.duration')} hint={tr('field.duration_why')} />
                </span>
              </th>
              <th className="px-2 py-2">{tr('table.behaviour')}</th>
              <th className="px-2 py-2 text-right">
                <span className="inline-flex items-center gap-1">{tr('table.errors')} <InfoDot body={tr('field.errors')} /></span>
              </th>
              <th className="w-24 px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {actors.map((a) => {
              const badges = actorBadges(a, tr, data?.bf_threshold)
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
                      {/* What was decided in Findings holds here too --
                          otherwise one assesses the same address twice. */}
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
                  {/* How long this client was active. Four minutes are a
                      tool run, four weeks are a regular guest -- the same
                      request count means something different in each. */}
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
                      {/* Only clients WITH findings have an artifact -- for
                          all others there is nothing to decide. */}
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
                            <FileSearch size={13} /> {tr('table.artifact')}
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
          {tr('actors.capped', { shown: formatCount(actors.length), total: formatCount(data.total) })}
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
