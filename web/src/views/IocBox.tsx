// IocBox.tsx -- the indicators of the case: collect, tag, annotate, export.
import { useT } from '../i18n'
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AtSign, Box, ChevronDown, ChevronRight, CornerDownRight, Crosshair,
  Download, FileDigit, Fingerprint, Globe, Link2, Plus, Radar, Share2,
  ShieldOff, Trash2, TriangleAlert, User,
} from 'lucide-react'
import {
  api, del, downloadUrl, patch, post, type CrossCaseIocMatch,
  type CrossCaseIocResponse, type Ioc,
} from '../api'
import { formatCount } from '../format'
import {
  Button, Chip, Card, CopyButton, EmptyState, IocTag, SearchInput,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { IpFlag } from '../components/IpFlag'
import { EnrichPanel } from '../components/Enrich'
import { TraceWindow } from '../components/TraceWindow'
import type { ViewId } from '../App'

const TYPE_ICON: Record<string, typeof Globe> = {
  ip: Globe, hash: Fingerprint, url: Link2, domain: Globe, email: AtSign,
  path: FileDigit, user: User, other: Box,
}

const TAG_TONE: Record<string, 'danger' | 'warn' | 'accent' | undefined> = {
  confirmed: 'danger', webshell: 'danger', successful: 'danger',
  'injected-code': 'danger',
  'brute-force': 'warn', scanner: 'warn', 'threat-list': 'warn',
  finding: 'accent', analyst: 'accent', hunt: undefined, actor: undefined,
  derived: undefined,
}

// Provenance repeats on almost every row -- everything collected via a
// confirmation carries `confirmed finding`, so as loud chips these tags
// separate nothing. They shrink to quiet text; what the case OBSERVED about
// the indicator (successful, brute-force, scanner) and what KIND it is
// (webshell, injected-code) keeps the colour and the front seat.
const PROVENANCE_TAGS = new Set([
  'analyst', 'finding', 'confirmed', 'hunt', 'actor', 'derived',
])

/** hxxps://evil[.]test -- pasteable into a ticket without anything turning
 *  into a link. Only shapes a mail client would linkify get the treatment;
 *  hashes, paths and logins are inert as they are. */
export function defang(value: string, type: string): string {
  let v = value
  if (type === 'url') v = v.replace(/^http(s?):\/\//i, 'hxxp$1://')
  if (type === 'ip' || type === 'domain' || type === 'url') {
    v = v.replace(/\./g, '[.]')
  }
  if (type === 'email') v = v.replace(/\./g, '[.]').replace(/@/g, '[at]')
  return v
}

const DEFANGABLE = new Set(['ip', 'url', 'domain', 'email'])

/** The tail that still identifies a long value at a glance: hashes keep
 *  head and tail, paths keep their file name end. */
function shortValue(value: string): string {
  return value.length > 26 ? `${value.slice(0, 10)}…${value.slice(-10)}` : value
}

export function IocBox({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const { data: iocs } = useQuery({
    queryKey: ['iocs', slug],
    queryFn: () => api<Ioc[]>(`/api/cases/${slug}/iocs`),
  })
  const { data: crossCase } = useQuery({
    queryKey: ['iocs', 'cross-case', slug],
    queryFn: () => api<CrossCaseIocResponse>(`/api/cases/${slug}/iocs/cross-case`),
  })
  // Hide switches as everywhere: a click hides the type resp. the tag, the
  // next click brings it back, several of them stack.
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set())
  const [hiddenTags, setHiddenTags] = useState<Set<string>>(new Set())
  const [search, setSearch] = useState('')
  const [newValue, setNewValue] = useState('')
  const [newNote, setNewNote] = useState('')
  // Expanded link sections and reputation panels, the briefly highlighted
  // entry that was just jumped to, the armed delete button, and the address
  // whose trace is open.
  const [opened, setOpened] = useState<Set<number>>(new Set())
  const [enrichOpen, setEnrichOpen] = useState<Set<number>>(new Set())
  const [flash, setFlash] = useState<number | null>(null)
  const [armed, setArmed] = useState<number | null>(null)
  const [traceIp, setTraceIp] = useState<string | null>(null)
  // The cross-case section: folded by default -- another case is context,
  // not this case's work list -- and unfolded either from its bar or from
  // the badge on the matching entry, which flashes its line up here.
  const [crossOpen, setCrossOpen] = useState(false)
  const [crossFlash, setCrossFlash] = useState<number | null>(null)

  const toggleIn = (setter: typeof setOpened) => (id: number) =>
    setter((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const toggleOpen = toggleIn(setOpened)
  const toggleEnrich = toggleIn(setEnrichOpen)

  const invalidate = () => qc.invalidateQueries({ queryKey: ['iocs'] })
  const add = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/iocs`, { value: newValue, note: newNote }),
    onSuccess: () => { setNewValue(''); setNewNote(''); invalidate() },
  })
  const remove = useMutation({
    mutationFn: (id: number) => del(`/api/cases/${slug}/iocs/${id}`),
    onSuccess: invalidate,
  })
  const saveNote = useMutation({
    mutationFn: (v: { id: number; note: string }) =>
      patch(`/api/cases/${slug}/iocs/${v.id}`, { note: v.note }),
    onSuccess: invalidate,
  })
  const saveType = useMutation({
    mutationFn: (v: { id: number; type: string }) =>
      patch(`/api/cases/${slug}/iocs/${v.id}`, { type: v.type }),
    onSuccess: invalidate,
  })

  // An IOC disappears when its type is hidden, or EVERY one of its tags --
  // an entry with one visible tag stays, otherwise hiding "hunt" would drag
  // the confirmed finds along that happen to carry both. The search reads
  // ORIGIN too: "which of these came out of hunt X" is a question about
  // provenance, and provenance lives there.
  const filtered = useMemo(() => (iocs ?? []).filter((i) =>
    !hiddenTypes.has(i.type) &&
    !(i.tags.length > 0 && i.tags.every((tg) => hiddenTags.has(tg))) &&
    (!search || i.value.toLowerCase().includes(search.toLowerCase()) ||
      i.note.toLowerCase().includes(search.toLowerCase()) ||
      i.origin.toLowerCase().includes(search.toLowerCase()))),
    [iocs, hiddenTypes, hiddenTags, search])

  // A hash whose file sits right here is an ATTRIBUTE of that file, not a
  // neighbour somewhere in the list -- it lives inside the file card's
  // linked section, folded by default. Only under a VISIBLE file: filter
  // the file away and the hash stands on its own feet again rather than
  // vanishing with it.
  const { roots, docked, dockParent } = useMemo(() => {
    const visible = new Set(filtered.map((i) => i.id))
    const byId = new Map(filtered.map((i) => [i.id, i]))
    const docked = new Map<number, Ioc[]>()
    const dockParent = new Map<number, number>()
    for (const i of filtered) {
      if (i.type !== 'hash') continue
      const file = (i.links ?? []).find(
        (l) => l.kind === 'hash-of' && l.type === 'path' && visible.has(l.id))
      if (file && byId.has(file.id)) {
        docked.set(file.id, [...(docked.get(file.id) ?? []), i])
        dockParent.set(i.id, file.id)
      }
    }
    return { roots: filtered.filter((i) => !dockParent.has(i.id)), docked, dockParent }
  }, [filtered])

  // A jump is only a jump when one notices at the destination that one has
  // arrived. A docked target sits folded inside its file's card, so the
  // jump unfolds that card first and scrolls after the browser painted it.
  const jumpTo = (id: number) => {
    const parent = dockParent.get(id)
    if (parent != null) setOpened((prev) => new Set(prev).add(parent))
    setFlash(id)
    window.setTimeout(() => {
      document.getElementById(`ioc-${id}`)
        ?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    }, parent != null ? 80 : 0)
    window.setTimeout(() => setFlash((cur) => (cur === id ? null : cur)), 1800)
  }

  const typeCounts = useMemo(() => {
    const out: Record<string, number> = {}
    for (const i of iocs ?? []) out[i.type] = (out[i.type] ?? 0) + 1
    return out
  }, [iocs])

  const tagCounts = useMemo(() => {
    const out: Record<string, number> = {}
    for (const i of iocs ?? []) for (const t of i.tags) out[t] = (out[t] ?? 0) + 1
    return out
  }, [iocs])

  const caseHref = (otherSlug: string) => {
    const url = new URL(location.href)
    url.searchParams.set('case', otherSlug)
    return url.toString()
  }

  // Which of THIS case's entries other cases also carry -- so the badge can
  // sit on the entry itself, where the analyst is looking, instead of only
  // in a summary block they have to cross-reference by value.
  const crossByIoc = useMemo(() => {
    const out = new Map<number, CrossCaseIocMatch[]>()
    for (const entry of crossCase?.entries ?? []) out.set(entry.id, entry.matches)
    return out
  }, [crossCase])

  const jumpToCross = (id: number) => {
    setCrossOpen(true)
    setCrossFlash(id)
    window.setTimeout(() => {
      document.getElementById(`cross-${id}`)
        ?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    }, 80)
    window.setTimeout(() => setCrossFlash((cur) => (cur === id ? null : cur)), 1800)
  }

  // The export ships what the analyst is LOOKING at, with the same filter
  // semantics the view applies -- and says so beside the buttons, because a
  // file that silently carries less (or more) than the screen is a file
  // nobody can trust.
  const filterActive = hiddenTypes.size > 0 || hiddenTags.size > 0 || !!search.trim()
  const exportQuery = () => {
    const p = new URLSearchParams()
    if (hiddenTypes.size) p.set('hide_types', [...hiddenTypes].join(','))
    if (hiddenTags.size) p.set('hide_tags', [...hiddenTags].join(','))
    if (search.trim()) p.set('search', search.trim())
    const q = p.toString()
    return q ? `&${q}` : ''
  }

  /** One indicator's interactive row -- the same anatomy whether it stands
   *  as a card of its own or docked inside its file's linked section. */
  const iocRow = (ioc: Ioc, docked: boolean) => {
    const Icon = TYPE_ICON[ioc.type] ?? Box
    return (
      <div className="flex items-center gap-3">
        <Icon size={docked ? 13 : 15} className="shrink-0 text-[var(--muted)]" />
        <select
          value={ioc.type}
          onChange={(e) => saveType.mutate({ id: ioc.id, type: e.target.value })}
          className="shrink-0 rounded-md border border-transparent bg-transparent px-1 py-0.5 text-[11px] uppercase text-[var(--muted)] outline-none transition-colors hover:border-[var(--line)] cursor-pointer"
        >
          {['ip', 'hash', 'url', 'domain', 'email', 'path', 'user', 'other'].map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <span className="mono flex min-w-0 flex-1 items-center gap-1.5 truncate text-[13px]" title={ioc.value}>
          {ioc.type === 'ip' && <IpFlag ip={ioc.value} />}
          <span className="min-w-0 truncate">{ioc.value}</span>
        </span>
        {/* When the address was ACTIVE -- the recipient's first question
            about an indicator, and the log index has known the answer all
            along. Dates in the log's own local time. */}
        {ioc.first_seen && (
          <Tooltip title={tr('iocbox.span.title')} body={tr('iocbox.span.body')}>
            <span className="shrink-0 text-[11px] text-[var(--muted)]">
              {ioc.first_seen === ioc.last_seen
                ? ioc.first_seen
                : `${ioc.first_seen} – ${ioc.last_seen}`}
            </span>
          </Tooltip>
        )}
        {/* Other cases carry this very value. Said on the entry itself,
            where the analyst is looking -- the summary bar above is the
            overview, this is the pointer into it. */}
        {crossByIoc.has(ioc.id) && (
          <Tooltip title={tr('cross.title')}
            body={crossByIoc.get(ioc.id)!
              .map((m) => m.name || m.slug).join(' · ')}
            hint={tr('cross.badge.hint')}>
            <button
              onClick={() => jumpToCross(ioc.id)}
              aria-label={tr('cross.title')}
              className="flex shrink-0 cursor-pointer items-center gap-1 rounded-md border border-[var(--accent)]/40 px-1.5 py-0.5 text-[11px] text-[var(--accent-text)] transition-colors hover:border-[var(--accent)]">
              <Share2 size={11} />
              {crossByIoc.get(ioc.id)!.length}
            </button>
          </Tooltip>
        )}
        {/* The value travels from here into a ticket, a firewall rule or a
            search box. Typing it out would be a source of errors for a
            SHA-256, and selecting it fails on the truncate. */}
        <CopyButton value={ioc.value} label={tr('iocbox.copy')}
          className="shrink-0" />
        {/* The same value with nothing clickable in it, for mails and
            tickets: hxxps://evil[.]test cannot be visited by accident. */}
        {DEFANGABLE.has(ioc.type) && (
          <CopyButton value={defang(ioc.value, ioc.type)}
            label={tr('iocbox.copy.defanged')}
            icon={<ShieldOff size={13} />}
            className="shrink-0" />
        )}
        {ioc.type === 'ip' && (
          <Tooltip hint={tr('iocbox.trace.hint')}>
            <button
              onClick={() => setTraceIp(ioc.value)}
              className="shrink-0 cursor-pointer rounded-md border border-transparent p-1 text-[var(--muted)] transition-colors hover:border-[var(--accent)]/60 hover:text-[var(--fg)]"
              aria-label={tr('iocbox.trace')}>
              <Crosshair size={13} />
            </button>
          </Tooltip>
        )}
        {/* Reputation is a lookup, not wallpaper: the panel used to stand
            open under every address and hash and halved how much of the
            case fits on a screen. */}
        {(ioc.type === 'hash' || ioc.type === 'ip') && (
          <Tooltip hint={tr('iocbox.enrich.hint')}>
            <button
              onClick={() => toggleEnrich(ioc.id)}
              aria-label={tr('iocbox.enrich')}
              className={`shrink-0 cursor-pointer rounded-md border p-1 transition-colors ${
                enrichOpen.has(ioc.id)
                  ? 'border-[var(--accent)]/60 text-[var(--fg)]'
                  : 'border-transparent text-[var(--muted)] hover:border-[var(--accent)]/60 hover:text-[var(--fg)]'}`}>
              <Radar size={13} />
            </button>
          </Tooltip>
        )}
        <div className="flex max-w-[280px] flex-wrap items-center justify-end gap-1">
          {ioc.tags.filter((t) => !PROVENANCE_TAGS.has(t)).map((t) => (
            <IocTag key={t} tag={t} tone={TAG_TONE[t]} />
          ))}
          {ioc.tags.filter((t) => PROVENANCE_TAGS.has(t)).map((t) => (
            <span key={t}
              className="rounded px-1 py-0.5 text-[10px] text-[var(--muted)] opacity-80">
              {t}
            </span>
          ))}
        </div>
        <input
          defaultValue={ioc.note}
          key={`${ioc.id}-${ioc.note}`}
          placeholder={tr('iocbox.note.short')}
          onBlur={(e) => {
            if (e.target.value !== ioc.note)
              saveNote.mutate({ id: ioc.id, note: e.target.value })
          }}
          className={`${docked ? 'w-40' : 'w-56'} shrink-0 rounded-md border border-transparent bg-transparent px-2 py-1 text-[12px] text-[var(--muted)] outline-none transition-colors focus:border-[var(--accent)]/60 focus:bg-[var(--panel-2)] focus:text-[var(--fg)]`}
        />
        {/* Armed on the first click, gone on the second: deleting an entry
            takes its note and its provenance with it, and there is no
            restore that could bring the edges back. */}
        <Button variant={armed === ioc.id ? 'danger' : 'ghost'}
          title={tr('common.remove')}
          className={armed === ioc.id
            ? 'shrink-0'
            : 'shrink-0 opacity-0 transition-opacity group-hover:opacity-100'}
          onClick={() => {
            if (armed === ioc.id) { remove.mutate(ioc.id); setArmed(null) }
            else setArmed(ioc.id)
          }}
          onMouseLeave={() => { if (armed === ioc.id) setArmed(null) }}>
          {armed === ioc.id
            ? <span className="text-[11px] font-semibold">{tr('iocbox.delete.sure')}</span>
            : <Trash2 size={13} />}
        </Button>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-1 flex items-center gap-1.5 text-lg font-bold">
          IOC Box
          <InfoDot title={tr('iocbox.title.what')}
            body={tr('iocbox.title.body')}
            hint={tr('iocbox.title.hint')} />
        </h1>
        {Object.entries(typeCounts).map(([t, n]) => (
          <Tooltip key={t} body={tr(`iocType.${t}`)}
            hint={hiddenTypes.has(t) ? tr('filter.hidden.back')
                                     : tr('iocbox.type.hide')}>
            <Chip active={false} dimmed={hiddenTypes.has(t)}
              onClick={() => setHiddenTypes((prev) => {
                const next = new Set(prev)
                if (next.has(t)) next.delete(t)
                else next.add(t)
                return next
              })} count={n}>
              {t}
            </Chip>
          </Tooltip>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder={tr('iocbox.search')} />
          {filterActive && iocs && (
            <span className="text-[11px] text-[var(--muted)]">
              {tr('iocbox.export.filtered', {
                shown: formatCount(filtered.length),
                total: formatCount(iocs.length),
              })}
            </span>
          )}
          {([
            ['csv', tr('export.csv.hint')],
            ['json', tr('export.json.hint')],
            ['stix', tr('export.stix.hint')],
          ] as const).map(([fmt, hint]) => (
            <Tooltip key={fmt} title={tr('export.as', { fmt: fmt.toUpperCase() })} hint={hint}>
              <a
                className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2.5 py-1.5 text-[12px] font-medium uppercase hover:border-[var(--accent)]/60"
                href={downloadUrl(`/api/cases/${slug}/iocs/export?format=${fmt}${exportQuery()}`)}
              >
                <Download size={12} /> {fmt}
              </a>
            </Tooltip>
          ))}
        </div>
      </div>

      {Object.keys(tagCounts).length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="flex items-center gap-1 text-[11px] uppercase tracking-wider text-[var(--muted)]">
            Tags:
            <InfoDot title={tr('iocbox.tags.what')}
              body={tr('iocbox.tags.body')}
              hint={tr('iocbox.tags.hint')} />
          </span>
          {Object.entries(tagCounts).sort((a, b) => b[1] - a[1]).map(([t, n]) => (
            <Tooltip key={t}
              hint={hiddenTags.has(t)
                ? tr('iocbox.tag.hidden')
                : tr('iocbox.tag.hide')}>
              <Chip active={false} dimmed={hiddenTags.has(t)}
                onClick={() => setHiddenTags((prev) => {
                  const next = new Set(prev)
                  if (next.has(t)) next.delete(t)
                  else next.add(t)
                  return next
                })} count={n}>
                {t}
              </Chip>
            </Tooltip>
          ))}
        </div>
      )}

      {/* ---- what OTHER cases carry too --------------------------------
          Folded by default: another case is context, not this case's work
          list. The bar keeps the whole statement readable while closed --
          how many indicators, how many cases, and the warning when cases
          could not be read at all -- because a fold must never hide the
          part that says what was NOT checked. */}
      {crossCase && (crossCase.matched_iocs > 0 || crossCase.cases_skipped > 0) && (
        <Card className="border-[var(--accent)]/35">
          <button
            onClick={() => setCrossOpen((v) => !v)}
            aria-expanded={crossOpen}
            className="flex w-full cursor-pointer items-center gap-2 px-4 py-2.5 text-left transition-colors hover:bg-[var(--panel-2)]"
          >
            {crossOpen ? <ChevronDown size={13} className="shrink-0 text-[var(--muted)]" />
                       : <ChevronRight size={13} className="shrink-0 text-[var(--muted)]" />}
            <Share2 size={14} className="shrink-0 text-[var(--accent-text)]" />
            <span className="shrink-0 text-[13px] font-semibold">{tr('cross.title')}</span>
            <span className="min-w-0 truncate text-[12px] text-[var(--muted)]">
              {tr('cross.summary', {
                iocs: formatCount(crossCase.matched_iocs),
                cases: formatCount(crossCase.matched_cases),
                matches: formatCount(crossCase.matches),
              })}
            </span>
            {crossCase.cases_skipped > 0 && (
              <span className="ml-auto flex shrink-0 items-center gap-1 text-[11px] text-[var(--warn)]"
                title={tr('cross.skipped', { n: formatCount(crossCase.cases_skipped) })}>
                <TriangleAlert size={12} />
                {formatCount(crossCase.cases_skipped)}
              </span>
            )}
          </button>
          {crossOpen && (
            <div className="flex flex-col gap-0.5 border-t border-[var(--line)] px-3 py-2">
              {crossCase.entries.map((entry) => {
                const EntryIcon = TYPE_ICON[entry.type] ?? Box
                return (
                  <div key={entry.id} id={`cross-${entry.id}`}
                    className={`flex flex-wrap items-center gap-2 rounded-md px-2 py-1 text-[12px] transition-shadow ${
                      crossFlash === entry.id ? 'ring-2 ring-[var(--accent)]' : ''}`}>
                    <EntryIcon size={12} className="shrink-0 text-[var(--muted)]" />
                    <span className="mono min-w-0 max-w-[380px] truncate" title={entry.value}>
                      {entry.value}
                    </span>
                    {entry.matches.map((match) => (
                      <a key={`${match.slug}-${match.id}`} href={caseHref(match.slug)}
                        title={`${match.reference || match.slug}${match.note ? ` — ${match.note}` : ''}`}
                        className="inline-flex items-center gap-1.5 rounded-md border border-[var(--line)] bg-[var(--panel-2)] px-2 py-0.5 text-[11px] transition-colors hover:border-[var(--accent)]/60">
                        <span className="max-w-[200px] truncate">{match.name || match.slug}</span>
                        {match.reference && (
                          <span className="rounded bg-[var(--panel)] px-1 text-[10px] text-[var(--muted)]">
                            {match.reference}
                          </span>
                        )}
                        <span className="text-[var(--accent-text)]">{tr('cross.open')}</span>
                      </a>
                    ))}
                  </div>
                )
              })}
              {crossCase.cases_skipped > 0 && (
                <div className="mt-1 flex items-center gap-1.5 px-2 text-[11px] text-[var(--warn)]">
                  <TriangleAlert size={12} className="shrink-0" />
                  {tr('cross.skipped', { n: formatCount(crossCase.cases_skipped) })}
                </div>
              )}
            </div>
          )}
        </Card>
      )}

      <Card className="flex flex-wrap items-center gap-2 px-4 py-3">
        <Plus size={15} className="text-[var(--muted)]" />
        <input
          value={newValue}
          onChange={(e) => setNewValue(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && newValue.trim()) add.mutate() }}
          placeholder={tr('iocbox.add.placeholder')}
          className="mono min-w-64 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
        />
        <input
          value={newNote}
          onChange={(e) => setNewNote(e.target.value)}
          placeholder={tr('iocbox.note.placeholder')}
          className="w-56 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
        />
        <Button variant="primary" disabled={!newValue.trim() || add.isPending}
          onClick={() => add.mutate()}>
          {tr('iocbox.add.button')}
        </Button>
      </Card>

      <div className="flex flex-col gap-1.5">
        {roots.map((ioc) => {
          const children = docked.get(ioc.id) ?? []
          const childIds = new Set(children.map((c) => c.id))
          // The hash-of edge to a docked child would appear twice -- once
          // as the child's own row, once as a link line. The row wins.
          const linkRows = (ioc.links ?? []).filter((l) => !childIds.has(l.id))
          const linkCount = children.length + linkRows.length
          const open = opened.has(ioc.id)
          const preview = children.length
            ? `${children[0].type} ${shortValue(children[0].value)}`
            : linkRows.length
              ? `${linkRows[0].label} ${shortValue(linkRows[0].value)}`
              : ''
          return (
            <Card key={ioc.id} id={`ioc-${ioc.id}`}
              className={`group flex flex-col animate-fade-in transition-shadow ${
                flash === ioc.id ? 'ring-2 ring-[var(--accent)]' : ''}`}>
              <div className="px-4 py-2.5">{iocRow(ioc, false)}</div>
              {/* Where it came from -- "the field that is worth something
                  six months later". It used to live as the note's
                  placeholder and vanished behind the first sentence anybody
                  wrote. */}
              {ioc.origin && (
                <div className="-mt-1.5 flex items-baseline gap-2 px-4 pb-2 pl-11 text-[11px] text-[var(--muted)]">
                  <span className="shrink-0 text-[10px] uppercase tracking-wider opacity-70">
                    {tr('iocbox.origin')}
                  </span>
                  <span className="min-w-0 truncate" title={ioc.origin}>{ioc.origin}</span>
                </div>
              )}
              {/* Only hashes and addresses can be asked about outside. A
                  path would name the server, a login would name a person --
                  neither belongs in someone else's database. */}
              {enrichOpen.has(ioc.id) && (ioc.type === 'hash' || ioc.type === 'ip') && (
                <div className="border-t border-[var(--line)] px-4 py-2">
                  <EnrichPanel slug={slug} kind={ioc.type} value={ioc.value} />
                </div>
              )}
              {/* ---- what this indicator is CONNECTED to ---------------
                  Folded by default: the edges are reference material, not
                  the work list. The bar names how many and previews the
                  first, so a folded card still says what it is holding. */}
              {linkCount > 0 && (
                <button
                  onClick={() => toggleOpen(ioc.id)}
                  aria-expanded={open}
                  className="flex w-full cursor-pointer items-center gap-2 border-t border-[var(--line)] px-4 py-1.5 text-left text-[11px] text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)] hover:text-[var(--fg)]"
                >
                  {open ? <ChevronDown size={12} className="shrink-0" />
                        : <ChevronRight size={12} className="shrink-0" />}
                  <Link2 size={11} className="shrink-0" />
                  <span className="shrink-0 font-medium">
                    {tr('iocbox.links.n', { n: formatCount(linkCount) })}
                  </span>
                  {!open && preview && (
                    <span className="mono min-w-0 truncate opacity-70">{preview}</span>
                  )}
                </button>
              )}
              {open && linkCount > 0 && (
                <div className="flex flex-col border-t border-[var(--line)] bg-[var(--panel-2)]/40 py-1 pr-3 pl-6">
                  {/* Derived indicators live HERE, as full rows: a hash is
                      an attribute of its file, not a neighbour in the list
                      -- and folded away it still keeps its note, its
                      lookup and its delete. */}
                  {children.map((child) => (
                    <div key={child.id} id={`ioc-${child.id}`}
                      className={`group flex items-stretch gap-2 rounded-md px-2 py-1 transition-shadow ${
                        flash === child.id ? 'ring-2 ring-[var(--accent)]' : ''}`}>
                      <CornerDownRight size={13}
                        className="mt-2 shrink-0 text-[var(--muted)] opacity-60" />
                      <div className="min-w-0 flex-1">
                        {iocRow(child, true)}
                        {enrichOpen.has(child.id) && child.type === 'hash' && (
                          <div className="mt-1 border-t border-[var(--line)] pt-1.5">
                            <EnrichPanel slug={slug} kind="hash" value={child.value} />
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                  {linkRows.map((l) => {
                    const LinkIcon = TYPE_ICON[l.type] ?? Box
                    return (
                      <button key={`${l.kind}-${l.id}`} onClick={() => jumpTo(l.id)}
                        title={tr('iocbox.links.hint')}
                        className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1 text-left transition-colors hover:bg-[var(--panel-2)]">
                        <CornerDownRight size={13}
                          className="shrink-0 text-[var(--muted)] opacity-60" />
                        <span className="shrink-0 text-[11px] italic text-[var(--muted)]">
                          {l.label}
                        </span>
                        <LinkIcon size={12} className="shrink-0 text-[var(--muted)]" />
                        <span className="mono min-w-0 truncate text-[12px]" title={l.value}>
                          {l.value}
                        </span>
                        {l.note && (
                          <span className="min-w-0 shrink-0 truncate text-[11px] text-[var(--muted)]">
                            — {l.note}
                          </span>
                        )}
                      </button>
                    )
                  })}
                </div>
              )}
            </Card>
          )
        })}
      </div>

      {iocs && !iocs.length && (
        <EmptyState icon={<Box size={36} />} title={tr('iocbox.empty.title')}
          sub={tr('iocbox.empty.sub')} />
      )}
      {iocs && iocs.length > 0 && (
        <div className="text-[12px] text-[var(--muted)]">
          {tr('iocbox.count', { shown: formatCount(filtered.length), total: formatCount(iocs.length) })}
        </div>
      )}

      {traceIp && (
        <TraceWindow slug={slug} ips={[traceIp]} onClose={() => setTraceIp(null)} />
      )}
    </div>
  )
}
