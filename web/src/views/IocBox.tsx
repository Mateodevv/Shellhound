// IocBox.tsx -- the indicators of the case: collect, tag, annotate, export.
import { useT } from '../i18n'
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AtSign, Box, ChevronDown, ChevronRight, Download, FileDigit, Fingerprint,
  Globe, Link2, Plus, Share2, Trash2, User,
} from 'lucide-react'
import { api, del, downloadUrl, patch, post, type Ioc } from '../api'
import { formatCount } from '../format'
import {
  Button, Chip, Card, CopyButton, EmptyState, IocTag, SearchInput,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { IpFlag } from '../components/IpFlag'
import { EnrichPanel } from '../components/Enrich'
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

export function IocBox({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const { data: iocs } = useQuery({
    queryKey: ['iocs', slug],
    queryFn: () => api<Ioc[]>(`/api/cases/${slug}/iocs`),
  })
  // Hide switches as everywhere: a click hides the type resp. the tag, the
  // next click brings it back, several of them stack.
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set())
  const [hiddenTags, setHiddenTags] = useState<Set<string>>(new Set())
  const [search, setSearch] = useState('')
  const [newValue, setNewValue] = useState('')
  const [newNote, setNewNote] = useState('')
  // Expanded neighbourhoods, and the briefly highlighted entry that was
  // just jumped to.
  const [opened, setOpened] = useState<Set<number>>(new Set())
  const [flash, setFlash] = useState<number | null>(null)

  // A jump is only a jump when one notices at the destination that one has
  // arrived: in a list of 40 identical-looking rows a silent scroll would be
  // the same as nothing at all.
  const jumpTo = (id: number) => {
    setFlash(id)
    document.getElementById(`ioc-${id}`)
      ?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    window.setTimeout(() => setFlash((cur) => (cur === id ? null : cur)), 1800)
  }

  const toggleOpen = (id: number) => setOpened((prev) => {
    const next = new Set(prev)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    return next
  })

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
  // the confirmed finds along that happen to carry both.
  const filtered = useMemo(() => (iocs ?? []).filter((i) =>
    !hiddenTypes.has(i.type) &&
    !(i.tags.length > 0 && i.tags.every((tg) => hiddenTags.has(tg))) &&
    (!search || i.value.toLowerCase().includes(search.toLowerCase()) ||
      i.note.toLowerCase().includes(search.toLowerCase()))),
    [iocs, hiddenTypes, hiddenTags, search])

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
          {([
            ['csv', tr('export.csv.hint')],
            ['json', tr('export.json.hint')],
            ['stix', tr('export.stix.hint')],
          ] as const).map(([fmt, hint]) => (
            <Tooltip key={fmt} title={tr('export.as', { fmt: fmt.toUpperCase() })} hint={hint}>
              <a
                className="inline-flex items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2.5 py-1.5 text-[12px] font-medium uppercase hover:border-[var(--accent)]/60"
                href={downloadUrl(`/api/cases/${slug}/iocs/export?format=${fmt}`)}
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
          Aufnehmen
        </Button>
      </Card>

      <div className="flex flex-col gap-1.5">
        {filtered.map((ioc) => {
          const Icon = TYPE_ICON[ioc.type] ?? Box
          const links = ioc.links ?? []
          const open = opened.has(ioc.id)
          return (
            <Card key={ioc.id} id={`ioc-${ioc.id}`}
              className={`group flex flex-col animate-fade-in transition-shadow ${
                flash === ioc.id ? 'ring-2 ring-[var(--accent)]' : ''}`}>
            <div className="flex items-center gap-3 px-4 py-2.5">
              <Icon size={15} className="shrink-0 text-[var(--muted)]" />
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
              {/* The value travels from here into a ticket, a firewall rule
                  or a search box. Typing it out would be a source of errors
                  for a SHA-256, and selecting it fails on the truncate. */}
              <CopyButton value={ioc.value} label={tr('iocbox.copy')}
                className="shrink-0" />
              {links.length > 0 && (
                <Tooltip title={tr('iocbox.links.title')}
                  body={links.map((l) => `${l.label} ${l.value}`).join(' · ')}
                  hint={tr('iocbox.links.hint')}>
                  <button
                    onClick={() => toggleOpen(ioc.id)}
                    className={`flex shrink-0 items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] transition-colors ${
                      open ? 'border-[var(--accent)]/60 text-[var(--fg)]'
                           : 'border-[var(--line)] text-[var(--muted)] hover:border-[var(--accent)]/60'}`}
                  >
                    {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                    <Share2 size={11} /> {links.length}
                  </button>
                </Tooltip>
              )}
              <div className="flex max-w-[280px] flex-wrap justify-end gap-1">
                {ioc.tags.map((t) => <IocTag key={t} tag={t} tone={TAG_TONE[t]} />)}
              </div>
              <input
                defaultValue={ioc.note}
                key={`${ioc.id}-${ioc.note}`}
                placeholder={ioc.origin || tr('iocbox.note.short')}
                onBlur={(e) => {
                  if (e.target.value !== ioc.note)
                    saveNote.mutate({ id: ioc.id, note: e.target.value })
                }}
                className="w-64 shrink-0 rounded-md border border-transparent bg-transparent px-2 py-1 text-[12px] text-[var(--muted)] outline-none transition-colors focus:border-[var(--accent)]/60 focus:bg-[var(--panel-2)] focus:text-[var(--fg)]"
                title={ioc.origin}
              />
              <Button variant="ghost" title={tr('common.remove')}
                className="opacity-0 transition-opacity group-hover:opacity-100"
                onClick={() => remove.mutate(ioc.id)}>
                <Trash2 size={13} />
              </Button>
            </div>
            {/* Only hashes and addresses can be asked about outside. A path
                would name the server, a login would name a person -- neither
                belongs in someone else's database. */}
            {(ioc.type === 'hash' || ioc.type === 'ip') && (
              <div className="border-t border-[var(--line)] px-4 py-2">
                <EnrichPanel slug={slug} kind={ioc.type} value={ioc.value} />
              </div>
            )}
            {open && (
              <div className="flex flex-col gap-1 border-t border-[var(--line)] px-4 py-2">
                {links.map((l) => {
                  const LinkIcon = TYPE_ICON[l.type] ?? Box
                  return (
                    <button key={`${l.kind}-${l.id}`} onClick={() => jumpTo(l.id)}
                      className="flex items-center gap-2 rounded-md px-1 py-0.5 text-left transition-colors hover:bg-[var(--panel-2)]">
                      <LinkIcon size={12} className="shrink-0 text-[var(--muted)]" />
                      <span className="shrink-0 text-[12px] text-[var(--muted)]">
                        {l.label}
                      </span>
                      <span className="mono min-w-0 truncate text-[12px]" title={l.value}>
                        {l.value}
                      </span>
                      {l.note && (
                        <span className="shrink-0 text-[11px] text-[var(--muted)]">
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
    </div>
  )
}
