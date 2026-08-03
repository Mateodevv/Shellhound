// IocBox.tsx — die Fall-Indikatoren: sammeln, taggen, annotieren, exportieren.
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AtSign, Box, Download, FileDigit, Fingerprint, Globe, Link2, Plus,
  Trash2, User,
} from 'lucide-react'
import { api, del, downloadUrl, patch, post, type Ioc } from '../api'
import { formatCount } from '../format'
import { Button, Chip, Card, EmptyState, IocTag, SearchInput } from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { IOC_TYPE_EXPLAIN } from '../explain'
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
  const qc = useQueryClient()
  const { data: iocs } = useQuery({
    queryKey: ['iocs', slug],
    queryFn: () => api<Ioc[]>(`/api/cases/${slug}/iocs`),
  })
  const [typeFilter, setTypeFilter] = useState('')
  const [tagFilter, setTagFilter] = useState('')
  const [search, setSearch] = useState('')
  const [newValue, setNewValue] = useState('')
  const [newNote, setNewNote] = useState('')

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

  const filtered = useMemo(() => (iocs ?? []).filter((i) =>
    (!typeFilter || i.type === typeFilter) &&
    (!tagFilter || i.tags.includes(tagFilter)) &&
    (!search || i.value.toLowerCase().includes(search.toLowerCase()) ||
      i.note.toLowerCase().includes(search.toLowerCase()))),
    [iocs, typeFilter, tagFilter, search])

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
        <Tooltip title="IOC Box — die Indikatoren dieses Falls"
          body="Alles, woran man den Vorfall wiedererkennt: Angreifer-IPs, Datei-Hashes, Shell-Pfade, eingeschleuste Domains."
          hint="Bestätigte Findings landen automatisch hier. Am Ende exportierst du die Liste für den Bericht oder ein SIEM.">
          <h1 className="mr-2 text-lg font-bold">IOC Box</h1>
        </Tooltip>
        {Object.entries(typeCounts).map(([t, n]) => (
          <Tooltip key={t} body={IOC_TYPE_EXPLAIN[t]}>
            <Chip active={typeFilter === t}
              onClick={() => setTypeFilter(typeFilter === t ? '' : t)} count={n}>
              {t}
            </Chip>
          </Tooltip>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <SearchInput value={search} onChange={setSearch} placeholder="Wert oder Notiz…" />
          {([
            ['csv', 'Tabelle für Excel und den Bericht.'],
            ['json', 'Maschinenlesbar — für eigene Skripte.'],
            ['stix', 'STIX 2.1 — das Austauschformat für SIEM- und Threat-Intel-Systeme.'],
          ] as const).map(([fmt, hint]) => (
            <Tooltip key={fmt} title={`Export als ${fmt.toUpperCase()}`} hint={hint}>
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
          <span className="text-[11px] uppercase tracking-wider text-[var(--muted)]">Tags:</span>
          {Object.entries(tagCounts).sort((a, b) => b[1] - a[1]).map(([t, n]) => (
            <Chip key={t} active={tagFilter === t}
              onClick={() => setTagFilter(tagFilter === t ? '' : t)} count={n}>
              {t}
            </Chip>
          ))}
        </div>
      )}

      <Card className="flex flex-wrap items-center gap-2 px-4 py-3">
        <Plus size={15} className="text-[var(--muted)]" />
        <input
          value={newValue}
          onChange={(e) => setNewValue(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && newValue.trim()) add.mutate() }}
          placeholder="IOC hinzufügen — IP, Hash, Domain, Pfad… (Typ wird erkannt)"
          className="mono min-w-64 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
        />
        <input
          value={newNote}
          onChange={(e) => setNewNote(e.target.value)}
          placeholder="Notiz (optional)"
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
          return (
            <Card key={ioc.id} className="group flex items-center gap-3 px-4 py-2.5 animate-fade-in">
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
              <span className="mono min-w-0 flex-1 truncate text-[13px]" title={ioc.value}>
                {ioc.value}
              </span>
              <div className="flex max-w-[280px] flex-wrap justify-end gap-1">
                {ioc.tags.map((t) => <IocTag key={t} tag={t} tone={TAG_TONE[t]} />)}
              </div>
              <input
                defaultValue={ioc.note}
                key={`${ioc.id}-${ioc.note}`}
                placeholder={ioc.origin || 'Notiz…'}
                onBlur={(e) => {
                  if (e.target.value !== ioc.note)
                    saveNote.mutate({ id: ioc.id, note: e.target.value })
                }}
                className="w-64 shrink-0 rounded-md border border-transparent bg-transparent px-2 py-1 text-[12px] text-[var(--muted)] outline-none transition-colors focus:border-[var(--accent)]/60 focus:bg-[var(--panel-2)] focus:text-[var(--fg)]"
                title={ioc.origin}
              />
              <Button variant="ghost" title="Entfernen"
                className="opacity-0 transition-opacity group-hover:opacity-100"
                onClick={() => remove.mutate(ioc.id)}>
                <Trash2 size={13} />
              </Button>
            </Card>
          )
        })}
      </div>

      {iocs && !iocs.length && (
        <EmptyState icon={<Box size={36} />} title="Die IOC Box ist leer"
          sub="Bestätigte Findings landen automatisch hier (Pfad + Hash + anfragende Clients). Actors lassen sich aus der Actors-View einsammeln, alles Weitere oben manuell." />
      )}
      {iocs && iocs.length > 0 && (
        <div className="text-[12px] text-[var(--muted)]">
          {formatCount(filtered.length)} von {formatCount(iocs.length)} Indikatoren
        </div>
      )}
    </div>
  )
}
