// CommandPalette.tsx -- ONE field across the whole case (Ctrl+K).
//
// With nine views, "where was that again…" turns into real friction, and the
// answer always sits in exactly one of them. The palette is a SPRINGBOARD,
// not a result list: every group is hard-capped, and a hit either opens the
// artifact window directly or jumps into the view.
import { useT } from '../i18n'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { Box, CornerDownLeft, Search, User, Users } from 'lucide-react'
import { api } from '../api'
import { formatCount } from '../format'
import { KIND_ICON } from '../artifactKinds'
import { SeverityBadge, TriageBadge } from './ui'
import type { ArtifactStub } from './ArtifactWindow'
import type { ViewId } from '../App'

interface SearchData {
  artifacts: { artifact: string; artifact_kind: string; worst: number
               triage: string; findings: number }[]
  iocs: { id: number; value: string; type: string; note: string }[]
  actors: { ip: string; requests: number; alerts: number }[]
  accounts: { id: number; login: string; email: string; admin: number; tbl: string }[]
}

interface Item {
  key: string
  group: string
  render: React.ReactNode
  run: () => void
}

export function CommandPalette({ slug, open, onClose, gotoView, onOpenArtifact }: {
  slug: string
  open: boolean
  onClose: () => void
  gotoView: (v: ViewId) => void
  onOpenArtifact: (stub: ArtifactStub) => void
}) {
  const tr = useT()
  const [q, setQ] = useState('')
  const [cursor, setCursor] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (open) {
      setQ('')
      setCursor(0)
      // Focus after rendering -- the palette is a keyboard affair.
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [open])

  const { data } = useQuery({
    queryKey: ['search', slug, q],
    queryFn: () => api<SearchData>(
      `/api/cases/${slug}/search?q=${encodeURIComponent(q)}`),
    enabled: open && q.trim().length >= 2,
    // NO PLACEHOLDER ACROSS A NEW KEY. `placeholderData: prev => prev`
    // hands the previous query's data to the next one -- including to the
    // empty query the palette resets to when it opens, so it listed the last
    // search's results under an empty box and Enter opened one of them.
    // Keeping it only while the box has content preserves what it is for:
    // no flicker between keystrokes.
    placeholderData: (prev) => (q.trim().length >= 2 ? prev : undefined),
  })

  const items = useMemo<Item[]>(() => {
    if (!data) return []
    const out: Item[] = []
    for (const a of data.artifacts) {
      const Icon = KIND_ICON[a.artifact_kind] ?? Box
      out.push({
        key: `art:${a.artifact}`,
        group: tr('nav.findings'),
        render: (
          <>
            <Icon size={14} className="shrink-0 text-[var(--muted)]" />
            <span className="mono min-w-0 flex-1 truncate">{a.artifact}</span>
            <SeverityBadge severity={a.worst} />
            <TriageBadge state={a.triage} label={tr(`triage.${a.triage}`)} />
          </>
        ),
        run: () => onOpenArtifact({
          artifact: a.artifact,
          artifact_kind: a.artifact_kind as ArtifactStub['artifact_kind'],
          worst: a.worst, triage: a.triage as ArtifactStub['triage'],
          triage_note: '',
        }),
      })
    }
    for (const a of data.actors) {
      out.push({
        key: `actor:${a.ip}`,
        group: tr('nav.actors'),
        render: (
          <>
            <Users size={14} className="shrink-0 text-[var(--muted)]" />
            <span className="mono min-w-0 flex-1 truncate">{a.ip}</span>
            <span className="shrink-0 text-[11px] tabular text-[var(--muted)]">
              {tr('palette.requests', { n: formatCount(a.requests) })}
              {a.alerts > 0
                && ` · ${tr('palette.alerts', { n: formatCount(a.alerts) })}`}
            </span>
          </>
        ),
        // An actor IS the client artifact -- the same window as everywhere.
        run: () => onOpenArtifact({
          artifact: a.ip, artifact_kind: 'client', worst: 3,
          triage: 'new', triage_note: '',
        }),
      })
    }
    for (const i of data.iocs) {
      out.push({
        key: `ioc:${i.id}`,
        group: tr('nav.iocbox'),
        render: (
          <>
            <Box size={14} className="shrink-0 text-[var(--muted)]" />
            <span className="shrink-0 text-[10px] uppercase text-[var(--muted)]">{i.type}</span>
            <span className="mono min-w-0 flex-1 truncate">{i.value}</span>
          </>
        ),
        run: () => gotoView('iocbox'),
      })
    }
    for (const a of data.accounts) {
      out.push({
        key: `acc:${a.id}`,
        group: tr('nav.database'),
        render: (
          <>
            <User size={14} className="shrink-0 text-[var(--muted)]" />
            <span className="mono min-w-0 truncate">{a.login}</span>
            {a.admin === 1 && (
              <span className="shrink-0 text-[10px] uppercase text-[var(--sev-high)]">Admin</span>
            )}
            <span className="min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]">
              {a.email}
            </span>
          </>
        ),
        run: () => gotoView('database'),
      })
    }
    return out
  }, [data, gotoView, onOpenArtifact, tr])

  useEffect(() => { setCursor(0) }, [items.length, q])

  if (!open) return null

  const pick = (item: Item) => {
    onClose()
    item.run()
  }

  return (
    <div className="fixed inset-0 z-[90] flex items-start justify-center bg-black/45 pt-[14vh]"
      onMouseDown={onClose}>
      <div
        className="w-[620px] max-w-[92vw] overflow-hidden rounded-xl border border-[var(--line)] bg-[var(--panel)] shadow-2xl animate-fade-up"
        onMouseDown={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-[var(--line)] px-4 py-3">
          <Search size={15} className="shrink-0 text-[var(--muted)]" />
          <input
            ref={inputRef}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') onClose()
              else if (e.key === 'ArrowDown') {
                e.preventDefault()
                setCursor((c) => Math.min(items.length - 1, c + 1))
              } else if (e.key === 'ArrowUp') {
                e.preventDefault()
                setCursor((c) => Math.max(0, c - 1))
              } else if (e.key === 'Enter' && items[cursor]) {
                pick(items[cursor])
              }
            }}
            placeholder={tr('palette.placeholder')}
            className="min-w-0 flex-1 bg-transparent text-[14px] outline-none placeholder:text-[var(--muted)]"
          />
          <span className="shrink-0 rounded border border-[var(--line)] px-1.5 py-0.5 text-[10px] text-[var(--muted)]">
            Esc
          </span>
        </div>

        <div className="max-h-[52vh] overflow-y-auto py-1">
          {items.map((item, i) => {
            const prev = items[i - 1]
            return (
              <div key={item.key}>
                {(!prev || prev.group !== item.group) && (
                  <div className="px-4 pb-0.5 pt-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                    {item.group}
                  </div>
                )}
                <button
                  onClick={() => pick(item)}
                  onMouseEnter={() => setCursor(i)}
                  className={clsx(
                    'flex w-full cursor-pointer items-center gap-2 px-4 py-1.5 text-left text-[12.5px]',
                    i === cursor ? 'bg-[var(--accent-soft)]' : 'hover:bg-[var(--panel-2)]')}>
                  {item.render}
                  {i === cursor && (
                    <CornerDownLeft size={12} className="shrink-0 text-[var(--muted)]" />
                  )}
                </button>
              </div>
            )
          })}
          {q.trim().length >= 2 && data && !items.length && (
            <div className="px-4 py-6 text-center text-[13px] text-[var(--muted)]">
              {tr('palette.nothing')}
            </div>
          )}
          {q.trim().length < 2 && (
            <div className="px-4 py-6 text-center text-[12px] text-[var(--muted)]">
              {tr('palette.scope')}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
