// CaseChain.tsx -- the chronology of the case.
//
// Every other view answers "what": which file, which client, which account.
// This one answers "in which order" -- the first paragraph of every report,
// which until now one typed out by jumping between three views and sorting
// timestamps in one's head.
//
// IT ORDERS MEASURED FACTS AND CLAIMS NO CAUSE. What stands here is an
// observation with a timestamp and a source; which of them follows from
// which is for the analyst to decide. That is why every line says WHERE the
// time comes from, and why the gaps stand as visibly as the events:
// "nothing is proven in between" is a statement of the case.
import { useT } from '../i18n'
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
import { IpFlag } from './IpFlag'

const KIND_ICON: Record<ChainEvent['kind'], typeof DoorOpen> = {
  erstkontakt: DoorOpen,
  versuch: CircleHelp,
  erfolg: FileWarning,
  alarm: AlertTriangle,
  'letzter-zugriff': LogIn,
  konto: UserPlus,
}

// Keys only: the event kinds come from the server under English names and
// are labelled here, not renamed.
const KIND_KEY: Record<ChainEvent['kind'], string> = {
  erstkontakt: 'chain.kind.firstContact',
  versuch: 'chain.kind.attempts',
  erfolg: 'chain.kind.success',
  alarm: 'chain.kind.alert',
  'letzter-zugriff': 'chain.lastActivity',
  konto: 'chain.kind.account',
}

const SOURCE_KEY: Record<ChainEvent['source'], string> = {
  log: 'chain.source.log',
  dump: 'chain.source.dump',
}

/** The clock alignment: an offset per source, set by the analyst.
 *
 *  Log server and database server can run different clocks, and with
 *  "account 03:17, first contact 09:12" a six-hour offset can turn the order
 *  of the story around. The tool does not guess -- the offset is a statement
 *  of the analyst and stands visibly in the chain. */
function ClockEditor({ slug, offsets, onClose }: {
  slug: string
  offsets: { logs: number; dump: number }
  onClose: () => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  // Operated in hours, stored in seconds: clocks diverge by time zones, not
  // by seconds -- and half hours exist (India).
  const [logs, setLogs] = useState(String(offsets.logs / 3600))
  const [dump, setDump] = useState(String(offsets.dump / 3600))
  useEffect(() => {
    setLogs(String(offsets.logs / 3600))
    setDump(String(offsets.dump / 3600))
  }, [offsets])
  // `parseFloat('abc')` is NaN, `JSON.stringify` writes that as null and the
  // server rejects the request -- so typing something unreadable silently
  // did nothing at all. The `|| '0'` only ever caught the empty string.
  const hours = (text: string) => {
    const n = parseFloat(text.replace(',', '.'))
    return Number.isFinite(n) ? Math.round(n * 3600) : null
  }
  const badInput = hours(logs) === null || hours(dump) === null

  const save = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/clock`, {
      logs: hours(logs) ?? 0,
      dump: hours(dump) ?? 0,
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
      <span className="text-[12px] font-medium">{tr('chain.clock')}</span>
      {feld(logs, setLogs, tr('chain.clock.logs'))}
      {feld(dump, setDump, tr('chain.clock.dump'))}
      <span className="text-[11px] text-[var(--muted)]">
        {tr('chain.clock.sign')}
      </span>
      <div className="ml-auto flex gap-1.5">
        <Button variant="primary" disabled={save.isPending || badInput}
          onClick={() => save.mutate()}>
          {tr('common.apply')}
        </Button>
        <Button variant="ghost" onClick={onClose}>{tr('common.cancel')}</Button>
      </div>
    </div>
  )
}

export function CaseChain({ slug, onOpen, onTrace }: {
  slug: string
  /** Open an artifact -- the same view as from Findings. */
  onOpen: (artifact: string, kind: string) => void
  onTrace: (ip: string) => void
}) {
  // It stands open because it is the first paragraph of the report.
  // Collapsing is for the cases where one wants to compare the key figures
  // above it without 40 lines in between.
  const tr = useT()
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
          {tr('chain.title')}
          <InfoDot
            title={tr('chain.title.long')}
            body={tr('chain.title.body')}
            hint={tr('chain.title.hint')} />
        </>
      }
      sub={data.events.length
        ? tr('chain.sub', { n: data.events.length, confirmed: data.confirmed, span: formatSpan(first, last) })
        : tr('chain.empty')}
      right={
        <div className="flex items-center gap-3">
          {/* The events arrive already shifted and carry no offset of their
              own, so this is the only thing that says what they mean. A
              chronology whose times do not state their zone is one nobody
              can quote. */}
          {data.events.length > 0 && (
            data.tz_mixed
              ? <Tooltip hint={tr('time.mixed.hint')}>
                  <span className="inline-flex items-center gap-1 text-[11.5px] text-[var(--sev-low)]">
                    <AlertTriangle size={12} />
                    {tr('time.mixed', { zones: data.tz_offsets.join(', ') })}
                  </span>
                </Tooltip>
              : <span className="text-[11.5px] text-[var(--muted)]">
                  {tr('time.zone', { zone: data.zone })}
                </span>
          )}
          <Tooltip title={tr('chain.clock')}
            body={tr('chain.clock.body')}
            hint={tr('chain.clock.hint')}>
            <Button variant="ghost" onClick={() => setClockOpen(!clockOpen)}>
              <Clock size={13} />
              {adjusted
                ? `${tr('chain.clocks')} ${data.offsets.logs ? `${tr('chain.clock.logs')} ${data.offsets.logs > 0 ? '+' : ''}${data.offsets.logs / 3600}h` : ''}${data.offsets.logs && data.offsets.dump ? ' · ' : ''}${data.offsets.dump ? `DB ${data.offsets.dump > 0 ? '+' : ''}${data.offsets.dump / 3600}h` : ''}`
                : tr('chain.clocks')}
            </Button>
          </Tooltip>
        </div>
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
          // Same second = one moment, not two. The time then appears only
          // once, otherwise one observation reads like two.
          const sameMoment = prev?.at === e.at
          const gapBefore = prev && e.at - prev.at > 3600
          return (
            <div key={i}>
              {gapBefore && (
                <div className="flex items-center gap-2 border-b border-[var(--line-soft)] bg-[var(--panel-2)] px-4 py-1 text-[11px] text-[var(--muted)]">
                  <span className="ml-[104px]">
                    ↕ {formatSpan(prev.at, e.at)} {tr('chain.gap')}
                  </span>
                </div>
              )}
              <div className="flex items-start gap-3 border-b border-[var(--line-soft)] px-4 py-2 last:border-0 hover:bg-[var(--panel-2)]">
                <Tooltip hint={tr(SOURCE_KEY[e.source])}>
                  <span className={clsx('mono w-[96px] shrink-0 pt-0.5 text-[11px] tabular',
                    sameMoment ? 'text-transparent' : 'text-[var(--muted)]')}>
                    {formatLogTime(e.at, 0).slice(0, 16)}
                  </span>
                </Tooltip>
                <Tooltip hint={tr(KIND_KEY[e.kind])}>
                  <Icon size={14} className={clsx('mt-0.5 shrink-0',
                    e.severity === 0 ? 'text-[var(--sev-high)]'
                      : e.severity === 1 ? 'text-[var(--sev-medium)]'
                        : 'text-[var(--muted)]')} />
                </Tooltip>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    {e.ip && <IpFlag ip={e.ip} />}
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
                      {tr('table.artifact')} <ArrowRight size={12} />
                    </button>
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </Card>

      {/* What the case does NOT prove belongs in the report just as much as
          what it does prove -- and it is written down nowhere else. */}
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
            <Database size={12} /> {tr('chain.undated')}
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
