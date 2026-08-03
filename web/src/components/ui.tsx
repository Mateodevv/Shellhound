// ui.tsx — the small building blocks: cards, badges, chips, drawer, progress.
import { type ReactNode, useEffect } from 'react'
import clsx from 'clsx'
import { X } from 'lucide-react'
import { SEVERITY_LABEL, SEVERITY_VAR } from '../format'
import { SEVERITY_EXPLAIN, TAG_EXPLAIN, TRIAGE_EXPLAIN } from '../explain'
import { InfoDot, Tooltip } from './Tooltip'

export function Card({ children, className, style }: {
  children: ReactNode; className?: string; style?: React.CSSProperties
}) {
  return (
    <div
      className={clsx(
        'rounded-xl border border-[var(--line)] bg-[var(--panel)]', className)}
      style={style}
    >
      {children}
    </div>
  )
}

export function StatTile({ label, value, tone, sub, onClick, info }: {
  label: string
  value: ReactNode
  tone?: string
  sub?: ReactNode
  onClick?: () => void
  info?: string
}) {
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      className={clsx(
        'rounded-xl border border-[var(--line)] bg-[var(--panel)] px-4 py-3 text-left',
        'transition-colors duration-150',
        onClick && 'cursor-pointer hover:border-[var(--accent)]/60 hover:bg-[var(--panel-2)]')}
    >
      <div className="flex items-center gap-1 text-[11px] font-medium uppercase tracking-wider text-[var(--muted)]">
        {label}
        {info && <InfoDot body={info} />}
      </div>
      <div className="mt-1 text-2xl font-semibold tabular" style={tone ? { color: tone } : undefined}>
        {value}
      </div>
      {sub && <div className="mt-0.5 text-xs text-[var(--muted)]">{sub}</div>}
    </button>
  )
}

export function SeverityBadge({ severity, plain }: { severity: number; plain?: boolean }) {
  const badge = (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-semibold"
      style={{
        color: SEVERITY_VAR[severity],
        background: `color-mix(in srgb, ${SEVERITY_VAR[severity]} 14%, transparent)`,
      }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY_VAR[severity] }} />
      {SEVERITY_LABEL[severity]}
    </span>
  )
  if (plain) return badge
  const e = SEVERITY_EXPLAIN[severity]
  return <Tooltip title={e?.what} hint={e?.why}>{badge}</Tooltip>
}

const TRIAGE_STYLE: Record<string, string> = {
  new: 'text-[var(--muted)] bg-[var(--panel-2)]',
  reviewed: 'text-[var(--accent-text)] bg-[var(--accent-soft)]',
  confirmed: 'text-[var(--danger-text)] bg-[var(--danger-soft)]',
  dismissed: 'text-[var(--muted)] bg-[var(--panel-2)] line-through',
}

export function TriageBadge({ state, label }: { state: string; label: string }) {
  const e = TRIAGE_EXPLAIN[state]
  return (
    <Tooltip title={e?.what} hint={e?.why}>
      <span className={clsx('inline-flex rounded-full px-2 py-0.5 text-[11px] font-medium',
        TRIAGE_STYLE[state] ?? TRIAGE_STYLE.new)}>
        {label}
      </span>
    </Tooltip>
  )
}

export function Tag({ children, tone, explain, hint }: {
  children: ReactNode
  tone?: 'accent' | 'danger' | 'warn'
  explain?: string
  hint?: string
}) {
  const badge = (
    <span className={clsx(
      'inline-flex items-center gap-1 rounded-md px-1.5 py-px text-[11px] font-medium',
      tone === 'danger' && 'bg-[var(--danger-soft)] text-[var(--danger-text)]',
      tone === 'warn' && 'bg-[rgba(250,178,25,0.12)] text-[var(--sev-low)]',
      tone === 'accent' && 'bg-[var(--accent-soft)] text-[var(--accent-text)]',
      !tone && 'bg-[var(--panel-2)] text-[var(--muted)]',
    )}>
      {children}
    </span>
  )
  if (!explain && !hint) return badge
  return <Tooltip title={explain} hint={hint}>{badge}</Tooltip>
}

/** Ein IOC-Tag, das sich selbst erklärt. */
export function IocTag({ tag, tone }: {
  tag: string; tone?: 'accent' | 'danger' | 'warn'
}) {
  const e = TAG_EXPLAIN[tag]
  return <Tag tone={tone} explain={e?.what} hint={e?.why}>{tag}</Tag>
}

export function Chip({ active, onClick, children, count }: {
  active: boolean; onClick: () => void; children: ReactNode; count?: number
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium',
        'transition-colors duration-150 cursor-pointer',
        active
          ? 'border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--accent-text)]'
          : 'border-[var(--line)] bg-transparent text-[var(--muted)] hover:border-[var(--accent)]/50 hover:text-[var(--fg)]')}
    >
      {children}
      {count != null && (
        <span className="tabular rounded-full bg-[var(--panel-2)] px-1.5 text-[10px]">
          {count.toLocaleString('de-AT')}
        </span>
      )}
    </button>
  )
}

export function Button({ children, onClick, variant = 'default', disabled, className, title }: {
  children: ReactNode
  onClick?: () => void
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  disabled?: boolean
  className?: string
  title?: string
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[13px] font-medium',
        'transition-all duration-150 cursor-pointer disabled:cursor-not-allowed disabled:opacity-40',
        variant === 'primary' &&
          'bg-[var(--accent)] text-white hover:brightness-110 active:scale-[0.98]',
        variant === 'danger' &&
          'bg-[var(--danger-soft)] text-[var(--danger-text)] hover:bg-[var(--danger-soft-hover)]',
        variant === 'default' &&
          'border border-[var(--line)] bg-[var(--panel-2)] hover:border-[var(--accent)]/60',
        variant === 'ghost' && 'text-[var(--muted)] hover:bg-[var(--panel-2)] hover:text-[var(--fg)]',
        className)}
    >
      {children}
    </button>
  )
}

export function ProgressBar({ value, tone }: { value: number; tone?: string }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--panel-2)]">
      <div
        className="h-full rounded-full transition-[width] duration-500 ease-out"
        style={{ width: `${Math.round(value * 100)}%`, background: tone ?? 'var(--accent)' }}
      />
    </div>
  )
}

export function EmptyState({ icon, title, sub, action }: {
  icon: ReactNode; title: string; sub?: string; action?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-center animate-fade-in">
      <div className="text-[var(--muted)] opacity-60">{icon}</div>
      <div className="text-[15px] font-medium">{title}</div>
      {sub && <div className="max-w-md text-[13px] text-[var(--muted)]">{sub}</div>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

// Welche Drawer gerade offen sind, in der Reihenfolge, in der sie geöffnet
// wurden. Escape schließt nur den OBERSTEN: sonst räumt ein Tastendruck die
// ganze Kette ab und man verliert den Kontext, in dem man gerade gearbeitet
// hat (Datei-Viewer zu, Artefakt-Detail gleich mit).
const drawerStack: symbol[] = []

export function Drawer({ open, onClose, title, children, wide, layer = 0 }: {
  open: boolean
  onClose: () => void
  title: ReactNode
  children: ReactNode
  wide?: boolean
  /** Stapelebene: 0 ist der Grund-Drawer, höher liegt DAVOR. Ein Viewer,
   *  den man aus einem Drawer heraus öffnet, gehört nach vorne — sonst
   *  klickt man auf »Datei ansehen« und es passiert scheinbar nichts. */
  layer?: number
}) {
  useEffect(() => {
    if (!open) return
    const token = Symbol('drawer')
    drawerStack.push(token)
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      if (drawerStack[drawerStack.length - 1] !== token) return
      e.stopPropagation()
      onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => {
      const i = drawerStack.indexOf(token)
      if (i >= 0) drawerStack.splice(i, 1)
      window.removeEventListener('keydown', onKey)
    }
  }, [open, onClose])

  if (!open) return null
  return (
    <div className="fixed inset-0" style={{ zIndex: 40 + layer * 10 }}>
      <div className="absolute inset-0 bg-black/50 animate-fade-in" onClick={onClose} />
      <div
        className={clsx(
          'absolute right-0 top-0 h-full overflow-y-auto border-l border-[var(--line)]',
          'bg-[var(--panel)] shadow-2xl animate-fade-up',
          wide ? 'w-[min(960px,92vw)]' : 'w-[min(560px,92vw)]')}
      >
        <div className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-[var(--line)] bg-[var(--panel)]/95 px-5 py-3 backdrop-blur">
          <div className="min-w-0 text-[15px] font-semibold">{title}</div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)] hover:text-[var(--fg)] cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
      </div>
    </div>
  )
}

export function SearchInput({ value, onChange, placeholder }: {
  value: string; onChange: (v: string) => void; placeholder?: string
}) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={clsx(
        'w-56 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px]',
        'placeholder:text-[var(--muted)]/60 outline-none transition-colors',
        'focus:border-[var(--accent)]/70')}
    />
  )
}

export function Section({ title, sub, children, right }: {
  title: string; sub?: string; children: ReactNode; right?: ReactNode
}) {
  return (
    <section className="animate-fade-up">
      <div className="mb-3 flex items-end justify-between gap-3">
        <div>
          <h2 className="text-[15px] font-semibold">{title}</h2>
          {sub && <p className="mt-0.5 text-xs text-[var(--muted)]">{sub}</p>}
        </div>
        {right}
      </div>
      {children}
    </section>
  )
}
