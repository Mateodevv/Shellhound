// ui.tsx — the small building blocks: cards, badges, chips, drawer, progress.
import { useT } from '../i18n'
import { type ReactNode, useEffect, useRef, useState } from 'react'
import clsx from 'clsx'
import { Check, ChevronDown, ChevronRight, Copy, X } from 'lucide-react'
import { SEVERITY_LABEL, SEVERITY_VAR } from '../format'
import { copyText } from '../copy'
import { explain } from '../explain'
import { InfoDot, Tooltip } from './Tooltip'

export function Card({ children, className, style, id }: {
  // `id` only so that a card can be a jump target (IOC box: from one
  // indicator to its linked neighbour).
  children: ReactNode; className?: string; style?: React.CSSProperties; id?: string
}) {
  return (
    <div
      id={id}
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
  const tr = useT()
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
  const e = explain(tr, `severity.${severity}`)
  return <Tooltip title={e?.what} hint={e?.why}>{badge}</Tooltip>
}

const TRIAGE_STYLE: Record<string, string> = {
  new: 'text-[var(--muted)] bg-[var(--panel-2)]',
  reviewed: 'text-[var(--accent-text)] bg-[var(--accent-soft)]',
  confirmed: 'text-[var(--danger-text)] bg-[var(--danger-soft)]',
  dismissed: 'text-[var(--muted)] bg-[var(--panel-2)] line-through',
}

export function TriageBadge({ state, label }: { state: string; label: string }) {
  const tr = useT()
  const e = explain(tr, `triage.${state}`)
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

/** An IOC tag that explains itself. */
export function IocTag({ tag, tone }: {
  tag: string; tone?: 'accent' | 'danger' | 'warn'
}) {
  const tr = useT()
  const e = explain(tr, `tag.${tag}`)
  return <Tag tone={tone} explain={e?.what} hint={e?.why}>{tag}</Tag>
}

export function Chip({ active, onClick, children, count, dimmed }: {
  active: boolean
  onClick: () => void
  children: ReactNode
  count?: number
  /** Hide logic: this chip is currently HIDDEN -- struck through and
   *  receded, but clickable, because the next click brings the entries back.
   *  `active` and `dimmed` are mutually exclusive. */
  dimmed?: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium',
        'transition-colors duration-150 cursor-pointer',
        dimmed
          ? 'border-[var(--line)] bg-transparent text-[var(--muted)] opacity-50 line-through hover:opacity-80'
          : active
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

export function Button({ children, onClick, variant = 'default', disabled, className, title, style, onMouseLeave }: {
  children: ReactNode
  onClick?: () => void
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  disabled?: boolean
  className?: string
  title?: string
  /** For the case where a button has to stand out from the surface it sits
   *  on -- a utility class would lose against the variant. */
  style?: React.CSSProperties
  /** For a button that ARMS on first click (delete, and nothing else so
   *  far): leaving it must disarm, or the armed state lies in wait. */
  onMouseLeave?: () => void
}) {
  return (
    <button
      onClick={onClick}
      onMouseLeave={onMouseLeave}
      disabled={disabled}
      title={title}
      style={style}
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

/** Copying with a receipt. Without the short confirmation nobody knows
 *  whether the click arrived -- and one clicks a second time, which changes
 *  nothing but leaves doubt. A FAILURE is shown just as clearly: silently
 *  doing nothing is the worst of the three possibilities. */
export function CopyButton({ value, label = 'Kopieren', className, icon }: {
  value: string; label?: string; className?: string
  /** Replaces the copy glyph in the idle state -- for a SECOND copy action
   *  beside the plain one (e.g. defanged), which would otherwise be an
   *  identical twin nobody can tell apart. Receipt states stay the same. */
  icon?: ReactNode
}) {
  const tr = useT()
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle')
  const timer = useRef<number | undefined>(undefined)
  useEffect(() => () => window.clearTimeout(timer.current), [])
  const copy = () => {
    copyText(value).then((ok) => {
      setState(ok ? 'ok' : 'fail')
      window.clearTimeout(timer.current)
      timer.current = window.setTimeout(() => setState('idle'), ok ? 1400 : 2600)
    })
  }
  return (
    <Tooltip hint={state === 'fail'
      ? tr('copy.unavailable')
      : tr('copy.hint', { what: label })}>
      <button onClick={copy} aria-label={label}
        className={clsx(
          'cursor-pointer rounded-md border border-transparent p-1 transition-colors',
          state === 'ok' ? 'text-[var(--ok)]'
            : state === 'fail' ? 'text-[var(--danger-text)]'
              : 'text-[var(--muted)] hover:border-[var(--accent)]/60 hover:text-[var(--fg)]',
          className)}>
        {state === 'ok' ? <Check size={13} />
          : state === 'fail' ? <X size={13} /> : (icon ?? <Copy size={13} />)}
      </button>
    </Tooltip>
  )
}

/** A section that can be collapsed. The state belongs to the caller, so it
 *  can be remembered or set from outside. */
export function Collapsible({ open, onToggle, title, sub, right, count, children }: {
  open: boolean
  onToggle: () => void
  title: ReactNode
  sub?: ReactNode
  right?: ReactNode
  count?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="animate-fade-up">
      <div className="mb-3 flex items-end justify-between gap-3">
        <button onClick={onToggle}
          className="group flex min-w-0 cursor-pointer items-start gap-2 text-left">
          <span className="mt-0.5 shrink-0 text-[var(--muted)] transition-colors group-hover:text-[var(--fg)]">
            {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
          </span>
          <span className="min-w-0">
            <span className="flex items-center gap-2 text-[15px] font-semibold">
              {title}
              {count != null && (
                <span className="rounded-full border border-[var(--line)] px-1.5 text-[11px] font-medium tabular text-[var(--muted)]">
                  {count}
                </span>
              )}
            </span>
            {sub && <p className="mt-0.5 text-xs text-[var(--muted)]">{sub}</p>}
          </span>
        </button>
        {right}
      </div>
      {open && children}
    </section>
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

// Which overlays are currently open, in the order they were opened. Escape
// closes only the TOPMOST one: otherwise one keystroke clears the whole
// chain and one loses the context one was just working in (file viewer
// closed, artifact detail along with it).
const drawerStack: symbol[] = []

/** Registers an open overlay and says whether it is currently the topmost.
 *  Drawer and modal share this stack -- they lie on top of each other. */
function useOverlayEscape(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return
    const token = Symbol('overlay')
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
}

/** A centred window -- the standard view for everything that needs AREA:
 *  artifact detail, file viewer, trace.
 *
 *  Windows opened from another one (`layer` > 0) are slightly smaller per
 *  level. That is not decoration: one sees at the edge that something else
 *  lies below, something one comes back to -- otherwise a trace feels like a
 *  change of subject rather than a glance to the side. */
export function Modal({ open, onClose, title, children, layer = 0 }: {
  open: boolean
  onClose: () => void
  title: ReactNode
  children: ReactNode
  layer?: number
}) {
  const tr = useT()
  useOverlayEscape(open, onClose)
  if (!open) return null
  const inset = Math.min(layer, 3)
  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 sm:p-6"
      style={{ zIndex: 40 + layer * 10 }}>
      <div className={clsx('absolute inset-0 animate-fade-in',
        layer > 0 ? 'bg-black/35' : 'bg-black/60')} onClick={onClose} />
      <div className={clsx(
        'relative flex flex-col overflow-hidden',
        'rounded-2xl border border-[var(--line)] bg-[var(--panel)] shadow-2xl',
        'animate-fade-up')}
        style={{
          width: `min(${1280 - inset * 70}px, ${96 - inset * 3}vw)`,
          maxHeight: `${92 - inset * 3}vh`,
        }}>
        <div className="flex shrink-0 items-center justify-between gap-3 border-b border-[var(--line)] px-5 py-3">
          <div className="min-w-0 text-[15px] font-semibold">{title}</div>
          <button
            onClick={onClose}
            title={tr('common.closeEsc')}
            className="shrink-0 rounded-lg p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)] hover:text-[var(--fg)] cursor-pointer"
          >
            <X size={16} />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </div>
  )
}

/** A message about something that JUST HAPPENED, without interrupting the
 *  flow of work. It lies above everything (open windows included), because
 *  it reports on the action one has just triggered.
 *
 *  It disappears by itself after `timeout` -- but only when it carries no
 *  action: a message with "undo" must not run away before it has been
 *  read. */
export function Toast({ open, onClose, tone = 'info', title, children, actions,
                        timeout = 9000 }: {
  open: boolean
  onClose: () => void
  tone?: 'info' | 'ok'
  title: ReactNode
  children?: ReactNode
  actions?: ReactNode
  timeout?: number
}) {
  const tr = useT()
  useEffect(() => {
    if (!open || !timeout || actions) return
    const t = setTimeout(onClose, timeout)
    return () => clearTimeout(t)
  }, [open, timeout, actions, onClose])

  if (!open) return null
  const accent = tone === 'ok' ? 'var(--ok)' : 'var(--accent)'
  return (
    <div className="fixed bottom-5 right-5 z-[100] w-[min(30rem,92vw)] animate-fade-up">
      <div className="rounded-xl border border-[var(--line)] bg-[var(--panel)] p-3 shadow-2xl"
        style={{ borderLeft: `3px solid ${accent}` }}>
        <div className="flex items-start gap-2">
          <div className="min-w-0 flex-1">
            <div className="text-[13px] font-semibold">{title}</div>
            {children && (
              <div className="mt-1 text-[12px] leading-snug text-[var(--muted)]">
                {children}
              </div>
            )}
          </div>
          <button onClick={onClose} title={tr('common.close')}
            className="shrink-0 rounded p-1 text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)] hover:text-[var(--fg)] cursor-pointer">
            <X size={14} />
          </button>
        </div>
        {actions && <div className="mt-2 flex flex-wrap gap-2">{actions}</div>}
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

/** A tab strip. The state lives in the caller, so a tab can be opened from
 *  elsewhere -- a reminder banner links straight to the tab that fixes it,
 *  and a banner that dumps you at the top of a long page is a banner that
 *  gets ignored the second time. */
export function Tabs<T extends string>({ tabs, active, onChange }: {
  tabs: { id: T; label: string; badge?: ReactNode }[]
  active: T
  onChange: (id: T) => void
}) {
  return (
    <div role="tablist"
      className="flex gap-1 border-b border-[var(--line)]">
      {tabs.map(({ id, label, badge }) => (
        <button key={id} role="tab" aria-selected={active === id}
          onClick={() => onChange(id)}
          className={clsx(
            'relative -mb-px cursor-pointer border-b-2 px-3 py-2 text-[13px] font-medium transition-colors',
            active === id
              ? 'border-[var(--accent)] text-[var(--fg)]'
              : 'border-transparent text-[var(--muted)] hover:text-[var(--fg)]')}>
          {label}
          {badge}
        </button>
      ))}
    </div>
  )
}
