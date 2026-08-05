// ThemeSwitcher.tsx -- a small popover for switching the UI theme.
// `up` opens the menu upwards (for the bottom edge of the sidebar).
import { useT } from '../i18n'
import { useEffect, useRef, useState } from 'react'
import clsx from 'clsx'
import { Check, Palette } from 'lucide-react'
import { THEMES, applyTheme, currentTheme } from '../theme'

function Swatch({ colors }: { colors: [string, string, string] }) {
  return (
    <span
      className="flex h-5 w-9 shrink-0 items-center justify-center gap-1 rounded-md border border-[var(--line)]"
      style={{ background: colors[0] }}
    >
      <span className="h-2 w-2 rounded-full" style={{ background: colors[1] }} />
      <span className="h-2 w-2 rounded-full" style={{ background: colors[2] }} />
    </span>
  )
}

export function ThemeSwitcher({ up }: { up?: boolean }) {
  const tr = useT()
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(currentTheme)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    window.addEventListener('mousedown', onDown)
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('mousedown', onDown)
      window.removeEventListener('keydown', onKey)
    }
  }, [open])

  const pick = (id: string) => {
    applyTheme(id)
    setActive(id)
    setOpen(false)
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        title={tr('theme.choose')}
        className={clsx(
          'flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] font-medium',
          'text-[var(--muted)] transition-colors duration-150 cursor-pointer',
          'hover:bg-[var(--panel-2)] hover:text-[var(--fg)]',
          open && 'bg-[var(--panel-2)] text-[var(--fg)]')}
      >
        <Palette size={15} />
        Theme
      </button>

      {open && (
        <div
          className={clsx(
            'absolute left-0 z-50 w-52 rounded-xl border border-[var(--line)]',
            'bg-[var(--panel)] p-1.5 shadow-2xl animate-fade-up',
            up ? 'bottom-full mb-2' : 'top-full mt-2')}
        >
          {THEMES.map((t) => (
            <button
              key={t.id}
              onClick={() => pick(t.id)}
              className={clsx(
                'flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2',
                'transition-colors duration-150 cursor-pointer',
                active === t.id
                  ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                  : 'text-[var(--fg)] hover:bg-[var(--panel-2)]')}
            >
              <Swatch colors={t.preview} />
              <span className="flex-1 text-left text-[13px] font-medium">{t.label}</span>
              {active === t.id && <Check size={14} className="text-[var(--accent)]" />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
