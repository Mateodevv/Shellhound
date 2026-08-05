// LanguageSwitcher.tsx — switch the interface language at runtime.
//
// Built exactly like ThemeSwitcher: both are presentation settings, they
// sit next to each other, and a different control shape for the same kind
// of choice would read as a different kind of thing.
import { useEffect, useRef, useState } from 'react'
import clsx from 'clsx'
import { Check, Languages } from 'lucide-react'
import { LANGUAGES, useI18n } from '../i18n'

export function LanguageSwitcher({ up }: { up?: boolean }) {
  const { lang, setLang, t } = useI18n()
  const [open, setOpen] = useState(false)
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

  const active = LANGUAGES.find((l) => l.id === lang)

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        title={t('app.language')}
        className={clsx(
          'flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] font-medium',
          'text-[var(--muted)] transition-colors duration-150 cursor-pointer',
          'hover:bg-[var(--panel-2)] hover:text-[var(--fg)]',
          open && 'bg-[var(--panel-2)] text-[var(--fg)]')}
      >
        <Languages size={15} />
        {active?.label ?? t('app.language')}
      </button>

      {open && (
        <div
          className={clsx(
            'absolute left-0 z-50 w-52 rounded-xl border border-[var(--line)]',
            'bg-[var(--panel)] p-1.5 shadow-2xl animate-fade-up',
            up ? 'bottom-full mb-2' : 'top-full mt-2')}
        >
          {LANGUAGES.map((l) => (
            <button
              key={l.id}
              onClick={() => { setLang(l.id); setOpen(false) }}
              className={clsx(
                'flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2',
                'transition-colors duration-150 cursor-pointer',
                lang === l.id
                  ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                  : 'text-[var(--fg)] hover:bg-[var(--panel-2)]')}
            >
              <span className="flex h-5 w-9 shrink-0 items-center justify-center rounded-md border border-[var(--line)] text-[10px] font-semibold uppercase tracking-wider">
                {l.id}
              </span>
              <span className="flex-1 text-left text-[13px] font-medium">{l.label}</span>
              {lang === l.id && <Check size={14} className="text-[var(--accent)]" />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
