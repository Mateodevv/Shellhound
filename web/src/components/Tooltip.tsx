// Tooltip.tsx — Erklärung bei Hover/Fokus.
//
// Warum nicht `title=""`: der native Tooltip erscheint erst nach ~1,5s, kann
// keine zwei Absätze und ist per Tastatur nicht erreichbar. Hier ist die
// Erklärung Teil der Oberfläche, nicht ein verstecktes Extra — deshalb eigene
// Umsetzung mit fixer Positionierung (funktioniert auch in scrollenden
// Tabellen und Drawern, ohne dass ein overflow:hidden sie abschneidet).
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { HelpCircle } from 'lucide-react'
import clsx from 'clsx'

interface Props {
  children: ReactNode
  title?: ReactNode
  body?: ReactNode
  hint?: ReactNode          // zweite Zeile: "was heißt das für mich"
  wide?: boolean
  className?: string
  as?: 'span' | 'div'
}

export function Tooltip({ children, title, body, hint, wide, className, as = 'span' }: Props) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState({ top: 0, left: 0, above: false })
  const ref = useRef<HTMLElement>(null)
  const timer = useRef<number | undefined>(undefined)

  const place = () => {
    const el = ref.current
    if (!el) return
    const r = el.getBoundingClientRect()
    const width = wide ? 360 : 280
    const above = r.top > window.innerHeight / 2
    setPos({
      top: above ? r.top - 8 : r.bottom + 8,
      left: Math.min(Math.max(8, r.left + r.width / 2 - width / 2),
                     window.innerWidth - width - 8),
      above,
    })
  }

  const show = () => {
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => { place(); setOpen(true) }, 220)
  }
  const hide = () => {
    window.clearTimeout(timer.current)
    setOpen(false)
  }

  useEffect(() => () => window.clearTimeout(timer.current), [])
  useEffect(() => {
    if (!open) return
    const onScroll = () => setOpen(false)
    window.addEventListener('scroll', onScroll, true)
    return () => window.removeEventListener('scroll', onScroll, true)
  }, [open])

  if (!title && !body && !hint) return <>{children}</>

  const Tag = as as 'span'
  return (
    <>
      <Tag
        ref={ref as React.Ref<HTMLSpanElement>}
        className={clsx('inline-flex items-center', className)}
        onMouseEnter={show}
        onMouseLeave={hide}
        onFocus={show}
        onBlur={hide}
        tabIndex={0}
      >
        {children}
      </Tag>
      {/* IN EIN PORTAL, nicht an Ort und Stelle: die virtualisierten Zeilen
          der Findings-Liste tragen ein `transform`, und ein Transform macht
          aus `position: fixed` einen Bezug auf DIESE Zeile und sperrt den
          z-index in ihren Stacking-Context. Der Tooltip lag dann hinter der
          nächsten Zeile. Am <body> gibt es diesen Käfig nicht. */}
      {open && createPortal(
        <div
          role="tooltip"
          className={clsx(
            'pointer-events-none fixed z-[100] rounded-lg border border-[var(--line)]',
            'bg-[var(--panel-2)] px-3 py-2 shadow-xl animate-fade-in',
            wide ? 'w-[360px]' : 'w-[280px]')}
          style={{
            top: pos.top,
            left: pos.left,
            transform: pos.above ? 'translateY(-100%)' : undefined,
          }}
        >
          {title && <div className="text-[12px] font-semibold">{title}</div>}
          {body && <div className="mt-0.5 text-[12px] leading-snug text-[var(--fg)]/85">{body}</div>}
          {hint && (
            <div className="mt-1.5 border-t border-[var(--line)] pt-1.5 text-[11.5px] leading-snug text-[var(--muted)]">
              {hint}
            </div>
          )}
        </div>,
        document.body)}
    </>
  )
}

/** Ein kleines Fragezeichen, das bei Hover erklärt. Für Spaltenköpfe und
 *  Kennzahlen, wo der Text selbst keinen Platz für die Erklärung hat. */
export function InfoDot({ title, body, hint, wide }: Omit<Props, 'children'>) {
  return (
    <Tooltip title={title} body={body} hint={hint} wide={wide}>
      <HelpCircle
        size={12}
        className="cursor-help text-[var(--muted)]/70 transition-colors hover:text-[var(--accent)]"
      />
    </Tooltip>
  )
}
