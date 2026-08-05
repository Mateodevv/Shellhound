// Tooltip.tsx -- explanation on hover/focus.
//
// Why not `title=""`: the native tooltip only appears after ~1.5s, cannot do
// two paragraphs and is unreachable by keyboard. Here the explanation is
// part of the interface, not a hidden extra -- hence an own implementation
// with fixed positioning (which also works in scrolling tables and drawers,
// without an overflow:hidden cutting it off).
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { HelpCircle } from 'lucide-react'
import clsx from 'clsx'

interface Props {
  children: ReactNode
  title?: ReactNode
  body?: ReactNode
  hint?: ReactNode          // second line: "what does that mean for me"
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
      {/* INTO A PORTAL, not in place: the virtualised rows of the findings
          list carry a `transform`, and a transform turns `position: fixed`
          into a reference to THAT row and locks the z-index into its
          stacking context. The tooltip then lay behind the next row. At
          <body> that cage does not exist. */}
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

/** A small question mark that explains on hover. For column heads and key
 *  figures, where the text itself has no room for the explanation. */
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
