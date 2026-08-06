// TimeSwitcher.tsx -- which reading of the timestamps is on screen.
//
// Built like the language and theme switchers, and sitting next to them,
// because it is the same kind of choice: it changes how something is
// PRESENTED and never what was measured. The stored data is an epoch in UTC
// plus the offset that stood in the log line; both readings are derived from
// those two numbers and neither is more true than the other.
//
// It always shows the ACTIVE mode as its label, so no timestamp on screen is
// ever more than one glance from a stated zone. That is the whole point of
// the control: a bare `2026-06-10 22:58:11` in a report is not a time, it is
// a time and a question.
import { useEffect, useRef, useState } from 'react'
import clsx from 'clsx'
import { Check, Clock } from 'lucide-react'
import { useQueryClient } from '@tanstack/react-query'
import { useT } from '../i18n'
import {
  setActiveTimeMode, storedTimeMode, TIME_KEY, type TimeMode,
} from '../format'

const MODES: TimeMode[] = ['log', 'utc']

export function TimeSwitcher({ up }: { up?: boolean }) {
  const tr = useT()
  const qc = useQueryClient()
  const [mode, setMode] = useState<TimeMode>(storedTimeMode)
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setActiveTimeMode(mode)
    try { localStorage.setItem(TIME_KEY, mode) } catch { /* non-fatal */ }
    // Part of the chronology is prose the SERVER assembled, with the times
    // already rendered into it. Those have to come back in the new reading,
    // so the cache goes -- the same answer the language switch gives.
    qc.invalidateQueries()
  }, [mode, qc])

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

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        title={tr('time.switch')}
        className={clsx(
          'flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] font-medium',
          'text-[var(--muted)] transition-colors duration-150 cursor-pointer',
          'hover:bg-[var(--panel-2)] hover:text-[var(--fg)]',
          open && 'bg-[var(--panel-2)] text-[var(--fg)]')}
      >
        <Clock size={15} />
        {tr(`time.mode.${mode}`)}
      </button>

      {open && (
        <div
          className={clsx(
            'absolute left-0 z-50 w-72 rounded-xl border border-[var(--line)]',
            'bg-[var(--panel)] p-1.5 shadow-2xl animate-fade-up',
            up ? 'bottom-full mb-2' : 'top-full mt-2')}
        >
          {MODES.map((m) => (
            <button
              key={m}
              onClick={() => { setMode(m); setOpen(false) }}
              className={clsx(
                'flex w-full items-start gap-2.5 rounded-lg px-2.5 py-2',
                'transition-colors duration-150 cursor-pointer',
                mode === m
                  ? 'bg-[var(--accent-soft)] text-[var(--accent-text)]'
                  : 'text-[var(--fg)] hover:bg-[var(--panel-2)]')}
            >
              <div className="min-w-0 flex-1 text-left">
                <div className="text-[13px] font-medium">
                  {tr(`time.mode.${m}`)}
                </div>
                <div className="mt-0.5 text-[11.5px] leading-snug text-[var(--muted)]">
                  {tr(`time.mode.${m}.hint`)}
                </div>
              </div>
              {mode === m && (
                <Check size={14} className="mt-0.5 shrink-0 text-[var(--accent)]" />
              )}
            </button>
          ))}
          <p className="px-2.5 py-2 text-[11px] leading-snug text-[var(--muted)]">
            {tr('time.noNames')}
          </p>
        </div>
      )}
    </div>
  )
}
