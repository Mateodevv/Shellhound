import { useId, useRef, useState } from 'react'
import { Activity, ChevronDown, ChevronUp } from 'lucide-react'
import type { Job } from '../api'
import { useT } from '../i18n'
import { ProgressBar } from './ui'
import { discovering, progressMessage } from '../analysis'

export function JobPopup({ jobs, onShowRuns }: { jobs: Job[]; onShowRuns: () => void }) {
  const tr = useT()
  const [open, setOpen] = useState(true)
  const panelId = useId()
  const toggle = useRef<HTMLButtonElement>(null)

  return (
    <aside aria-label={tr('jobs.activity')}
      className="fixed right-3 top-[4.5rem] z-30 flex max-w-[calc(100vw-1.5rem)] flex-col items-end sm:right-6 md:top-4"
      onKeyDown={(event) => {
        if (event.key === 'Escape' && open) {
          event.stopPropagation()
          setOpen(false)
          toggle.current?.focus()
        }
      }}>
      <button ref={toggle} type="button" aria-expanded={open} aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
        className="flex cursor-pointer items-center gap-2 rounded-lg border border-[var(--accent)]/40 bg-[var(--panel)] px-3 py-2 text-[12px] font-semibold text-[var(--accent-text)] shadow-lg hover:bg-[var(--panel-2)] focus-visible:outline-2 focus-visible:outline-[var(--accent)]">
        <Activity size={14} className="animate-pulse-soft" />
        <span aria-live="polite">{tr('nav.jobsRunning', { n: jobs.length })}</span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>
      {open && (
        <div id={panelId} className="mt-2 w-80 max-w-full overflow-hidden rounded-xl border border-[var(--line-strong)] bg-[var(--panel)] shadow-2xl animate-fade-up">
          <div className="max-h-[min(24rem,calc(100dvh-12rem))] space-y-4 overflow-y-auto p-4">
            {jobs.map((job) => {
              const key = `job.${job.kind}`
              const label = tr(key) === key ? job.kind : tr(key)
              const message = progressMessage(job, tr)
              return (
                <div key={job.id}>
                  <div className="mb-1 flex items-center justify-between gap-3 text-[12px]">
                    <span className="min-w-0 truncate font-semibold" title={label}>
                      {label}{job.scan_context?.mode === 'retry' && ` · ${tr('jobs.retry')}`}
                    </span>
                    <span className="shrink-0 text-[10px] text-[var(--muted)]">
                      {job.state === 'queued' ? tr('jobs.queued') : discovering(job)
                        ? tr('jobs.discovering') : `${Math.round(job.progress * 100)}%`}
                    </span>
                  </div>
                  {message && <div className="mb-2 truncate text-[11px] text-[var(--muted)]" title={message}>{message}</div>}
                  <ProgressBar value={job.progress} indeterminate={discovering(job)} label={`${label}: ${message || tr('jobs.queued')}`} />
                </div>
              )
            })}
          </div>
          <button type="button" onClick={() => { setOpen(false); onShowRuns(); toggle.current?.focus() }}
            className="w-full cursor-pointer border-t border-[var(--line)] px-4 py-2.5 text-left text-[12px] font-medium text-[var(--accent-text)] hover:bg-[var(--panel-2)]">
            {tr('jobs.showRuns')}
          </button>
        </div>
      )}
    </aside>
  )
}
