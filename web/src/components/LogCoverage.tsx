// LogCoverage.tsx -- what the logs can and cannot show, below the
// chronology that is built out of them.
//
// The primary forensic content comes first; coverage and limitations follow
// it as qualifications. This keeps an analyst from having to cross a warning
// block before reaching the timeline they opened the page to inspect.
//
// NO FINDINGS, NO SEVERITIES, and that is not modesty. A quiet window and a
// removed window look identical from here -- a maintenance night, a rotation,
// a firewall change all produce the same hole. So this points at the
// question and never answers it: the analyst decides whether a gap means
// anything, and the tool must not put a colour on that decision.
import { useQuery } from '@tanstack/react-query'
import { Clock3, FileWarning, Radar } from 'lucide-react'
import { api } from '../api'
import { useT } from '../i18n'
import { formatCount, formatLogTime, formatSpan } from '../format'
import { Card } from './ui'
import { InfoDot } from './Tooltip'

interface QuietWindow {
  from: number
  to: number
  seconds: number
}

interface FileAnomaly {
  path: string
  name: string
  truncated: boolean
  stale_mtime: boolean
  last_epoch: number | null
}

interface Coverage {
  quiet: {
    /** Capped -- `total` says how many there really were. */
    windows: QuietWindow[]
    /** False when there was too little data to say anything, which is not
     *  the same as "no holes". */
    checked: boolean
    /** The log's own rhythm in seconds, and the yardstick the threshold is
     *  derived from: a server answering every two seconds and one answering
     *  three times a day cannot share a cutoff. The interface used to call
     *  this `median`, a name no endpoint has ever sent. */
    median_gap?: number
    /** How long a silence has to be before it counts, in seconds. */
    threshold?: number
    /** Quiet windows found in total, before `windows` was capped. */
    total?: number
  }
  files: FileAnomaly[]
  notes: string[]
  /** The log's own UTC offset, so these times can be shown on the same clock
   *  as the chronology below instead of silently in UTC. */
  tz: number
}

export function LogCoverage({ slug }: { slug: string }) {
  const tr = useT()
  const { data } = useQuery({
    queryKey: ['coverage', slug],
    queryFn: () => api<Coverage>(`/api/cases/${slug}/coverage`),
  })

  const windows = data?.quiet.windows ?? []
  const files = data?.files ?? []
  // THE MEASUREMENT, NOT THE LIST. `windows` is capped at six so the block
  // stays readable; `total` says how many there were. Counting the list made
  // the sentence below say "6 observations" on a case with fourteen holes --
  // and that is the number a reader carries into the report.
  const measured = Math.max(data?.quiet.total ?? windows.length, windows.length)
  const unlisted = measured - windows.length
  if (!data || (!windows.length && !files.length)) return null

  return (
    <Card className="flex flex-col gap-2 border-[var(--line)] px-4 py-3 animate-fade-up">
      <div className="flex items-center gap-2">
        <Radar size={14} className="shrink-0 text-[var(--muted)]" />
        <span className="text-[13px] font-semibold">
          {tr('coverage.title')}
        </span>
        <InfoDot title={tr('coverage.title')} body={tr('coverage.body')}
          hint={tr('coverage.hint')} wide />
      </div>

      {windows.length > 0 && (
        <div className="flex flex-col gap-1">
          {windows.map((w, i) => (
            <div key={i} className="flex items-center gap-2 text-[12.5px]">
              <Clock3 size={12} className="shrink-0 text-[var(--sev-low)]" />
              {/* WITH THE ZONE, AND THE SAME ONE THE CHRONOLOGY USES. These
                  were rendered at offset 0 regardless of the switcher while
                  the chronology under them showed log-local time and labelled
                  it -- the same instant, hours apart, on one screen, and this
                  block named no zone at all. */}
              <span className="mono tabular shrink-0 text-[var(--muted)]">
                {formatLogTime(w.from, data.tz)}
              </span>
              <span className="shrink-0 text-[var(--muted)]">→</span>
              <span className="mono tabular shrink-0 text-[var(--muted)]">
                {formatLogTime(w.to, data.tz, { withZone: true })}
              </span>
              <span className="min-w-0 flex-1 truncate">
                {tr('coverage.window', { span: formatSpan(w.from, w.to) })}
              </span>
            </div>
          ))}
          {unlisted > 0 && (
            <div className="pl-[20px] text-[12px] text-[var(--muted)]">
              {tr('coverage.more', { n: formatCount(unlisted) })}
            </div>
          )}
        </div>
      )}

      {files.map((f) => (
        <div key={f.path} className="flex items-center gap-2 text-[12.5px]">
          <FileWarning size={12} className="shrink-0 text-[var(--sev-low)]" />
          <span className="mono shrink-0">{f.name}</span>
          <span className="min-w-0 flex-1 truncate text-[var(--muted)]">
            {[f.truncated ? tr('coverage.file.truncated') : '',
              f.stale_mtime ? tr('coverage.file.stale') : '']
              .filter(Boolean).join(' · ')}
          </span>
        </div>
      ))}

      {/* The sentence that keeps this honest. It is the whole reason the
          block carries no severity: none of it proves anything. */}
      <p className="text-[11.5px] leading-snug text-[var(--muted)]">
        {tr('coverage.disclaimer', {
          n: formatCount(measured + files.length),
        })}
      </p>
    </Card>
  )
}
