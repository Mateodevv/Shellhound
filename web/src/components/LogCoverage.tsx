// LogCoverage.tsx -- what the logs can and cannot show, above the
// chronology that is built out of them.
//
// IT BELONGS ABOVE, not below. The chronology is a sequence of measured
// observations; this says how much of the period those observations could
// have come from at all. Reading the order of events without knowing that
// six hours of the log are missing is reading a sentence with a word cut
// out and not noticing.
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
  quiet: { windows: QuietWindow[]; checked: boolean; median?: number }
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
          n: formatCount(windows.length + files.length),
        })}
      </p>
    </Card>
  )
}
