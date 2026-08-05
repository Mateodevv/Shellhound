// FsTimeline.tsx -- when the webroot was touched. A LEAD, never a proof.
//
// The chronology above this is built from measured request times and refuses
// the file system on principle: nobody can tell from the mtime of a COPY
// whether it came from the original or from the copying, and an attacker can
// set it to anything.
//
// This panel is the other half of that honesty. The distrust is about PROOF,
// not about value -- "these fourteen files were written within forty seconds
// of each other, and one of them is the shell you already confirmed" is one
// of the most useful sentences in a webroot investigation. So it is shown,
// clearly fenced off: dashed border, its own heading, ordered by TIME rather
// than by any suspicion score, and with no severity anywhere.
//
// A deployment writes hundreds of files in one burst and looks exactly the
// same. That is why the cluster is shown and no verdict about it.
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, Clock3, FileCode2, Layers } from 'lucide-react'
import clsx from 'clsx'
import { api, type FsClusters } from '../api'
import { useT } from '../i18n'
import { formatBytes, formatCount, formatLogTime, formatSpan } from '../format'
import { Card, Collapsible, Tag } from './ui'
import { InfoDot, Tooltip } from './Tooltip'

export function FsTimeline({ slug, onView }: {
  slug: string
  onView: (path: string) => void
}) {
  const tr = useT()
  const [open, setOpen] = useState(false)
  const [noise, setNoise] = useState(false)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  const { data } = useQuery({
    queryKey: ['fstimeline', slug, noise],
    // Only asked for once the panel is open: this walks the whole webroot,
    // and a dashboard that stats 100,000 files on load is a dashboard nobody
    // opens twice.
    enabled: open,
    queryFn: () => api<FsClusters>(
      `/api/cases/${slug}/fstimeline?noise=${noise ? 'true' : 'false'}`),
  })

  const toggle = (i: number) => setExpanded((prev) => {
    const next = new Set(prev)
    if (next.has(i)) next.delete(i)
    else next.add(i)
    return next
  })

  return (
    <Collapsible
      open={open}
      onToggle={() => setOpen(!open)}
      count={data?.clusters.length || undefined}
      title={
        <>
          {tr('fs.title')}
          <InfoDot title={tr('fs.title')} body={tr('fs.body')}
            hint={tr('fs.hint')} wide />
        </>
      }
      sub={tr('fs.sub')}
      right={
        <Tooltip hint={tr('fs.noise.hint')}>
          <label className="flex cursor-pointer items-center gap-1.5 text-[12px] text-[var(--muted)]">
            <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
              checked={noise} onChange={(e) => setNoise(e.target.checked)} />
            {tr('fs.noise')}
          </label>
        </Tooltip>
      }>

      {data && !data.checked && (
        <div className="px-1 py-2 text-[12.5px] text-[var(--muted)]">
          {data.reason === 'nowebroot' ? tr('fs.noWebroot') : tr('fs.noFiles')}
        </div>
      )}

      {data?.checked && (
        <div className="flex flex-col gap-1.5">
          {data.clusters.map((c, i) => {
            const isOpen = expanded.has(i)
            // The ONE piece of interpretation: a cluster containing
            // something the case already confirmed is worth reading first,
            // because the OTHER files in it were written in the same minute.
            const tied = c.confirmed > 0
            return (
              <Card key={`${c.from}-${i}`}
                className={clsx('overflow-hidden border-dashed',
                  tied && 'border-[var(--sev-high)]/40')}>
                <button onClick={() => toggle(i)}
                  className="flex w-full cursor-pointer items-center gap-3 px-4 py-2 text-left hover:bg-[var(--panel-2)]">
                  {isOpen ? <ChevronDown size={14} className="shrink-0 text-[var(--muted)]" />
                          : <ChevronRight size={14} className="shrink-0 text-[var(--muted)]" />}
                  <Layers size={14} className="shrink-0 text-[var(--muted)]" />
                  <span className="mono shrink-0 tabular text-[12.5px]">
                    {formatLogTime(c.from, 0)}
                  </span>
                  <span className="shrink-0 text-[11.5px] text-[var(--muted)]">
                    {c.to > c.from ? `+ ${formatSpan(c.from, c.to)}` : ''}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-[12.5px]">
                    {tr('fs.files', { n: formatCount(c.count) })}
                    <span className="text-[var(--muted)]"> · {formatBytes(c.bytes)}</span>
                  </span>
                  {c.confirmed > 0 && (
                    <Tag tone="danger" hint={tr('fs.tied.hint')}>
                      {tr('fs.tied', { n: c.confirmed })}
                    </Tag>
                  )}
                  {c.confirmed === 0 && c.flagged > 0 && (
                    <Tag tone="warn" hint={tr('fs.flagged.hint')}>
                      {tr('fs.flagged', { n: c.flagged })}
                    </Tag>
                  )}
                </button>
                {isOpen && (
                  <div className="border-t border-[var(--line)] px-4 py-2">
                    {c.files.map((f) => (
                      <button key={f.path} onClick={() => onView(f.path)}
                        className="flex w-full cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-left hover:bg-[var(--panel-2)]">
                        <FileCode2 size={12}
                          className={clsx('shrink-0',
                            f.confirmed ? 'text-[var(--sev-high)]'
                                        : f.flagged ? 'text-[var(--sev-low)]'
                                                    : 'text-[var(--muted)]')} />
                        <span className="mono min-w-0 flex-1 truncate text-[11.5px]"
                          title={f.path}>
                          {f.path}
                        </span>
                      </button>
                    ))}
                    {c.truncated && (
                      <div className="mt-1 text-[11px] text-[var(--sev-low)]">
                        {tr('fs.cluster.capped')}
                      </div>
                    )}
                  </div>
                )}
              </Card>
            )
          })}

          {!data.clusters.length && (
            <div className="px-1 py-2 text-[12.5px] text-[var(--muted)]">
              {tr('fs.empty')}
            </div>
          )}

          <div className="flex items-center gap-1.5 px-1 text-[11px] text-[var(--muted)]">
            <Clock3 size={11} />
            {tr('fs.footer', {
              files: formatCount(data.files),
              seconds: data.burst_seconds ?? 60,
            })}
            {data.truncated && ` · ${tr('fs.capped')}`}
          </div>
        </div>
      )}
    </Collapsible>
  )
}
