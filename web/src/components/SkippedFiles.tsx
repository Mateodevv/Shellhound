import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import { useT } from '../i18n'
import { Button } from './ui'

interface SkipDetails {
  items: { path: string; reason: string }[]
  total: number
  recorded: boolean
}

/** Fetch the immutable details of this job only when the analyst opens them. */
export function SkippedFiles({ slug, jobId }: { slug: string; jobId: number }) {
  const tr = useT()
  const [open, setOpen] = useState(false)
  const [offset, setOffset] = useState(0)
  const { data, isPending, isError, refetch } = useQuery({
    queryKey: ['job-skips', slug, jobId, offset],
    queryFn: () => api<SkipDetails>(`/api/cases/${slug}/jobs/${jobId}/skipped?offset=${offset}&limit=100`),
    enabled: open,
  })
  return (
    <div className="mt-2 text-[12px]">
      <button aria-expanded={open} onClick={() => setOpen(!open)}
        className="cursor-pointer font-medium text-[var(--accent-text)] hover:underline">
        {tr('evidence.skips.title')}
      </button>
      {open && <div className="mt-2 rounded-lg border border-[var(--line)] p-3">
        {isPending && <p>{tr('common.loading')}</p>}
        {isError && <div role="alert">
          <p>{tr('evidence.skips.error')}</p>
          <Button onClick={() => refetch()}>{tr('evidence.skips.retry')}</Button>
        </div>}
        {data && <>
          {!data.recorded && <p className="text-[var(--muted)]">{tr('evidence.skips.legacy')}</p>}
          {data.recorded && data.total === 0 && <p className="text-[var(--muted)]">{tr('evidence.skips.empty')}</p>}
          {data.total > 0 && <>
            <ul className="max-h-64 overflow-auto divide-y divide-[var(--line)]">
              {data.items.map((item, index) => <li key={offset + index} className="py-2 first:pt-0">
                <div className="mono break-all text-[var(--fg)]">{item.path}</div>
                <div className="mt-1 break-words text-[var(--muted)]">{item.reason}</div>
              </li>)}
            </ul>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <span className="text-[var(--muted)]">{tr('evidence.skips.page', {
                first: offset + 1, last: offset + data.items.length, total: data.total,
              })}</span>
              {data.total > 100 && <>
                <Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>{tr('evidence.skips.previous')}</Button>
                <Button disabled={offset + data.items.length >= data.total} onClick={() => setOffset(offset + 100)}>{tr('evidence.skips.next')}</Button>
              </>}
            </div>
          </>}
        </>}
      </div>}
    </div>
  )
}
