// WebrootDiff.tsx -- the webroot against a known-clean copy.
//
// The classic manual work after every web server incident, as a query: what
// is EXTRA (uploaded shells live here), what is MODIFIED (injected code in
// legitimate files), what is MISSING (often the trace of a cleanup attempt).
// A hit is a CANDIDATE, not a find -- every upload directory is full of
// legitimate extras. The comparison shrinks the haystack; looking, flagging
// or dismissing stays manual work, and that is exactly what the buttons on
// every row are for.
import { useT } from '../i18n'
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { Box, Check, FileSearch, GitCompare, Play } from 'lucide-react'
import { api, post, type EvidenceItem } from '../api'
import { formatBytes, formatCount } from '../format'
import { Button, Card, Chip, Tag } from './ui'
import { InfoDot, Tooltip } from './Tooltip'

interface DiffRow {
  id: number
  status: 'extra' | 'missing' | 'modified' | 'too_big'
  path: string
  size: number
  ref_size: number
  absolute: string
  in_box: boolean
}

interface DiffData {
  total: number
  counts: Record<string, number>
  rows: DiffRow[]
  ran_at: string
  webroot: { path: string } | null
}

// Keys only at module level -- translation happens at render time.
const STATUS_KEY: Record<DiffRow['status'], string> = {
  extra: 'diff.extra',
  modified: 'diff.modified',
  missing: 'diff.missing',
  too_big: 'diff.unchecked',
}

const STATUS_TONE: Record<DiffRow['status'], 'danger' | 'warn' | undefined> = {
  extra: 'warn', modified: 'danger', missing: undefined, too_big: undefined,
}

export function WebrootDiff({ slug, evidence, onView }: {
  slug: string
  evidence: EvidenceItem[]
  onView: (path: string) => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const webroots = evidence.filter((e) => e.kind === 'webroot')
  const references = evidence.filter((e) => e.kind === 'reference')
  const [webrootId, setWebrootId] = useState<number | ''>('')
  const [referenceId, setReferenceId] = useState<number | ''>('')
  const [hidden, setHidden] = useState<Set<string>>(new Set())
  const [search, setSearch] = useState('')

  const hide = [...hidden].join(',')
  const { data } = useQuery({
    queryKey: ['diff', slug, hide, search],
    queryFn: () => api<DiffData>(
      `/api/cases/${slug}/diff?hide_status=${hide}&search=${encodeURIComponent(search)}&limit=500`),
  })

  const run = useMutation({
    mutationFn: () => post(`/api/cases/${slug}/diff/run`, {
      webroot_id: webrootId || webroots[0]?.id,
      reference_id: referenceId || references[0]?.id,
    }),
  })

  const flag = useMutation({
    mutationFn: (paths: string[]) => post(`/api/cases/${slug}/files/flag`,
      // The note lands in the case archive and therefore stays English.
      { paths, note: 'deviation from the reference copy' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['diff'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
    },
  })

  // Without a reference there is nothing to compare — the card then only
  // advertises registering one instead of showing dead controls.
  if (!references.length && !data?.rows.length) {
    return (
      <Card className="flex items-center gap-3 px-4 py-3">
        <GitCompare size={16} className="shrink-0 text-[var(--muted)]" />
        <div className="min-w-0 flex-1 text-[12.5px] text-[var(--muted)]">
          <span className="font-medium text-[var(--fg)]">{tr('diff.empty.lead')}</span>{' '}
          {tr('diff.empty.body')}
        </div>
      </Card>
    )
  }

  const counts = data?.counts ?? {}
  const total = Object.values(counts).reduce((a, b) => a + b, 0)

  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2.5">
        <GitCompare size={15} className="shrink-0 text-[var(--muted)]" />
        <span className="text-[13px] font-semibold">{tr('diff.title')}</span>
        <InfoDot title={tr('diff.title.long')}
          body={tr('diff.title.body')}
          hint={tr('diff.title.hint')} />
        {webroots.length > 1 && (
          <select value={webrootId} onChange={(e) => setWebrootId(Number(e.target.value))}
            className="rounded-lg border border-[var(--line)] bg-[var(--panel)] px-2 py-1 text-[12px] outline-none cursor-pointer">
            {webroots.map((e) => (
              <option key={e.id} value={e.id}>{e.label || e.path}</option>
            ))}
          </select>
        )}
        {references.length > 1 && (
          <select value={referenceId} onChange={(e) => setReferenceId(Number(e.target.value))}
            className="rounded-lg border border-[var(--line)] bg-[var(--panel)] px-2 py-1 text-[12px] outline-none cursor-pointer">
            {references.map((e) => (
              <option key={e.id} value={e.id}>{e.label || e.path}</option>
            ))}
          </select>
        )}
        {references.length > 0 && webroots.length > 0 && (
          <Tooltip hint={tr('diff.run.hint')}>
            <Button variant="primary" disabled={run.isPending}
              onClick={() => run.mutate()}>
              <Play size={13} /> {tr('diff.run')}
            </Button>
          </Tooltip>
        )}
        {data?.ran_at && (
          <span className="ml-auto text-[11px] text-[var(--muted)]">
            {tr('common.last')}: {data.ran_at.replace('T', ' ')}
          </span>
        )}
      </div>

      {total > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 border-b border-[var(--line)] px-4 py-2">
          {(['modified', 'extra', 'missing', 'too_big'] as const).map((s) => (
            counts[s] ? (
              <Tooltip key={s} title={tr(STATUS_KEY[s])} body={tr(`${STATUS_KEY[s]}.hint`)}
                hint={hidden.has(s) ? tr('filter.hidden.back')
                                    : tr('diff.filter.hide')}>
                <Chip active={!hidden.has(s)} dimmed={hidden.has(s)} count={counts[s]}
                  onClick={() => setHidden((prev) => {
                    const next = new Set(prev)
                    if (next.has(s)) next.delete(s)
                    else next.add(s)
                    return next
                  })}>
                  {tr(STATUS_KEY[s])}
                </Chip>
              </Tooltip>
            ) : null
          ))}
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder={tr('diff.filter.path')}
            className="mono ml-auto w-56 rounded-lg border border-[var(--line)] bg-[var(--panel)] px-2.5 py-1 text-[12px] outline-none focus:border-[var(--accent)]/70" />
        </div>
      )}

      {(data?.rows ?? []).map((r) => (
        <div key={r.id}
          className="group flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-1.5 last:border-0 hover:bg-[var(--panel-2)]">
          <Tag tone={STATUS_TONE[r.status]} explain={tr(`${STATUS_KEY[r.status]}.hint`)}>
            {tr(STATUS_KEY[r.status])}
          </Tag>
          <span className="mono min-w-0 flex-1 truncate text-[12px]" title={r.path}>
            {r.path}
          </span>
          {r.in_box && <Tag tone="accent">IOC</Tag>}
          <span className="shrink-0 tabular text-[11px] text-[var(--muted)]">
            {r.status === 'missing' ? formatBytes(r.ref_size) : formatBytes(r.size)}
            {r.status === 'modified' && ` (${tr('diff.reference')} ${formatBytes(r.ref_size)})`}
          </span>
          <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
            {r.absolute && (
              <Button variant="ghost" onClick={() => onView(r.absolute)}>
                <FileSearch size={13} /> {tr('common.view')}
              </Button>
            )}
            {r.absolute && !r.in_box && (
              <Tooltip hint={tr('diff.flag.hint')}>
                <Button variant="ghost" disabled={flag.isPending}
                  onClick={() => flag.mutate([r.absolute])}>
                  <Box size={13} /> IOC
                </Button>
              </Tooltip>
            )}
            {r.in_box && <Check size={13} className="text-[var(--ok)]" />}
          </div>
        </div>
      ))}

      {data && total > 0 && (
        <div className="px-4 py-2 text-[11.5px] text-[var(--muted)]">
          {tr('diff.deviations', { n: formatCount(data.total) })}
          {data.rows.length < data.total && ` — ${tr('diff.capped', { n: formatCount(data.rows.length) })}`}
        </div>
      )}
      {data && total === 0 && data.ran_at && (
        <div className={clsx('px-4 py-3 text-[12.5px] text-[var(--muted)]')}>
          {tr('diff.identical')}
        </div>
      )}
    </Card>
  )
}
