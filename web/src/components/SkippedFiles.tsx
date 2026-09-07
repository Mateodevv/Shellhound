import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, post } from '../api'
import { formatBytes } from '../format'
import { useT } from '../i18n'
import { Button, Tag } from './ui'

interface SkipEntry {
  id?: number
  path: string
  reason: string
  category?: 'file' | 'rule' | 'discovery' | 'other'
  status?: 'unresolved' | 'accepted' | 'resolved' | 'retrying'
  group?: 'size_limit' | 'other'
  retryable?: boolean
  acceptable?: boolean
  forceable?: boolean
  size_bytes?: number
  limit_bytes?: number
  action_reason?: string
  latest_reason?: string
  retry_job_id?: number
}

interface SkipDetails {
  items: SkipEntry[]
  total: number
  recorded: boolean
  unresolved?: number
  retryable?: number
  busy?: boolean
  blocked_reason?: string
  counts?: { size_limit: number; other: number; accepted: number }
  selection_ids?: { retryable: number[]; acceptable: number[]; forceable: number[] }
}

type Group = 'all' | 'size_limit' | 'other'
type Status = 'pending' | 'accepted' | 'all'
type Action = { kind: 'retry' | 'force' | 'accept'; mode: 'all' | 'selected'; ids?: number[] }

/** A new identity gets fresh UI state; polling the same job keeps selections. */
export function SkippedFiles({ slug, jobId }: { slug: string; jobId: number }) {
  return <SkippedFilesList key={`${slug}:${jobId}`} slug={slug} jobId={jobId} />
}

function SkippedFilesList({ slug, jobId }: { slug: string; jobId: number }) {
  const tr = useT()
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [offset, setOffset] = useState(0)
  const [group, setGroup] = useState<Group>('all')
  const [status, setStatus] = useState<Status>('pending')
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const { data, isPending, isError, refetch } = useQuery({
    queryKey: ['job-skips', slug, jobId, group, status, offset],
    queryFn: () => api<SkipDetails>(`/api/cases/${slug}/jobs/${jobId}/skipped?offset=${offset}&limit=100&group=${group}&status=${status}`),
    enabled: open,
    refetchInterval: open ? 4000 : false,
  })
  useEffect(() => {
    // Choose the useful first group once; polling must not move the analyst's view.
    if (group === 'all' && data?.counts) setGroup(data.counts.size_limit > 0 ? 'size_limit' : 'other')
  }, [data, group])
  useEffect(() => {
    const resolved = data?.items.filter((item) => item.status === 'resolved').map((item) => item.id) ?? []
    const eligible = data?.selection_ids ? new Set(Object.values(data.selection_ids).flat()) : undefined
    if (!resolved.length && !eligible) return
    setSelected((current) => {
      const next = new Set([...current].filter((id) => eligible ? eligible.has(id) : !resolved.includes(id)))
      return next.size === current.size ? current : next
    })
  }, [data])
  useEffect(() => {
    if (data && offset >= data.total && offset > 0) setOffset(Math.max(0, Math.ceil(data.total / 100 - 1) * 100))
  }, [data, offset])
  const action = useMutation({
    mutationFn: ({ kind, mode, ids }: Action) => {
      const selection = mode === 'all' ? { mode } : { mode, ids: ids ?? [...selected] }
      return post<{ jobs?: number[]; run_id?: string }>(
        `/api/cases/${slug}/jobs/${jobId}/${kind === 'accept' ? 'accept-skipped' : 'retry-skipped'}`,
        data?.counts ? { ...selection, group, status,
          ...(kind === 'accept' ? {} : { allow_large_files: kind === 'force' }) } : selection)
    },
    onSuccess: () => {
      setSelected(new Set())
      for (const key of ['job-skips', 'jobs', 'case', 'dashboard']) {
        qc.invalidateQueries({ queryKey: [key, slug] })
      }
    },
    onError: () => qc.invalidateQueries({ queryKey: ['job-skips', slug, jobId] }),
  })
  const busy = Boolean(data?.busy || action.isPending)
  const blocked = Boolean(data?.blocked_reason)
  const grouped = Boolean(data?.counts)
  const eligible = data?.selection_ids
  const selectable = [...new Set(eligible ? group === 'size_limit'
    ? [...eligible.acceptable, ...eligible.forceable] : eligible.retryable : [])]
  const selectedFor = (kind: keyof NonNullable<SkipDetails['selection_ids']>) =>
    (eligible?.[kind] ?? []).filter((id) => selected.has(id))
  const acceptIds = selectedFor('acceptable')
  const forceIds = selectedFor('forceable')
  const retryIds = selectedFor('retryable')
  const changeFilter = (nextGroup: Group, nextStatus: Status) => {
    setGroup(nextGroup)
    setStatus(nextStatus)
    setOffset(0)
    setSelected(new Set())
    action.reset()
  }
  const select = (id: number, checked: boolean) => {
    setSelected((current) => {
      const next = new Set(current)
      if (checked) next.add(id)
      else next.delete(id)
      return next
    })
    action.reset()
  }

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
          {data.counts && <>
            <div className="flex flex-wrap items-center gap-2">
              {(['size_limit', 'other'] as const).map((value) => <Button key={value}
                variant={group === value ? 'primary' : 'ghost'} aria-pressed={group === value}
                disabled={action.isPending} onClick={() => changeFilter(value, 'pending')}>
                {tr(`evidence.skips.group.${value}`, { n: data.counts![value] })}
              </Button>)}
              <label className="ml-auto flex flex-wrap items-center gap-2 text-[var(--muted)]">
                {tr('evidence.skips.show')}
                <select aria-label={tr('evidence.skips.show')} value={status} disabled={action.isPending}
                  onChange={(event) => changeFilter(group, event.target.value as Status)}
                  className="rounded-md border border-[var(--line)] bg-[var(--panel)] px-2 py-1 text-[var(--fg)]">
                  <option value="pending">{tr('evidence.skips.filter.pending')}</option>
                  <option value="accepted">{tr('evidence.skips.filter.accepted', { n: data.counts.accepted })}</option>
                  <option value="all">{tr('evidence.skips.filter.all')}</option>
                </select>
              </label>
            </div>
            <p className="my-3 text-[var(--muted)]">{tr(group === 'size_limit'
              ? 'evidence.skips.sizeHelp' : 'evidence.skips.otherHelp')}</p>
          </>}
          {!data.recorded && <p className="text-[var(--muted)]">{tr('evidence.skips.legacy')}</p>}
          {data.recorded && data.total === 0 && <p className="text-[var(--muted)]">
            {tr(grouped ? 'evidence.skips.filteredEmpty' : 'evidence.skips.empty')}
          </p>}
          {data.total > 0 && <>
            {!grouped && data.unresolved !== undefined && <p className="mb-2 text-[var(--muted)]">
              {tr(data.unresolved ? 'evidence.skips.unresolvedCount' : 'evidence.skips.resolvedAll', { n: data.unresolved })}
            </p>}
            {grouped && <div className="mb-3 flex flex-wrap items-center gap-2">
              <Button disabled={busy || selectable.length === 0} onClick={() => {
                setSelected(new Set(selectable))
                action.reset()
              }}>{tr('evidence.skips.selectAll', { n: selectable.length })}</Button>
              <span className="text-[var(--muted)]">{tr('evidence.skips.selectionCount', { n: selected.size })}</span>
              {selected.size > 0 && <Button variant="ghost" disabled={busy}
                onClick={() => setSelected(new Set())}>{tr('evidence.skips.clearSelection')}</Button>}
            </div>}
            <ul className="max-h-64 overflow-auto divide-y divide-[var(--line)]">
              {data.items.map((item, index) => <li key={item.id ?? offset + index} className="flex items-start gap-2 py-2 first:pt-0">
                {item.id !== undefined && (item.category === 'file' || grouped && selectable.includes(item.id)) && <input type="checkbox"
                  className="mt-1 shrink-0 accent-[var(--accent)]"
                  aria-label={tr(grouped ? 'evidence.skips.selectFile' : 'evidence.skips.select', { path: item.path })}
                  disabled={busy || (grouped ? !selectable.includes(item.id) : !item.retryable || blocked)}
                  checked={selected.has(item.id)}
                  onChange={(event) => select(item.id!, event.target.checked)} />}
                <div className="min-w-0 flex-1">
                  <div className="mono break-all text-[var(--fg)]">{item.path}</div>
                  <div className="mt-1 break-words text-[var(--muted)]">{item.reason}</div>
                  {item.size_bytes != null && item.limit_bytes != null && <div className="mt-1 text-[var(--muted)]">
                    {tr('evidence.skips.size', { size: formatBytes(item.size_bytes), limit: formatBytes(item.limit_bytes) })}
                  </div>}
                  {item.latest_reason && item.latest_reason !== item.reason && <div className="mt-1 break-words text-[var(--muted)]">
                    {tr('evidence.skips.latestReason', { reason: item.latest_reason })}
                  </div>}
                  {item.action_reason && item.action_reason !== item.reason && item.action_reason !== item.latest_reason && (
                    <p className="mt-1 break-words text-[var(--muted)]">{item.action_reason}</p>
                  )}
                  {item.status && <div className="mt-1 flex flex-wrap items-center gap-2">
                    <Tag tone={item.status === 'resolved' ? 'ok' : item.status === 'accepted' ? undefined : 'warn'}>{tr(`evidence.skips.${item.status}`)}</Tag>
                    {item.retry_job_id != null && <span className="text-[var(--muted)]">
                      {tr('evidence.skips.retryJob', { id: item.retry_job_id })}
                    </span>}
                  </div>}
                </div>
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
            {grouped && <div className="mt-3 border-t border-[var(--line)] pt-3">
              <div className="flex flex-wrap gap-2">
                {group === 'size_limit' ? <>
                  <Button disabled={busy || acceptIds.length === 0}
                    onClick={() => action.mutate({ kind: 'accept', mode: 'selected', ids: acceptIds })}>
                    {tr('evidence.skips.acceptSelected', { n: acceptIds.length })}
                  </Button>
                  <Button disabled={busy || forceIds.length === 0}
                    onClick={() => action.mutate({ kind: 'force', mode: 'selected', ids: forceIds })}>
                    {tr('evidence.skips.forceSelected', { n: forceIds.length })}
                  </Button>
                </> : <Button disabled={busy || retryIds.length === 0}
                  onClick={() => action.mutate({ kind: 'retry', mode: 'selected', ids: retryIds })}>
                  {tr('evidence.skips.retrySelected', { n: retryIds.length })}
                </Button>}
              </div>
              <p className="mt-2 text-[11px] text-[var(--muted)]">{tr(group === 'size_limit'
                ? 'evidence.skips.overrideHelp' : 'evidence.skips.limits')}</p>
            </div>}
            {!grouped && data.retryable !== undefined && <div className="mt-3 border-t border-[var(--line)] pt-3">
              <div className="flex flex-wrap gap-2">
                <Button disabled={busy || blocked || data.retryable === 0}
                  onClick={() => action.mutate({ kind: 'retry', mode: 'all' })}>{tr('evidence.skips.retryAll', { n: data.retryable })}</Button>
                <Button disabled={busy || blocked || selected.size === 0}
                  onClick={() => action.mutate({ kind: 'retry', mode: 'selected' })}>{tr('evidence.skips.retrySelected', { n: selected.size })}</Button>
                {selected.size > 0 && <Button variant="ghost" disabled={action.isPending}
                  onClick={() => setSelected(new Set())}>{tr('evidence.skips.clearSelection')}</Button>}
              </div>
              <p className="mt-2 text-[11px] text-[var(--muted)]">{tr('evidence.skips.limits')}</p>
            </div>}
          </>}
          {data.blocked_reason && <p className="mt-2 text-[var(--sev-low)]">{data.blocked_reason}</p>}
          {data.busy && <p role="status" className="mt-2 text-[var(--muted)]">{tr('evidence.skips.busy')}</p>}
        </>}
        {action.isError && <p role="alert" className="mt-2 text-[var(--danger-text)]">{action.error.message}</p>}
        {action.isSuccess && <p role="status" className="mt-2 text-[var(--muted)]">
          {tr(action.variables.kind === 'accept' ? 'evidence.skips.acceptedDone'
            : action.data.jobs?.length ? 'evidence.skips.started' : 'evidence.skips.nothingToRetry')}
        </p>}
      </div>}
    </div>
  )
}
