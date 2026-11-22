import { useEffect, useRef, useState } from 'react'
import { useT } from '../../i18n'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, post } from '../../api'
import { useLogSources } from '../logview/useLogSources'
import { Button, Tag } from '../ui/ui'

type Group = 'manual_review' | 'unsupported' | 'processing_error'
type Selection = { source_id: string; warning_key: string }
type Details = { items: Array<{ id: number; path: string; reason: string; status: 'unresolved' | 'accepted' | 'historical'; source_id: string; warning_key: string; current_source_warning?: boolean }>; total: number; busy?: boolean; counts: Record<Group | 'accepted', number>; selection_ids: { retryable: number[]; acceptable: number[]; reopenable: number[] }; selection_warnings: Record<string, Selection> }

export function LogWarnings({ slug, jobId, initiallyOpen = false, initialStatus = 'pending' }: { slug: string; jobId: number; initiallyOpen?: boolean; initialStatus?: 'pending' | 'accepted' | 'all' }) {
  const tr = useT()
  const qc = useQueryClient()
  const sources = useLogSources(slug)
  const [open, setOpen] = useState(initiallyOpen)
  const [group, setGroup] = useState<Group>('manual_review')
  const groupChosen = useRef(false)
  const [status, setStatus] = useState<'pending' | 'accepted' | 'all'>(initialStatus)
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<Map<number, Selection>>(new Map())
  const query = useQuery({ queryKey: ['job-skips', slug, jobId, group, status, offset], enabled: open,
    queryFn: () => api<Details>(`/api/cases/${slug}/jobs/${jobId}/skipped?offset=${offset}&limit=100&group=${group}&status=${status}`), refetchInterval: open ? 4000 : false })
  const details = query.data
  const eligible = details?.selection_ids
  const selectable = [...new Set([...(eligible?.acceptable ?? []), ...(eligible?.reopenable ?? []), ...(eligible?.retryable ?? [])])]
  const matches = (id: number, value: Selection) => {
    const latest = details?.selection_warnings[String(id)]
    return selectable.includes(id) && latest?.source_id === value.source_id && latest.warning_key === value.warning_key
  }
  useEffect(() => {
    if (!details) return
    if (!groupChosen.current) {
      groupChosen.current = true
      const first = (['manual_review', 'unsupported', 'processing_error'] as const).find(value => details.counts[value] > 0)
      if (first && first !== group) { setGroup(first); setOffset(0) }
    }
    setSelected(current => new Map([...current].filter(([id, value]) => matches(id, value))))
  }, [details]) // eslint-disable-line react-hooks/exhaustive-deps
  const action = useMutation({ mutationFn: ({ kind, ids }: { kind: 'accept' | 'reopen' | 'retry'; ids: number[] }) => {
    const selections = ids.map(id => selected.get(id)).filter((value): value is Selection => !!value)
    if (selections.length !== ids.length || ids.some(id => !matches(id, selected.get(id)!))) throw new Error(tr('logWarnings.stale'))
    return kind === 'retry' ? post(`/api/cases/${slug}/log-sources/analyze`, { source_ids: selections.map(s => s.source_id), warning_selections: selections })
      : post(`/api/cases/${slug}/log-sources/review-warnings`, { decision: kind, selections })
  }, onSuccess: () => setSelected(new Map()), onSettled: () => { for (const key of ['job-skips', 'jobs', 'case', 'dashboard', 'log-sources']) void qc.invalidateQueries({ queryKey: [key, slug] }) } })
  const ids = (kind: keyof NonNullable<typeof eligible>) => (eligible?.[kind] ?? []).filter(id => { const value = selected.get(id); return value && matches(id, value) })
  const disabled = query.isError || query.isFetching || action.isPending || !!details?.busy
  const change = (nextGroup: Group, nextStatus: typeof status) => { groupChosen.current = true; setGroup(nextGroup); setStatus(nextStatus); setOffset(0); setSelected(new Map()); action.reset() }
  return <div className="mt-2 text-xs">
    <button className="font-medium text-[var(--accent-text)] hover:underline" aria-expanded={open} onClick={() => setOpen(!open)}>{tr('logWarnings.show')}</button>
    {open && <div className="mt-2 rounded-lg border border-[var(--line)] p-3 space-y-3">
      {query.isPending && <p role="status">{tr('common.loading')}</p>}
      {query.isError && <div role="alert">{query.error.message} <Button onClick={() => void query.refetch()}>{tr('common.retry')}</Button></div>}
      {details && <>
        <div className="flex flex-wrap gap-2">{(['manual_review', 'unsupported', 'processing_error'] as const).map(value => <Button key={value} aria-pressed={group === value} variant={group === value ? 'primary' : 'ghost'} onClick={() => change(value, 'pending')}>{tr(`logWarnings.group.${value}`, { n: details.counts[value] })}</Button>)}
          <label className="ml-auto">{tr('evidence.skips.show')} <select aria-label={tr('logWarnings.filter')} className="rounded border border-[var(--line)] bg-[var(--panel)] p-1" value={status} onChange={e => change(group, e.target.value as typeof status)}><option value="pending">{tr('evidence.skips.filter.pending')}</option><option value="accepted">{tr('evidence.skips.filter.accepted', { n: details.counts.accepted })}</option><option value="all">{tr('evidence.skips.filter.all')}</option></select></label></div>
        <div className="flex flex-wrap items-center gap-2"><Button disabled={disabled || !selectable.length} onClick={() => setSelected(new Map(selectable.map(id => [id, details.selection_warnings[String(id)]]).filter(([, value]) => !!value) as Array<[number, Selection]>))}>{tr('evidence.skips.selectAll', { n: selectable.length })}</Button><span>{tr('evidence.skips.selectionCount', { n: selected.size })}</span><Button disabled={disabled || !selected.size} onClick={() => setSelected(new Map())}>{tr('evidence.skips.clearSelection')}</Button></div>
        {!details.total && <p>{tr('logWarnings.empty')}</p>}
        <ul className="max-h-64 divide-y divide-[var(--line)] overflow-auto">{details.items.map(item => { const source = sources.data?.sources.find(s => s.id === item.source_id); const params = new URLSearchParams({ case: slug, view: 'logs', section: source?.family || 'text', source: item.source_id }); const settings = new URLSearchParams({ case: slug, view: 'evidence', source: item.source_id }); return <li key={item.id} className="flex gap-2 py-2"><input aria-label={tr('evidence.skips.selectFile', { path: item.path })} type="checkbox" disabled={disabled || !selectable.includes(item.id)} checked={!!selected.get(item.id) && matches(item.id, selected.get(item.id)!)} onChange={e => setSelected(old => { const next = new Map(old); if (e.target.checked && details.selection_warnings[String(item.id)]) next.set(item.id, details.selection_warnings[String(item.id)]); else next.delete(item.id); return next })} /><div className="min-w-0"><p className="break-all">{item.path}</p><p className="break-words text-[var(--muted)]">{item.reason}</p><Tag>{item.current_source_warning ? tr('logWarnings.currentSource') : tr(`logWarnings.status.${item.status}`)}</Tag>{item.source_id && group !== 'unsupported' && <div className="mt-1 flex flex-wrap gap-3">{group === 'manual_review' && <a className="text-[var(--accent-text)] underline" href={`?${params}`}>{tr('logWarnings.openLogs')}</a>}<a className="text-[var(--accent-text)] underline" href={`?${settings}`}>{tr('logWarnings.settings')}</a></div>}</div></li> })}</ul>
        {details.total > 100 && <div className="flex gap-2"><Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>{tr('evidence.skips.previous')}</Button><span>{offset + 1}–{offset + details.items.length} / {details.total}</span><Button disabled={offset + details.items.length >= details.total} onClick={() => setOffset(offset + 100)}>{tr('evidence.skips.next')}</Button></div>}
        <div className="flex flex-wrap gap-2">
          {status !== 'accepted' && <Button disabled={disabled || !ids('acceptable').length} onClick={() => action.mutate({ kind: 'accept', ids: ids('acceptable') })}>{tr('logWarnings.accept', { n: ids('acceptable').length })}</Button>}
          {status !== 'pending' && <Button disabled={disabled || !ids('reopenable').length} onClick={() => action.mutate({ kind: 'reopen', ids: ids('reopenable') })}>{tr('logWarnings.reopen', { n: ids('reopenable').length })}</Button>}
          {group === 'processing_error' && <Button disabled={disabled || !ids('retryable').length} onClick={() => action.mutate({ kind: 'retry', ids: ids('retryable') })}>{tr('logWarnings.retry', { n: ids('retryable').length })}</Button>}
        </div>
      </>}
      {action.isError && <p role="alert" className="text-[var(--danger-text)]">{action.error.message}</p>}
    </div>}
  </div>
}
