import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Eraser, RefreshCw } from 'lucide-react'
import { post, type Ioc } from '../api'
import { useT } from '../i18n'
import { openCtiKey, safeCtiUrl, useOpenCti } from '../opencti'
import { Button, Tag, Tabs } from './ui'
import { CtiError } from './CaseProfile'
import { Tooltip } from './Tooltip'
import { IocTypeBadge } from './IocTypeBadge'

const terminal = new Set(['done', 'complete', 'completed', 'failed', 'error', 'partial', 'cancelled'])
const failed = new Set(['failed', 'error', 'partial'])
const stamp = (value?: string) => value ? value.replace('T', ' ').replace(/\.\d+(Z)?$/, '$1') : '—'

function ActivityError({ error }: { error?: string }) {
  const tr = useT()
  if (!error) return null
  return <details className="mt-1"><summary className="cursor-pointer text-[var(--danger-text)]">{tr('ctiActivity.errorDetails')}</summary><div className="mt-2"><CtiError error={error} /></div></details>
}

export function OpenCtiActivity({ slug, iocs, allowRetry = false }: { slug: string; iocs: Ioc[]; allowRetry?: boolean }) {
  const tr = useT()
  const qc = useQueryClient()
  const status = useOpenCti(slug)
  const [tab, setTab] = useState('jobs')
  const invalidate = () => qc.invalidateQueries({ queryKey: openCtiKey(slug) })
  const clear = useMutation({ mutationFn: () => post<{ cleared: number }>(`/api/cases/${slug}/opencti/activity/clear`, {}), onSuccess: invalidate })
  const refresh = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/enrichment/status`, {}), onSuccess: invalidate })
  const retry = useMutation({ mutationFn: (export_id: string) => post(`/api/cases/${slug}/opencti/retry`, { export_id }), onSuccess: invalidate })
  const jobs = (status.data?.jobs ?? []).filter(entry => !entry.activity_hidden)
  const enrichments = (status.data?.enrichments ?? []).filter(entry => !entry.activity_hidden)
  const exports = (status.data?.exports ?? []).filter(entry => !entry.activity_hidden)
  const entries = [...jobs, ...enrichments, ...exports]
  const clearable = entries.filter(entry => terminal.has(entry.state)).length
  const tabs = [{ id: 'jobs', label: 'cti.jobs', count: jobs.length }, { id: 'enrichments', label: 'cti.connectorJobs', count: enrichments.length }, { id: 'exports', label: 'cti.exportHistory', count: exports.length }]
  const badge = (state: string) => <Tag tone={failed.has(state) ? 'danger' : ['done', 'complete', 'completed'].includes(state) ? 'ok' : ['queued', 'running'].includes(state) ? 'accent' : undefined}>{tr(`ctiActivity.state.${state}`) === `ctiActivity.state.${state}` ? state : tr(`ctiActivity.state.${state}`)}</Tag>
  return <section className="space-y-3 text-[12px]" aria-label={tr('ctiActivity.title')}>
    <div className="flex flex-wrap items-center justify-between gap-2">
      <p className="text-[var(--muted)]">{tr('ctiActivity.summary', { n: entries.length, running: entries.filter(entry => !terminal.has(entry.state)).length })}</p>
      <div className="flex items-center gap-2">
        <Button disabled={refresh.isPending || !enrichments.length} onClick={() => refresh.mutate()}><RefreshCw size={13} className={refresh.isPending ? 'animate-spin' : ''} />{tr('cti.refreshEnrichment')}</Button>
        <Tooltip body={tr('ctiActivity.clearHelp')}><span><Button disabled={clear.isPending || !clearable} onClick={() => clear.mutate()}><Eraser size={13} />{tr('ctiActivity.clear')}</Button></span></Tooltip>
      </div>
    </div>
    <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={tabs.map(item => ({ id: item.id, label: tr(item.label), badge: <span className="ml-2 text-[var(--muted)]">{item.count}</span> }))} /></div>
    <CtiError error={clear.error || refresh.error || retry.error} />
    {clear.isSuccess && <p role="status" className="text-[var(--muted)]">{tr('ctiActivity.cleared', { n: clear.data.cleared })}</p>}
    <div role="tabpanel" aria-label={tr(tabs.find(item => item.id === tab)!.label)} className="h-[min(42vh,360px)] min-h-40 overflow-auto rounded-lg border border-[var(--line)] [scrollbar-gutter:stable]">
      <table className="ioc-relationships w-full text-left text-[12px]">
        <thead className="sticky top-0 z-10"><tr><th className="w-28">{tr('ctiActivity.status')}</th><th>{tr(tab === 'enrichments' ? 'iocTable.object' : 'ctiActivity.operation')}</th><th>{tr(tab === 'enrichments' ? 'ctiActivity.connector' : 'ctiActivity.details')}</th><th className="w-44">{tr('ctiActivity.updated')}</th></tr></thead>
        <tbody>
          {tab === 'jobs' && jobs.map(job => <tr key={job.id}>
            <td className="align-top">{badge(job.state)}</td>
            <td className="align-top font-medium">{tr(`ctiActivity.kind.${job.kind}`) === `ctiActivity.kind.${job.kind}` ? job.kind : tr(`ctiActivity.kind.${job.kind}`)}</td>
            <td className="min-w-48 max-w-lg break-words"><p>{job.message || '—'}</p>{['queued', 'running'].includes(job.state) && <progress className="mt-2 h-1.5 w-full accent-[var(--accent)]" aria-label={tr('ctiActivity.progress')} max={1} value={job.progress} />}<ActivityError error={job.error} /></td>
            <td className="align-top text-[var(--muted)]">{stamp(job.finished || job.started || job.created)}</td>
          </tr>)}
          {tab === 'enrichments' && enrichments.map(entry => { const ioc = iocs.find(ioc => ioc.id === entry.ioc_id); return <tr key={entry.id}>
            <td className="align-top">{badge(entry.state)}</td>
            <td className="max-w-sm align-top"><div className="flex items-start gap-2">{ioc && <IocTypeBadge type={ioc.type} value={ioc.value} />}<span className="break-all font-medium">{ioc?.value || tr('ctiActivity.unavailable')}</span></div></td>
            <td><span title={entry.connector_id}>{entry.connector_name || tr('cti.connectorJob', { id: entry.connector_id.slice(0, 8) })}</span><ActivityError error={entry.error} />{safeCtiUrl(entry.url) && <a href={safeCtiUrl(entry.url)} target="_blank" rel="noopener noreferrer" className="ml-2 text-[var(--accent-text)]">{tr('cti.openJob')}</a>}</td>
            <td className="align-top text-[var(--muted)]">{stamp(entry.updated)}</td>
          </tr> })}
          {tab === 'exports' && exports.map(entry => <tr key={entry.id}>
            <td className="align-top">{badge(entry.state)}</td>
            <td className="align-top font-medium">{tr('ctiActivity.transfer', { n: Number(entry.stats?.objects ?? 0) })}</td>
            <td><ActivityError error={entry.error} />{allowRetry && ['failed', 'partial', 'error', 'pending', 'paused'].includes(entry.state) && <Button disabled={retry.isPending} onClick={() => retry.mutate(entry.id)}>{tr('cti.retry')}</Button>}<TransferReceiptDetails stats={entry.stats} /></td>
            <td className="align-top text-[var(--muted)]">{stamp(entry.updated || entry.created)}</td>
          </tr>)}
          {!tabs.find(item => item.id === tab)!.count && <tr><td colSpan={4} className="h-32 text-center text-[var(--muted)]">{tr(status.isPending ? 'common.loading' : 'ctiActivity.empty')}</td></tr>}
        </tbody>
      </table>
    </div>
  </section>
}

function TransferReceiptDetails({ stats }: { stats: Record<string, unknown> }) {
  const tr = useT()
  const batches = (Array.isArray(stats?.batches) ? stats.batches : []) as { state: string; ids: string[]; work_id?: string; status?: { success_count?: number; failure_count?: number; pending_count?: number } }[]
  const samples = (Array.isArray(stats?.samples) ? stats.samples : []) as { id: string; display_path: string; state: string }[]
  const descriptions = (Array.isArray(stats?.descriptions) ? stats.descriptions : []) as { source_id: string; state: string; error?: string }[]
  if (!batches.length && !samples.length && !descriptions.length) return null
  return <details className="w-full rounded border border-[var(--line)] p-2"><summary className="cursor-pointer">{tr('cti.transferDetails')}</summary>
    <div className="mt-2 flex flex-col gap-2">{batches.map((batch, index) => <div key={index}>
      <p>{tr('cti.batch', { n: index + 1, count: batch.ids?.length ?? 0 })} · {batch.state}</p>
      {batch.status && <p className="text-[var(--muted)]">{tr('cti.batchCounts', { done: batch.status.success_count ?? 0, failed: batch.status.failure_count ?? 0, pending: batch.status.pending_count ?? 0 })}</p>}
      {batch.work_id && <p className="break-all text-[var(--muted)]">{tr('cti.workId')}: <code>{batch.work_id}</code></p>}
    </div>)}{samples.map((sample) => <p key={sample.id}>{sample.display_path} · {sample.state}</p>)}
    {!!descriptions.length && <p>{tr('cti.descriptionCounts', { done: descriptions.filter((d) => d.state === 'complete').length, total: descriptions.length })}</p>}
    {descriptions.filter((d) => d.error).map((d) => <p key={d.source_id} className="text-[var(--warn)]">{d.error}</p>)}
    </div>
  </details>
}
