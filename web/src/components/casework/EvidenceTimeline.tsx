import { useEffect, useId, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, Flag } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api, type FirstSign, type TimelineCounts, type TimelinePreview } from '../../api'
import type { Navigate } from '../../App'
import { formatCount, formatLogTime } from '../../format'
import { useT } from '../../i18n'
import { Button } from '../ui/ui'

const SERIES = [
  { key: 'filesystem_confirmed', source: 'filesystem', scope: 'confirmed', color: 'var(--sev-medium)', label: 'dashboardTimeline.filesConfirmed' },
  { key: 'filesystem_pending', source: 'filesystem', scope: 'pending', color: 'var(--muted)', label: 'dashboardTimeline.filesPending' },
  { key: 'log_confirmed', source: 'log', scope: 'confirmed', color: 'var(--danger-text)', label: 'dashboardTimeline.logsConfirmed' },
  { key: 'log_pending', source: 'log', scope: 'pending', color: 'var(--review-text)', label: 'dashboardTimeline.logsPending' },
] as const

const time = (epoch: number) => formatLogTime(epoch, 0, { mode: 'utc', withZone: true })
const range = (start: number, end: number) => `${time(start)} – ${time(end)}`

/** Buckets are calculated over the complete event set, never the current page.
 * The selectors provide the same drill-down as clicking a chart segment. */
export function EvidenceTimeline({ slug, firstSign, gotoView }: {
  slug: string; firstSign?: FirstSign; gotoView: Navigate
}) {
  const tr = useT()
  const id = useId()
  const [narrow, setNarrow] = useState(() => window.matchMedia('(max-width: 640px)').matches)
  const [interval, setInterval] = useState('')
  const [seriesKey, setSeriesKey] = useState<keyof TimelineCounts>('filesystem_confirmed')
  useEffect(() => {
    const media = window.matchMedia('(max-width: 640px)')
    const change = () => setNarrow(media.matches)
    media.addEventListener('change', change)
    return () => media.removeEventListener('change', change)
  }, [])
  const bins = narrow ? 12 : 24
  const query = useQuery({
    queryKey: ['timeline-preview', slug, bins],
    queryFn: () => api<TimelinePreview>(`/api/cases/${slug}/timeline-preview?bins=${bins}`),
    refetchInterval: 10000,
  })
  const data = query.data
  if (query.isError) return <div className="mt-5 rounded-lg border border-[var(--line)] p-5">
    <p role="alert" className="text-sm text-[var(--review-text)]">{tr('dashboardTimeline.error')}</p>
    <Button className="mt-3" onClick={() => void query.refetch()}>{tr('common.retry')}</Button>
  </div>
  if (!data) return <div role="status" className="mt-5 flex h-48 items-center justify-center rounded-lg bg-[var(--panel-2)] text-sm text-[var(--muted)]">{tr('dashboardTimeline.loading')}</div>

  const total = Object.values(data.totals).reduce((sum, value) => sum + value, 0)
  const bucket = data.buckets.find(item => String(item.start) === interval) ?? data.buckets[0]
  const series = SERIES.find(item => item.key === seriesKey)!
  const selectedCount = bucket?.[seriesKey] ?? 0
  const signEpoch = firstSign?.state !== 'stale_override' && firstSign?.event?.fresh !== false ? firstSign?.event?.epoch : null
  const signBucket = signEpoch == null ? undefined : data.buckets.find(item => signEpoch >= item.start && signEpoch < item.end)
  const plottedSign = !!signBucket
  const open = (start: number, end: number, selected: typeof SERIES[number]) => gotoView('timeline', {
    scope: selected.scope, event_source: selected.source, from_epoch: String(start), to_epoch: String(end),
  })

  return <div className="mt-5">
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <p className="text-sm font-semibold">{tr('dashboardTimeline.events')}</p>
      <span className="text-xs text-[var(--muted)]">{tr('dashboardTimeline.zone')}</span>
    </div>
    <p className="mt-1 text-xs leading-relaxed text-[var(--muted)]">{tr('dashboardTimeline.meaning')}</p>
    {total > 0 && data.buckets.length > 0 ? <>
      <div className="mt-5 h-[260px] min-w-0" role="img" aria-label={tr('dashboardTimeline.chartLabel', { n: formatCount(total) })}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data.buckets.map(item => ({ ...item, position: (item.start + item.end) / 2 }))} margin={{ top: plottedSign ? 22 : 10, right: 10, bottom: 0, left: 0 }} barCategoryGap="24%" barGap={3} accessibilityLayer={false}>
            <CartesianGrid stroke="var(--line-soft)" vertical={false} />
            <XAxis dataKey="position" type="number" domain={[data.buckets[0].start, data.buckets.at(-1)!.end]} scale="time"
              ticks={data.buckets.map(item => item.start)} tickLine={false} axisLine={{ stroke: 'var(--line)' }} minTickGap={narrow ? 32 : 24}
              tick={{ fill: 'var(--muted)', fontSize: 11 }} tickFormatter={(value: number) => {
                const date = new Date(value * 1000).toISOString()
                return data.interval < 86400 ? `${date.slice(5, 10)} ${date.slice(11, 16)}` : date.slice(0, 10)
              }} />
            <YAxis allowDecimals={false} width={56} tickLine={false} axisLine={false} tick={{ fill: 'var(--muted)', fontSize: 11 }}
              label={{ value: tr('dashboardTimeline.events'), angle: -90, position: 'insideLeft', fill: 'var(--muted)', fontSize: 10 }} />
            <Tooltip cursor={{ fill: 'var(--accent-soft)' }} content={({ active, payload }) => {
              const item = payload?.[0]?.payload as TimelinePreview['buckets'][number] | undefined
              return active && item ? <div className="max-w-80 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 text-xs shadow-xl">
                <p className="font-semibold tabular">{range(item.start, item.end)}</p>
                <p className="mt-1 text-[var(--muted)]">{tr('dashboardTimeline.exclusive')}</p>
                {SERIES.map(entry => <p key={entry.key} className="mt-2 flex items-center justify-between gap-4" style={{ color: entry.color }}>
                  <span>{tr(entry.label)}</span><strong className="tabular">{formatCount(item[entry.key])}</strong>
                </p>)}
              </div> : null
            }} />
            {SERIES.map(entry => <Bar key={entry.key} dataKey={entry.key} stackId={entry.source} fill={entry.color}
              name={tr(entry.label)} maxBarSize={30} isAnimationActive={false} cursor="pointer"
              onClick={(_item, index) => { const selected = data.buckets[index]; if (selected?.[entry.key]) open(selected.start, selected.end, entry) }} />)}
            {signBucket && <ReferenceLine x={(signBucket.start + signBucket.end) / 2} stroke="var(--accent-text)" strokeDasharray="4 3"
              label={{ value: '⚑', position: 'top', fill: 'var(--accent-text)', fontSize: 18 }} />}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-2 text-xs" aria-label={tr('dashboardTimeline.legend')}>
        {SERIES.map(entry => <li key={entry.key} className="flex items-center gap-2">
          <span aria-hidden="true" className="h-2.5 w-2.5 rounded-sm" style={{ background: entry.color }} />
          <span className="text-[var(--muted)]">{tr(entry.label)}</span>
          <strong className="tabular" style={{ color: entry.color }}>{formatCount(data.totals[entry.key])}</strong>
        </li>)}
      </ul>
      {plottedSign && <p className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--accent-text)]">
        <Flag size={13} /><span>{tr('firstSign.title')}: <span className="tabular">{time(signEpoch!)}</span></span>
      </p>}
      <div className="mt-5 flex flex-wrap items-end gap-3 border-t border-[var(--line-soft)] pt-4">
        <label htmlFor={`${id}-interval`} className="flex min-w-0 flex-1 basis-64 flex-col gap-1 text-xs text-[var(--muted)]">
          {tr('dashboardTimeline.interval')}
          <select id={`${id}-interval`} value={bucket ? String(bucket.start) : ''} onChange={event => setInterval(event.target.value)}
            className="min-w-0 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-2 text-xs text-[var(--fg)]">
            {data.buckets.map(item => <option key={item.start} value={String(item.start)}>{range(item.start, item.end)}</option>)}
          </select>
        </label>
        <label htmlFor={`${id}-series`} className="flex min-w-0 flex-1 basis-56 flex-col gap-1 text-xs text-[var(--muted)]">
          {tr('dashboardTimeline.sourceDecision')}
          <select id={`${id}-series`} value={seriesKey} onChange={event => setSeriesKey(event.target.value as keyof TimelineCounts)}
            className="min-w-0 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-2 text-xs text-[var(--fg)]">
            {SERIES.map(entry => <option key={entry.key} value={entry.key}>{tr(entry.label)}</option>)}
          </select>
        </label>
        <Button disabled={!selectedCount} onClick={() => { if (bucket) open(bucket.start, bucket.end, series) }}>
          {tr(selectedCount === 1 ? 'dashboardTimeline.viewOneEvent' : 'dashboardTimeline.viewEvents', { n: formatCount(selectedCount) })}<ArrowRight size={14} />
        </Button>
      </div>
      <p className="mt-2 text-xs text-[var(--muted)]">{tr('dashboardTimeline.exclusive')}</p>
    </> : <div className="mt-5 rounded-lg border border-dashed border-[var(--line)] px-5 py-8 text-center">
      <p className="text-sm font-semibold">{tr('dashboardTimeline.empty')}</p>
      <p className="mt-2 text-sm text-[var(--muted)]">{tr('dashboardTimeline.emptyHint')}</p>
    </div>}
    <p className="mt-4 text-xs leading-relaxed text-[var(--muted)]">{tr('dashboardTimeline.metadata')}</p>
    {(data.undated > 0 || data.unavailable > 0) && <div className="mt-3 rounded-lg bg-[var(--review-soft)] p-3 text-xs text-[var(--review-text)]">
      {data.undated > 0 && <p>{tr(data.undated === 1 ? 'dashboardTimeline.undatedOne' : 'dashboardTimeline.undated', { n: formatCount(data.undated) })}</p>}
      {data.unavailable > 0 && <p className={data.undated ? 'mt-1' : ''}>{tr(data.unavailable === 1 ? 'dashboardTimeline.unavailableOne' : 'dashboardTimeline.unavailableEvents', { n: formatCount(data.unavailable) })}</p>}
      <button type="button" className="mt-2 cursor-pointer rounded font-semibold hover:underline focus-visible:outline-2 focus-visible:outline-[var(--accent)]"
        onClick={() => gotoView('timeline', { scope: 'all' })}>{tr('dashboardTimeline.reviewLimits')}<ArrowRight size={12} className="ml-1 inline" /></button>
    </div>}
  </div>
}
