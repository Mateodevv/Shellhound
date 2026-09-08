import { useT } from '../../i18n'
import { useState } from 'react'
import { ArrowRight, CheckCircle2, Clock3, Search, TriangleAlert } from 'lucide-react'
import type { HuntBatch, HuntBatchPattern } from '../../api'
import { absoluteTime, formatCount, formatLogTime } from '../../format'
import { Button, Card, Tag } from '../../components/ui'
import { huntRunState } from './run-state'

export function HuntRunCounts({ run }: { run: HuntBatch }) {
  const tr = useT()
  const { checked, matched, failed, remaining, total } = run.counts
  const running = ['queued', 'running'].includes(run.state)
  const counts: { label: string; value: string | number; color: string; background: string }[] = [
    { label: tr('hunt.flow.checked'), value: `${checked} / ${total ?? '?'}`, color: checked ? 'var(--ok)' : 'var(--fg)', background: checked ? 'color-mix(in srgb, var(--ok) 8%, transparent)' : 'var(--panel-2)' },
    { label: tr('hunt.flow.matched'), value: matched, color: matched ? 'var(--danger-text)' : 'var(--muted)', background: matched ? 'var(--danger-soft)' : 'var(--panel-2)' },
    { label: tr('activity.job.failed'), value: failed, color: failed ? 'var(--review-text)' : 'var(--muted)', background: failed ? 'var(--review-soft)' : 'var(--panel-2)' },
  ]
  if (running || remaining !== 0) counts.push({
    label: running ? tr('hunt.flow.remaining') : tr('hunt.flow.notChecked'), value: remaining ?? '?',
    color: 'var(--review-text)', background: 'var(--review-soft)',
  })
  return <dl className={counts.length === 4 ? 'grid grid-cols-2 gap-3 sm:grid-cols-4' : 'grid grid-cols-3 gap-3'}>
    {counts.map(({ label, value, color, background }) => <div key={label} className="rounded-xl border border-[var(--line-soft)] px-4 py-3" style={{ background }}>
      <dt className="text-xs font-medium text-[var(--muted)]">{label}</dt>
      <dd className="mt-1 text-2xl font-semibold tabular-nums" style={{ color }}>{value}</dd>
    </div>)}
  </dl>
}

export function HuntRunOverview({ run, runs, onRun, onPattern, onCancel, cancelling }: {
  run: HuntBatch | undefined
  runs: HuntBatch[]
  onRun: (id: string) => void
  onPattern: (pattern: HuntBatchPattern) => void
  onCancel: () => void
  cancelling: boolean
}) {
  const tr = useT()
  const [showAll, setShowAll] = useState(false)
  if (!run) return <Card className="p-8 text-center">
    <Search size={30} className="mx-auto text-[var(--accent-text)]" />
    <h2 className="mt-3 text-lg font-semibold">{tr('hunt.flow.startWithAPatternCheck')}</h2>
    <p className="mx-auto mt-2 max-w-xl text-sm leading-relaxed text-[var(--muted)]">{tr('hunt.flow.emptyRunHint')}</p>
  </Card>

  const { running, tone, label: stateLabel } = huntRunState(run, tr)
  const patterns = [...run.patterns].sort((a, b) =>
    Number(Boolean(b.test?.hits)) - Number(Boolean(a.test?.hits))
    || (b.test?.hits ?? 0) - (a.test?.hits ?? 0)
    || a.name.localeCompare(b.name))
  // Failures and pending checks remain visible; the filter hides only checked zero-hit rows.
  const visible = patterns.filter((p) => showAll || p.status !== 'done' || Boolean(p.test?.hits))

  return <Card className="overflow-hidden">
    <header className="flex flex-wrap items-start justify-between gap-4 border-b border-[var(--line)] p-5">
      <div>
        <h2 className="flex items-center gap-2 text-lg font-semibold">
          {running ? <Clock3 size={19} /> : tone === 'ok' ? <CheckCircle2 size={19} /> : <TriangleAlert size={19} />} <Tag tone={tone}>{stateLabel}</Tag>
        </h2>
        <p className="mt-1 text-sm text-[var(--muted)]">{absoluteTime(run.created)} UTC</p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-sm text-[var(--muted)]">{tr('hunt.flow.run')}<select className="ml-2 max-w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2 text-sm text-[var(--fg)]"
            value={run.batch_id} onChange={(e) => { setShowAll(false); onRun(e.target.value) }}>
            {runs.map((item) => <option key={item.batch_id} value={item.batch_id}>
              {absoluteTime(item.created)} UTC · {item.counts.total ?? '?'} {tr('hunt.flow.patterns')}</option>)}
          </select>
        </label>
        {running && <Button disabled={cancelling} onClick={onCancel}>{cancelling ? tr('hunt.flow.stopping') : tr('hunt.flow.stopCheck')}</Button>}
      </div>
    </header>
    <div className="p-5">
      <HuntRunCounts run={run} />
      {running && <progress aria-label={tr('hunt.flow.patternsChecked')} max={1} value={run.progress || 0}
        className="mt-4 h-2 w-full accent-[var(--accent)]" />}
      {run.index_summary && <p className="mt-4 text-sm text-[var(--muted)]">
        {formatCount(run.index_summary.requests)} {tr('hunt.flow.indexedRequests')} {formatLogTime(run.index_summary.first_epoch, run.index_summary.tz, { withZone: true })}
        {' → '}{formatLogTime(run.index_summary.last_epoch, run.index_summary.tz, { withZone: true })}
      </p>}
      {!run.fresh && <p role="status" className="mt-4 rounded-lg bg-[var(--review-soft)] p-3 text-sm text-[var(--review-text)]">{tr('hunt.flow.historicalHint')}</p>}
      {!run.roster_known && <p className="mt-3 text-sm text-[var(--muted)]">{tr('hunt.flow.legacyRunHint')}</p>}
      {run.error && <ErrorMessage message={run.error} />}
    </div>
    <div className="flex flex-wrap items-center justify-between gap-2 border-y border-[var(--line)] bg-[var(--panel-2)] px-5 py-3">
      <h3 className="font-semibold">{tr('hunt.flow.patternsToInvestigate')}</h3>
      <label className="flex cursor-pointer items-center gap-2 text-sm">
        <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> {tr('hunt.flow.includePatternsWithNoMatches')}</label>
    </div>
    {!visible.length ? <div className="p-6 text-sm text-[var(--muted)]">
      {running ? tr('hunt.flow.waitingResult')
        : tr('hunt.flow.noMatches')}
    </div> : <div className="divide-y divide-[var(--line)]">
      {visible.map((pattern) => <div key={pattern.id} className="p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-w-0">
            <h4 className={`flex flex-wrap items-center gap-2 font-semibold ${pattern.test?.hits ? 'text-[var(--danger-text)]' : ''}`}>
              {pattern.name || tr('hunt.flow.unnamedPattern')} {pattern.cve && <Tag>{pattern.cve}</Tag>}
            </h4>
            <p className="mt-1 text-sm text-[var(--muted)]">{pattern.technology} · v{pattern.version}</p>
          </div>
          {pattern.test ? <Button disabled={!run.fresh} onClick={() => onPattern(pattern)}>{tr('hunt.flow.inspectMatches')} <ArrowRight size={15} /></Button>
            : <Tag tone="warn">
              {{ pending: tr('hunt.flow.waiting'), running: tr('hunt.flow.checking'), failed: tr('activity.job.failed'), not_run: tr('hunt.flow.notChecked'), done: tr('hunt.flow.checked') }[pattern.status]}
            </Tag>}
        </div>
        {pattern.test && <dl className="mt-4 grid grid-cols-2 gap-3 text-sm lg:grid-cols-4">
          {[[tr('hunt.flow.matchingRequests'), formatCount(pattern.test.hits)], [tr('hunt.flow.ipAddresses'), formatCount(pattern.test.clients)],
            [tr('hunt.flow.firstMatch'), formatLogTime(pattern.test.first_epoch, pattern.test.tz, { withZone: true })],
            [tr('hunt.flow.lastMatch'), formatLogTime(pattern.test.last_epoch, pattern.test.tz, { withZone: true })]].map(([label, value]) =>
            <div key={label}><dt className="text-[var(--muted)]">{label}</dt><dd className="mt-1 font-medium">{value}</dd></div>)}
        </dl>}
        {pattern.error && <ErrorMessage message={pattern.error} />}
      </div>)}
    </div>}
  </Card>
}

export function ErrorMessage({ message, onRetry }: { message: string; onRetry?: () => void }) {
  const tr = useT()
  return <div role="alert" className="my-3 flex flex-wrap items-center gap-3 rounded-lg border border-[var(--sev-low)]/30 bg-[var(--review-soft)] p-3 text-sm text-[var(--review-text)]">
    <span className="min-w-0 flex-1 break-words">{message}</span>
    {onRetry && <Button onClick={onRetry}>{tr('evidence.skips.retry')}</Button>}
  </div>
}
