import type { ReactNode } from 'react'
import { ArrowRight, CheckCircle2, Clock3, Library, Plus, Search, TriangleAlert } from 'lucide-react'
import type { HuntBatch, HuntPattern } from '../../api'
import { absoluteTime, formatCount, formatLogTime } from '../../format'
import { useT } from '../../i18n'
import { Button, Card, Tag } from '../../components/ui'
import { ErrorMessage, HuntRunCounts } from './HuntRunOverview'
import { huntRunState } from './run-state'

export function HuntResultsSummary({ run, loading, unavailable, canRun, enabled, starting,
  scope, onStart, onResults, onCancel, cancelling }: {
  run?: HuntBatch; loading: boolean; unavailable: boolean; canRun: boolean; enabled: number; starting: boolean
  scope: ReactNode; onStart: () => void; onResults: () => void; onCancel: () => void; cancelling: boolean
}) {
  const tr = useT()
  const state = run ? huntRunState(run, tr) : null
  const matches = run?.patterns.filter((p) => Boolean(p.test?.hits)).slice(0, 3) ?? []
  return <section aria-label={tr('hunt.overview.results')}>
    <Card className="overflow-hidden">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line-soft)] px-5 py-4 sm:px-6">
        <h2 className="flex items-center gap-2 font-semibold"><Search size={18} className="text-[var(--accent-text)]" />{tr('hunt.overview.results')}</h2>
        {state && <Tag tone={state.tone}>{state.label}</Tag>}
      </header>
      {loading ? <p role="status" className="p-8 text-sm text-[var(--muted)]">{tr('hunt.flow.loadingPatternChecks')}</p>
        : unavailable ? <p className="p-8 text-sm text-[var(--danger-text)]">{tr('hunt.overview.resultsUnavailable')}</p>
          : !run ? <div className="px-5 py-6 text-center sm:px-8 sm:py-7">
            <h3 className="text-xl font-semibold">{tr('hunt.overview.readyTitle')}</h3>
            <p className="mx-auto mt-2 max-w-xl text-sm leading-relaxed text-[var(--muted)]">{tr('hunt.overview.readyHint')}</p>
            <Button variant="primary" className="mx-auto mt-5 min-h-14 w-full max-w-sm justify-center rounded-xl px-7 py-4 !text-base shadow-lg shadow-black/15"
              disabled={!canRun || !enabled} onClick={onStart}><Search size={21} />{starting ? tr('hunt.overview.starting') : tr('hunt.flow.checkAllCount', { n: enabled })}</Button>
            <div className="mx-auto mt-4 max-w-2xl text-sm text-[var(--muted)]">{scope}</div>
          </div> : <div className="space-y-4 p-5 sm:p-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h3 className="flex items-center gap-2 text-xl font-semibold">
                  {state?.running ? <Clock3 size={21} className="text-[var(--review-text)]" /> : state?.tone === 'ok' ? <CheckCircle2 size={21} className="text-[var(--ok)]" /> : <TriangleAlert size={21} className="text-[var(--review-text)]" />}
                  {state?.running ? tr('hunt.overview.checkInProgress') : tr('hunt.overview.savedCheck')}
                </h3>
                <p className="mt-1 text-xs text-[var(--muted)]">{absoluteTime(run.created)} UTC</p>
              </div>
              <Button variant="primary" onClick={onResults}>{tr('hunt.overview.viewResults')}<ArrowRight size={16} /></Button>
            </div>
            <HuntRunCounts run={run} />
            {state?.running && <progress aria-label={tr('hunt.flow.patternsChecked')} max={1} value={run.progress || 0} className="h-2 w-full accent-[var(--sev-low)]" />}
            {matches.length > 0 ? <button type="button" onClick={onResults} aria-label={tr('hunt.overview.matchesToInspect')}
              className="block w-full cursor-pointer rounded-lg border border-[var(--danger-text)]/30 bg-[var(--danger-soft)] px-4 py-3 text-left text-sm transition-colors hover:bg-[var(--danger-soft-hover)]">
              <span className="flex items-center justify-between gap-3 font-medium text-[var(--danger-text)]">{tr('hunt.overview.matchesToInspect')}<ArrowRight size={16} className="shrink-0" /></span>
              <span className="mt-1 block break-words text-[var(--fg)]">{matches.map((p) => p.name || tr('hunt.flow.unnamedPattern')).join(' · ')}{run.counts.matched > matches.length ? ` · +${formatCount(run.counts.matched - matches.length)}` : ''}</span>
              <span className="mt-1 block text-xs text-[var(--muted)]">{tr('hunt.overview.matchHint')}</span>
            </button> : <p className="text-sm text-[var(--muted)]">{state?.running ? tr('hunt.flow.waitingResult') : state?.tone === 'ok' ? tr('hunt.flow.noMatches') : tr('hunt.overview.noCompletedMatches')}</p>}
            {run.index_summary && <p className="text-xs leading-relaxed text-[var(--muted)]">
              {tr('hunt.overview.checkedScope', { n: formatCount(run.index_summary.requests) })}{' · '}
              {formatLogTime(run.index_summary.first_epoch, run.index_summary.tz, { withZone: true })}{' → '}{formatLogTime(run.index_summary.last_epoch, run.index_summary.tz, { withZone: true })}
            </p>}
            {!run.fresh && <p role="status" className="rounded-lg bg-[var(--review-soft)] p-3 text-sm text-[var(--review-text)]">{tr('hunt.flow.historicalHint')}</p>}
            {!run.roster_known && <p className="text-sm text-[var(--muted)]">{tr('hunt.flow.legacyRunHint')}</p>}
            {run.error && <ErrorMessage message={run.error} />}
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[var(--line-soft)] pt-4">
              {state?.running ? <Button disabled={cancelling} onClick={onCancel}>{cancelling ? tr('hunt.flow.stopping') : tr('hunt.flow.stopCheck')}</Button>
                : <Button disabled={!canRun || !enabled} onClick={onStart}><Search size={16} />{starting ? tr('hunt.overview.starting') : tr('hunt.overview.checkAgain')}</Button>}
              {!state?.running && <div className="min-w-0 text-xs text-[var(--muted)]">{scope}</div>}
            </div>
          </div>}
    </Card>
  </section>
}

export function HuntLibrarySummary({ patterns, loading, unavailable, onLibrary, onNew, onResume }: {
  patterns: HuntPattern[]; loading: boolean; unavailable: boolean; onLibrary: () => void; onNew: () => void; onResume?: () => void
}) {
  const tr = useT()
  const enabled = patterns.filter((p) => p.enabled && !p.archived)
  const technologyCounts = new Map<string, number>()
  enabled.forEach((p) => technologyCounts.set(p.technology, (technologyCounts.get(p.technology) ?? 0) + 1))
  const preview = [...enabled].sort((a, b) => a.name.localeCompare(b.name)).slice(0, 5)
  return <section aria-label={tr('hunt.overview.library')}>
    <Card className="overflow-hidden">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--line-soft)] px-5 py-4 sm:px-6">
        <h2 className="flex items-center gap-2 font-semibold"><Library size={18} className="text-[var(--accent-text)]" />{tr('hunt.overview.library')}</h2>
        {!loading && !unavailable && <div className="flex gap-2"><Tag tone={enabled.length ? 'ok' : 'warn'}>{formatCount(enabled.length)} {tr('hunt.flow.enabled')}</Tag><Tag>{formatCount(patterns.length)} {tr('hunt.flow.saved')}</Tag></div>}
      </header>
      <div className="p-5 sm:p-6">
        {loading ? <p role="status" className="text-sm text-[var(--muted)]">{tr('hunt.overview.loadingLibrary')}</p>
          : unavailable ? <p className="text-sm text-[var(--danger-text)]">{tr('hunt.overview.libraryUnavailable')}</p>
            : <>
              <p className="text-sm leading-relaxed text-[var(--muted)]">{patterns.length ? tr('hunt.overview.libraryHint') : tr('hunt.flow.emptyLibrary')}</p>
              {technologyCounts.size > 0 && <div className="mt-3 flex flex-wrap gap-2">{[...technologyCounts].sort(([a], [b]) => a.localeCompare(b)).map(([technology, count]) => <Tag key={technology}>{tr(`hunt.technology.${technology}`)} · {formatCount(count)}</Tag>)}</div>}
              {preview.length > 0 && <ul className="mt-4 divide-y divide-[var(--line-soft)] rounded-xl border border-[var(--line-soft)] bg-[var(--panel-2)]/35 px-4">
                {preview.map((pattern) => <li key={pattern.id} className="flex min-w-0 flex-wrap items-center justify-between gap-x-4 gap-y-1 py-2.5 text-sm">
                  <span className="min-w-0 break-words font-medium">{pattern.name || tr('hunt.flow.unnamedPattern')}</span>
                  <span className="text-xs text-[var(--muted)]">{tr(`hunt.technology.${pattern.technology}`)}{pattern.cve ? ` · ${pattern.cve}` : ''}</span>
                </li>)}
              </ul>}
              {enabled.length > preview.length && <p className="mt-2 text-xs text-[var(--muted)]">{tr('hunt.overview.morePatterns', { n: enabled.length - preview.length })}</p>}
              {patterns.length > 0 && !enabled.length && <p className="mt-3 text-sm text-[var(--review-text)]">{tr('hunt.flow.noneEnabled')}</p>}
            </>}
        <div className="mt-5 flex flex-wrap gap-3">
          <Button onClick={onLibrary}>{tr('hunt.overview.openLibrary')}<ArrowRight size={16} /></Button>
          <Button variant={patterns.length ? 'ghost' : 'primary'} disabled={loading || unavailable} onClick={onNew}><Plus size={16} />{tr('hunt.flow.addAPattern')}</Button>
          {onResume && <Button variant="ghost" onClick={onResume}>{tr('hunt.flow.resumeDraft')}</Button>}
        </div>
      </div>
    </Card>
  </section>
}
