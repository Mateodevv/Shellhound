import type { HuntBatch } from '../../api'
import type { useT } from '../../i18n'

export function huntRunState(run: HuntBatch, tr: ReturnType<typeof useT>) {
  const running = ['queued', 'running'].includes(run.state)
  const failed = run.state === 'failed' || run.counts.failed > 0
  const incomplete = run.state === 'cancelled' || !run.roster_known || Boolean(run.counts.remaining)
  const tone = failed || running || incomplete || !run.fresh ? 'warn' : 'ok'
  const label = running ? tr('hunt.flow.checkingPatterns')
    : run.state === 'cancelled' ? tr('hunt.flow.checkStopped')
      : run.state === 'failed' ? tr('hunt.flow.checkInterrupted')
        : run.counts.failed ? tr('hunt.flow.finishedWithFailedPatterns')
          : !run.roster_known ? tr('hunt.flow.historicalResults')
            : run.counts.remaining ? tr('hunt.overview.unfinished') : tr('hunt.flow.checkComplete')
  return { running, tone, label } as const
}
