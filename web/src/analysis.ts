import type { EvidenceItem, Job } from './api'
import type { Translate } from './i18n'
import { formatCount } from './format'

export interface AnalysisAttempt {
  status: 'running' | 'partial' | 'failed' | 'cancelled' | 'complete' | 'complete_with_warnings'
  at?: string
  warnings?: number
}

export function statsComplete(stats: Record<string, unknown> = {}, engine?: string): boolean {
  if (stats.partial || stats.broken_rules || stats.discovery_errors || stats.available === false) return false
  if (!stats.skipped) return true
  // Older jobs did not classify skips. Do not reinterpret an unknown skip
  // (for example, an unavailable log index) as a completed file scan.
  return ['webshell', 'yara'].includes(engine ?? '')
    && Number(stats.file_skips) === Number(stats.skipped)
}

export function jobComplete(job: Job): boolean {
  if (job.state !== 'done') return false
  return job.analysis_status ? ['complete', 'complete_with_warnings'].includes(job.analysis_status)
    : statsComplete(job.stats, job.kind)
}

export function jobWarnings(job: Job): number {
  if (job.warning_count !== undefined) return job.warning_count
  return jobComplete(job) ? Number(job.stats?.file_skips || 0) : 0
}

export function discovering(job: Job): boolean {
  return job.state === 'running' && job.progress_details?.phase === 'discovering'
}

export function progressMessage(job: Job, tr: Translate): string {
  const details = job.progress_details
  if (!details) return job.message
  if (details.phase === 'discovering') return tr('jobs.discoveringCount', { n: formatCount(details.completed) })
  if (details.phase === 'scanning' && details.total !== null) {
    return tr('jobs.scanningCount', { n: formatCount(details.completed), total: formatCount(details.total) })
  }
  return details.phase === 'finalizing' ? tr('jobs.finalizing') : job.message
}

export function evidenceAttempt(item: EvidenceItem, jobs: Job[] = []): AnalysisAttempt | undefined {
  const saved = item.stats?.last_attempt as AnalysisAttempt | undefined
  if (saved?.status) return saved
  // Older cases have no per-source attempt record. Only infer an incomplete
  // attempt from this source's primary engine after its registration.
  if (item.scanned_at) return undefined
  const primary = { webroot: 'webshell', access_logs: 'index_logs', sql_dump: 'sqldb', reference: '' }[item.kind]
  const latest = jobs.filter((job) => job.kind === primary && job.created >= item.added
      && job.scan_context?.mode !== 'retry')
    .sort((a, b) => b.id - a.id)[0]
  if (!latest) return undefined
  const status = latest.state === 'done'
    ? jobComplete(latest) ? (jobWarnings(latest) > 0 ? 'complete_with_warnings' : undefined) : 'partial'
    : latest.state === 'queued' ? 'running' : latest.state
  return status ? { status, at: latest.finished || latest.created, warnings: jobWarnings(latest) } : undefined
}

export function needsAttention(attempt?: AnalysisAttempt): boolean {
  return Boolean(attempt && ['partial', 'failed', 'cancelled'].includes(attempt.status))
}
