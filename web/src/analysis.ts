import type { EvidenceItem, Job } from './api'

export interface AnalysisAttempt {
  status: 'running' | 'partial' | 'failed' | 'cancelled' | 'complete'
  at?: string
}

export function statsComplete(stats: Record<string, unknown> = {}): boolean {
  return !stats.partial && !stats.skipped && !stats.broken_rules && stats.available !== false
}

export function evidenceAttempt(item: EvidenceItem, jobs: Job[] = []): AnalysisAttempt | undefined {
  const saved = item.stats?.last_attempt as AnalysisAttempt | undefined
  if (saved?.status) return saved
  // Older cases have no per-source attempt record. Only infer an incomplete
  // attempt from this source's primary engine after its registration.
  if (item.scanned_at) return undefined
  const primary = { webroot: 'webshell', access_logs: 'index_logs', sql_dump: 'sqldb', reference: '' }[item.kind]
  const latest = jobs.filter((job) => job.kind === primary && job.created >= item.added)
    .sort((a, b) => b.id - a.id)[0]
  if (!latest) return undefined
  const status = latest.state === 'done'
    ? statsComplete(latest.stats) ? undefined : 'partial'
    : latest.state === 'queued' ? 'running' : latest.state
  return status ? { status, at: latest.finished || latest.created } : undefined
}

export function needsAttention(attempt?: AnalysisAttempt): boolean {
  return Boolean(attempt && ['partial', 'failed', 'cancelled'].includes(attempt.status))
}
