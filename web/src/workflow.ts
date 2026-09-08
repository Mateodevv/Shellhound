import type { CaseDetail, Dashboard, Job } from './api'
import { evidenceAttempt, needsAttention, jobComplete } from './analysis'

export const EVIDENCE_KINDS = ['webroot', 'access_logs', 'sql_dump'] as const

export interface WorkflowAction {
  id: 'evidence' | 'analysis' | 'running' | 'issue' | 'pending' | 'triage' | 'warnings' | 'hunt' | 'report'
  view: 'evidence' | 'findings' | 'hunt' | 'report'
  label: string
  count?: number
  params?: { triage: string; severity: string }
}

const ANALYSIS_ENGINES = new Set(['webshell', 'cms', 'yara', 'index_logs', 'errorlog', 'sigma', 'sqldb'])

export function isBaseAnalysisJob(job: Job): boolean {
  return ANALYSIS_ENGINES.has(job.kind) && job.scan_context?.mode !== 'retry'
}

function requiredEngines(present: Set<string>): Set<string> {
  const engines = new Set<string>()
  if (present.has('webroot')) ['webshell', 'cms', 'yara'].forEach((kind) => engines.add(kind))
  if (present.has('access_logs')) {
    engines.add('index_logs')
    engines.add('sigma')
    if (present.has('webroot')) engines.add('errorlog')
  }
  if (present.has('sql_dump')) engines.add('sqldb')
  return engines
}

const reviewAction = (count: number): WorkflowAction => ({
  id: 'triage', view: 'findings', label: 'case.action.reviewNext', count,
  // Include informational artifacts too: the linked list must match its count.
  params: { triage: 'new,reviewed', severity: '0,1,2,3' },
})

/** Pick the next useful place without performing the action itself. */
export function deriveWorkflowAction(
  caseInfo: CaseDetail | undefined,
  jobs: Job[] | undefined,
  dashboard: Dashboard | undefined,
): WorkflowAction | null {
  // Missing queries are loading/error states, never an empty review queue.
  if (!caseInfo || !jobs || !dashboard) return null
  const present = new Set(caseInfo.evidence_items.map((item) => item.kind))
  if (!EVIDENCE_KINDS.some((kind) => present.has(kind))) {
    return { id: 'evidence', view: 'evidence', label: 'case.action.completeEvidence' }
  }

  const required = requiredEngines(present)
  const baseJobs = jobs.filter((job) => isBaseAnalysisJob(job) && required.has(job.kind))
  const running = [...baseJobs, ...(dashboard.jobs_running ?? []).filter((job) =>
    isBaseAnalysisJob(job) && required.has(job.kind))]
  if (running.some((job) => job.state === 'queued' || job.state === 'running')) {
    return { id: 'running', view: 'evidence', label: 'case.action.viewAnalysis' }
  }
  // A successful unrelated engine cannot erase a failed rescan.
  const latest = new Map<string, Job>()
  for (const job of [...baseJobs].sort((a, b) =>
    b.created.localeCompare(a.created) || b.id - a.id)) {
    if (!latest.has(job.kind)) latest.set(job.kind, job)
  }
  if ([...latest.values()].some((job) => job.state === 'failed' || job.state === 'cancelled'
      || (job.state === 'done' && !jobComplete(job)))
      || caseInfo.evidence_items.some((item) => needsAttention(evidenceAttempt(item, jobs)))) {
    return { id: 'issue', view: 'evidence', label: 'case.action.reviewAnalysis' }
  }

  const pending = caseInfo.evidence_items.filter((item) =>
    item.kind !== 'reference' && !item.scanned_at).length
  if (!baseJobs.length && dashboard.analysis_complete !== true) {
    return { id: 'analysis', view: 'evidence', label: 'case.action.runAnalysis' }
  }
  if (pending > 0) {
    return { id: 'pending', view: 'evidence', label: 'case.action.analyzeNew', count: pending }
  }
  if (dashboard.analysis_complete === false) {
    return { id: 'issue', view: 'evidence', label: 'case.action.reviewAnalysis' }
  }
  // File changes do not clear an evidence receipt. A missing or outdated
  // access-log index still needs preparation before the case can be complete.
  if (present.has('access_logs') && (!caseInfo.log_index.exists || !caseInfo.log_index.fresh)) {
    return { id: 'issue', view: 'evidence', label: 'case.action.reviewAnalysis' }
  }

  const triage = dashboard?.triage ?? {}
  const open = (triage.new ?? 0) + (triage.reviewed ?? 0)
  if (open > 0) {
    return reviewAction(open)
  }
  if ((dashboard.analysis_warnings ?? 0) > 0) return {
    id: 'warnings', view: 'evidence', label: 'dashboard.reviewSkipped', count: dashboard.analysis_warnings,
  }
  return { id: 'report', view: 'report', label: 'case.action.prepareReport' }
}

/** Secondary tasks stay useful without turning an optional hunt into a gate. */
export function deriveWorkflowActions(
  caseInfo: CaseDetail | undefined,
  jobs: Job[] | undefined,
  dashboard: Dashboard | undefined,
): { primary: WorkflowAction | null; secondary: WorkflowAction[] } {
  const primary = deriveWorkflowAction(caseInfo, jobs, dashboard)
  if (!primary || !caseInfo || !dashboard || primary.id === 'evidence') return { primary, secondary: [] }
  const secondary: WorkflowAction[] = []
  const open = (dashboard.triage.new ?? 0) + (dashboard.triage.reviewed ?? 0)
  if (open > 0 && primary.id !== 'triage') secondary.push(reviewAction(open))
  if ((dashboard.analysis_warnings ?? 0) > 0 && primary.view !== 'evidence') secondary.push({
    id: 'warnings', view: 'evidence', label: 'dashboard.reviewSkipped', count: dashboard.analysis_warnings,
  })
  if (caseInfo.log_index.exists && caseInfo.log_index.fresh && caseInfo.log_index.lines > 0
      && primary.id !== 'running') secondary.push({
    id: 'hunt', view: 'hunt', label: 'nav.hunt',
  })
  return { primary, secondary: secondary.slice(0, 2) }
}
