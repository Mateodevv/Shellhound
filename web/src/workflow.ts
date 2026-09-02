import type { CaseDetail, Dashboard, Job } from './api'

export const REQUIRED_EVIDENCE = ['webroot', 'access_logs', 'sql_dump'] as const

export interface WorkflowAction {
  id: 'evidence' | 'analysis' | 'running' | 'issue' | 'pending' | 'triage' | 'report'
  view: 'evidence' | 'findings' | 'report'
  label: string
  count?: number
}

/** Pick the next useful place without performing the action itself. */
export function deriveWorkflowAction(
  caseInfo: CaseDetail | undefined,
  jobs: Job[] | undefined,
  dashboard: Dashboard | undefined,
): WorkflowAction | null {
  if (!caseInfo) return null
  const present = new Set(caseInfo.evidence_items.map((item) => item.kind))
  if (REQUIRED_EVIDENCE.some((kind) => !present.has(kind))) {
    return { id: 'evidence', view: 'evidence', label: 'case.action.completeEvidence' }
  }

  if (!jobs?.length) {
    return { id: 'analysis', view: 'evidence', label: 'case.action.runAnalysis' }
  }

  const newest = [...jobs].sort((a, b) => b.created.localeCompare(a.created))[0]
  const run = newest.run_id
    ? jobs.filter((job) => job.run_id === newest.run_id)
    : [newest]
  if (run.some((job) => job.state === 'queued' || job.state === 'running')) {
    return { id: 'running', view: 'evidence', label: 'case.action.viewAnalysis' }
  }
  if (run.some((job) => job.state === 'failed' || job.state === 'cancelled')) {
    return { id: 'issue', view: 'evidence', label: 'case.action.reviewAnalysis' }
  }

  const pending = caseInfo.evidence_items.filter((item) =>
    item.kind !== 'reference' && !item.scanned_at).length
  if (pending > 0) {
    return { id: 'pending', view: 'evidence', label: 'case.action.analyzeNew', count: pending }
  }

  const triage = dashboard?.triage ?? {}
  const open = (triage.new ?? 0) + (triage.reviewed ?? 0)
  if (open > 0) {
    return { id: 'triage', view: 'findings', label: 'case.action.reviewNext', count: open }
  }
  return { id: 'report', view: 'report', label: 'case.action.prepareReport' }
}
