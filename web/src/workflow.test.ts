import { describe, expect, it } from 'vitest'
import type { CaseDetail, Dashboard, Job } from './api'
import { deriveWorkflowAction } from './workflow'

const evidence = (kinds: string[]): CaseDetail => ({
  slug: 'case', dir: 'C:/case', name: 'Case', reference: '', notes: '', created: '',
  artifacts: 0, confirmed: 0, iocs: 0,
  evidence_items: kinds.map((kind, id) => ({
    id, kind: kind as CaseDetail['evidence_items'][number]['kind'], path: `C:/${kind}`,
    added: '', stats: {}, label: kind, exists: true, files: 1, bytes: 1,
    scanned_at: '2026-01-01T00:00:00Z', meta_partial: 0,
  })),
  log_index: { exists: false, fresh: false, reason: '', lines: 0, clients: 0, unparsed: 0, size: 0 },
})

const job = (state: Job['state'], created = '2026-01-01T00:00:00Z', run_id = 'run'): Job => ({
  id: 1, run_id, kind: 'webshell', state, progress: 1, message: '', error: '', created, stats: {},
})

const dashboard = (triage: Record<string, number>): Dashboard => ({ triage } as Dashboard)

describe('deriveWorkflowAction', () => {
  const complete = evidence(['webroot', 'access_logs', 'sql_dump'])

  it('guides incomplete evidence before anything else', () => {
    expect(deriveWorkflowAction(evidence(['webroot']), [], dashboard({}))).toMatchObject({ id: 'evidence' })
  })

  it('guides a complete case to its first analysis', () => {
    expect(deriveWorkflowAction(complete, [], dashboard({}))).toMatchObject({ id: 'analysis' })
  })

  it('prioritises running and failed state from the newest run', () => {
    expect(deriveWorkflowAction(complete, [job('running')], dashboard({ new: 4 }))).toMatchObject({ id: 'running' })
    expect(deriveWorkflowAction(complete, [job('failed')], dashboard({ new: 4 }))).toMatchObject({ id: 'issue' })
    expect(deriveWorkflowAction(complete, [job('failed', '2025-01-01', 'old'), job('done', '2026-01-01', 'new')],
      dashboard({ new: 4 }))).toMatchObject({ id: 'triage' })
  })

  it('continues triage, then prepares the report', () => {
    expect(deriveWorkflowAction(complete, [job('done')], dashboard({ new: 3, reviewed: 2 })))
      .toMatchObject({ id: 'triage', count: 5 })
    expect(deriveWorkflowAction(complete, [job('done')], dashboard({ confirmed: 3, dismissed: 2 })))
      .toMatchObject({ id: 'report' })
  })

  it('prioritises newly registered evidence after run status and before triage', () => {
    const withPending = evidence(['webroot', 'access_logs', 'sql_dump'])
    withPending.evidence_items.push({
      ...withPending.evidence_items[0], id: 9, path: 'C:/webroot-2', scanned_at: '',
    })
    expect(deriveWorkflowAction(withPending, [job('done')], dashboard({ new: 3 })))
      .toMatchObject({ id: 'pending', count: 1, view: 'evidence' })
    expect(deriveWorkflowAction(withPending, [job('failed')], dashboard({ new: 3 })))
      .toMatchObject({ id: 'issue' })
  })
})
