import { describe, expect, it } from 'vitest'
import type { CaseDetail, Dashboard, Job } from './api'
import { deriveWorkflowAction, deriveWorkflowActions } from './workflow'

const evidence = (kinds: string[]): CaseDetail => ({
  slug: 'case', dir: 'C:/case', name: 'Case', reference: '', notes: '', created: '',
  artifacts: 0, confirmed: 0, iocs: 0,
  evidence_items: kinds.map((kind, id) => ({
    id, kind: kind as CaseDetail['evidence_items'][number]['kind'], path: `C:/${kind}`,
    added: '', stats: {}, label: kind, exists: true, files: 1, bytes: 1,
    scanned_at: '2026-01-01T00:00:00Z', meta_partial: 0,
  })),
  log_index: { exists: kinds.includes('access_logs'), fresh: kinds.includes('access_logs'),
    reason: '', lines: 0, clients: 0, unparsed: 0, size: 0 },
})

const job = (state: Job['state'], created = '2026-01-01T00:00:00Z', run_id = 'run'): Job => ({
  id: 1, run_id, kind: 'webshell', state, progress: 1, message: '', error: '', created, stats: {},
})

const dashboard = (triage: Record<string, number>): Dashboard => ({ triage } as Dashboard)

describe('deriveWorkflowAction', () => {
  const complete = evidence(['webroot', 'access_logs', 'sql_dump'])

  it.each(['running', 'failed', 'cancelled'] as const)('keeps warning-only evidence usable during a %s targeted retry', (state) => {
    const single = evidence(['webroot'])
    single.evidence_items[0].stats = { last_attempt: { status: 'complete_with_warnings', warnings: 2 } }
    const base = { ...job('done'), analysis_status: 'complete_with_warnings' as const,
      warning_count: 2, stats: { skipped: 2, file_skips: 2 } }
    const retry = { ...job(state, '2026-01-02', 'retry'), id: 2,
      scan_context: { mode: 'retry' as const, parent_job_id: 1 } }
    expect(deriveWorkflowAction(single, [retry, base], dashboard({ new: 1 }))).toMatchObject({ id: 'triage' })
    expect(deriveWorkflowAction(single, [retry, base], dashboard({}))).toMatchObject({ id: 'report' })
  })

  it('asks for evidence only when no supported source is registered', () => {
    expect(deriveWorkflowAction(evidence([]), [], dashboard({}))).toMatchObject({ id: 'evidence' })
    expect(deriveWorkflowAction(evidence(['reference']), [], dashboard({}))).toMatchObject({ id: 'evidence' })
  })

  it.each(['webroot', 'access_logs', 'sql_dump'])('supports a %s-only case end to end', (kind) => {
    const single = evidence([kind])
    const engine = { webroot: 'webshell', access_logs: 'index_logs', sql_dump: 'sqldb' }[kind]!
    const singleJob = (state: Job['state']) => ({ ...job(state), kind: engine })
    expect(deriveWorkflowAction(single, [], dashboard({}))).toMatchObject({ id: 'analysis' })
    expect(deriveWorkflowAction(single, [singleJob('running')], dashboard({}))).toMatchObject({ id: 'running' })
    expect(deriveWorkflowAction(single, [singleJob('failed')], dashboard({}))).toMatchObject({ id: 'issue' })
    expect(deriveWorkflowAction(single, [singleJob('done')], dashboard({ new: 1 }))).toMatchObject({ id: 'triage' })
    expect(deriveWorkflowAction(single, [singleJob('done')], dashboard({ dismissed: 1 }))).toMatchObject({ id: 'report' })
    single.evidence_items[0].scanned_at = ''
    expect(deriveWorkflowAction(single, [singleJob('done')], dashboard({}))).toMatchObject({ id: 'pending' })
  })

  it('does not hide an active older run behind a newer completed job', () => {
    expect(deriveWorkflowAction(evidence(['webroot']), [
      job('running', '2026-01-01', 'old'), job('done', '2026-01-02', 'new'),
    ], dashboard({}))).toMatchObject({ id: 'running' })
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

  it('waits for required data before recommending a report', () => {
    expect(deriveWorkflowAction(complete, undefined, dashboard({}))).toBeNull()
    expect(deriveWorkflowAction(complete, [job('done')], undefined)).toBeNull()
    expect(deriveWorkflowActions(undefined, [], dashboard({}))).toEqual({ primary: null, secondary: [] })
  })

  it.each(['running', 'failed', 'cancelled'] as const)('does not treat a %s hunt as analysis', (state) => {
    const hunt = { ...job(state, '2026-01-02', 'hunt'), kind: 'hunt' }
    expect(deriveWorkflowAction(complete, [job('done'), hunt], dashboard({}))).toMatchObject({ id: 'report' })
    expect(deriveWorkflowAction(complete, [hunt], dashboard({}))).toMatchObject({ id: 'analysis' })
  })

  it('does not let a later unrelated engine hide a failed or incomplete analysis', () => {
    const oldFailure = job('failed', '2026-01-01')
    const newerSuccess = { ...job('done', '2026-01-02'), kind: 'cms' }
    expect(deriveWorkflowAction(complete, [oldFailure, newerSuccess], dashboard({}))).toMatchObject({ id: 'issue' })
    expect(deriveWorkflowAction(complete, [job('done')], { ...dashboard({}), analysis_complete: false }))
      .toMatchObject({ id: 'issue' })
  })

  it('uses aggregate completion when successful analysis jobs have fallen outside the recent history', () => {
    expect(deriveWorkflowAction(complete, [], { ...dashboard({}), analysis_complete: true }))
      .toMatchObject({ id: 'report' })
  })

  it.each([
    { exists: true, fresh: false, reason: 'Registered source changed' },
    { exists: false, fresh: false, reason: 'Index missing' },
  ])('requires log analysis despite a completed receipt when index state is $reason', (index) => {
    const source = evidence(['access_logs'])
    source.evidence_items[0].stats = { last_attempt: { status: 'complete' } }
    source.log_index = { ...source.log_index, ...index }
    const completedIndex = { ...job('done'), kind: 'index_logs' }
    for (const triage of [{ new: 0 }, { new: 2 }]) {
      expect(deriveWorkflowAction(source, [completedIndex], { ...dashboard(triage), analysis_complete: true }))
        .toMatchObject({ id: 'issue', view: 'evidence' })
    }
  })

  it('reviews findings before unresolved skips, and keeps accepted gaps out of the warning queue', () => {
    const withWarnings = { ...dashboard({ new: 2, reviewed: 1 }), analysis_warnings: 4, analysis_accepted: 5 }
    expect(deriveWorkflowAction(complete, [job('done')], withWarnings)).toMatchObject({
      id: 'triage', count: 3, params: { triage: 'new,reviewed', severity: '0,1,2,3' },
    })
    expect(deriveWorkflowAction(complete, [job('done')], { ...withWarnings, triage: {} }))
      .toMatchObject({ id: 'warnings', count: 4 })
    expect(deriveWorkflowAction(complete, [job('done')], { ...withWarnings, triage: {}, analysis_warnings: 0 }))
      .toMatchObject({ id: 'report' })
  })

  it('offers a hunt only with usable indexed logs and never makes it mandatory', () => {
    const indexed = { ...complete, log_index: { ...complete.log_index, exists: true, fresh: true, lines: 10 } }
    const actions = deriveWorkflowActions(indexed, [job('done')], dashboard({}))
    expect(actions.primary?.id).toBe('report')
    expect(actions.secondary).toEqual([expect.objectContaining({ id: 'hunt' })])
    expect(deriveWorkflowActions(complete, [job('done')], dashboard({})).secondary).toEqual([])
    expect(deriveWorkflowActions(indexed, [job('running')], dashboard({})).secondary).toEqual([])
    expect(deriveWorkflowActions({ ...indexed, log_index: { ...indexed.log_index, fresh: false } },
      [job('done')], dashboard({})).secondary).toEqual([])
  })

  it('caps secondary actions at two while exposing skips and optional hunts beside triage', () => {
    const indexed = { ...complete, log_index: { ...complete.log_index, exists: true, fresh: true, lines: 10 } }
    const data = { ...dashboard({ new: 2 }), analysis_warnings: 3 }
    const actions = deriveWorkflowActions(indexed, [job('done')], data)
    expect(actions.primary?.id).toBe('triage')
    expect(actions.secondary.map((action) => action.id)).toEqual(['warnings', 'hunt'])
    expect(deriveWorkflowActions(indexed, [job('failed')], data).secondary).toHaveLength(2)
  })
})
