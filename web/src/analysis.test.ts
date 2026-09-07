import { describe, expect, it } from 'vitest'
import type { Job } from './api'
import { jobComplete, jobWarnings, needsAttention, statsComplete } from './analysis'

const job: Job = { id: 1, run_id: 'run', kind: 'webshell', state: 'done', progress: 1,
  message: '', error: '', created: '', stats: { skipped: 2, file_skips: 2 } }

describe('file scan completion', () => {
  it.each(['webshell', 'yara'])('counts finished %s file skips as warnings', (kind) => {
    expect(jobComplete({ ...job, kind })).toBe(true)
    expect(jobWarnings({ ...job, kind })).toBe(2)
    expect(needsAttention({ status: 'complete_with_warnings', warnings: 2 })).toBe(false)
  })

  it.each([
    { partial: true }, { discovery_errors: 1 }, { broken_rules: 1 }, { available: false },
  ])('preserves a real failure alongside ordinary skips: %j', (failure) => {
    expect(jobComplete({ ...job, stats: { ...job.stats, ...failure } })).toBe(false)
  })

  it('does not silently bless other engines or unclassified historical skips', () => {
    expect(statsComplete(job.stats, 'sigma')).toBe(false)
    expect(statsComplete({ skipped: 2 }, 'webshell')).toBe(false)
    expect(jobComplete({ ...job, state: 'cancelled' })).toBe(false)
  })

  it('uses the authoritative cumulative result and unresolved count after retries', () => {
    expect(jobComplete({ ...job, analysis_status: 'complete', warning_count: 0 })).toBe(true)
    expect(jobWarnings({ ...job, analysis_status: 'complete', warning_count: 0 })).toBe(0)
    expect(jobComplete({ ...job, analysis_status: 'partial' })).toBe(false)
  })
})
