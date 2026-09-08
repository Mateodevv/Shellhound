import { fireEvent, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { api, type CaseDetail, type Dashboard as DashboardData, type Job } from '../api'
import { renderWithProviders } from '../test/setup'
import { Dashboard } from './Dashboard'

vi.mock('../api', async (orig) => ({ ...(await orig<typeof import('../api')>()), api: vi.fn() }))

const AT = 1_752_000_000
const DONE: Job = {
  id: 1, kind: 'webshell', run_id: 'analysis', state: 'done', progress: 1,
  message: '', error: '', created: '2026-08-01T00:00:00Z', stats: {},
}
const EMPTY_HIGHLIGHTS = { groups: [], total_groups: 0, informational: 0, hidden: 0 }
const HUNT: NonNullable<DashboardData['hunt_summary']> = {
  batch_id: 'saved-run-7', state: 'done', created: '2026-09-08T10:00:00',
  fresh: true, matched: 2, checked: 4, total: 4, complete: true,
  pattern_names: ['Training marker requests', 'Example login pattern'],
}
const DATA: DashboardData = {
  severity: { '0': 4 }, triage: { confirmed: 2 }, confirmed_kinds: { file: 1, client: 1 },
  confirmed_severity: { '0': 2 }, confirmed_artifacts: [
    { artifact: '/srv/www/review.php', artifact_kind: 'file', worst: 0 },
    { artifact: '203.0.113.9', artifact_kind: 'client', worst: 0 },
  ],
  top_findings: { ...EMPTY_HIGHLIGHTS, total_groups: 2, groups: [
    { category: 'webshell', worst: 0, confirmed: 1, awaiting_review: 0, kinds: { file: 1 }, historical: 0,
      example: { artifact: '/srv/www/review.php', artifact_kind: 'file', rule: 'Harmless marker', source: 'webshell' } },
    { category: 'shell_access', worst: 0, confirmed: 1, awaiting_review: 0, kinds: { client: 1 }, historical: 0,
      example: { artifact: '203.0.113.9', artifact_kind: 'client', rule: 'Harmless request marker', source: 'logs' } },
  ] },
  findings_total: 100, iocs: 7, accounts: 8, admins: 2,
  cms_installs: [{ id: 1, root: '/srv/www', cms: 'Example CMS', version: '1.0' }],
  evidence: [{ id: 1, kind: 'webroot', path: '/srv/www', added: '2026-08-01T00:00:00Z',
    scanned_at: '2026-08-01T00:00:00Z', stats: {} }],
  jobs_running: [], analysis_complete: true,
  logs: { lines: 12_400, clients: 390, unparsed: 3, alerted_clients: 6, first_epoch: AT, last_epoch: AT + 86_400 },
  timeline: [], chronology: {
    total_events: 2, event_span: { first: AT, last: AT + 86_400 }, first_success_at: AT + 120,
    observations: [{ role: 'first_success', at: AT + 120, kind: 'erfolg', title: 'Reviewed path returned HTTP 200',
      detail: '/review.php', source: 'log', artifact: '/srv/www/review.php', artifact_kind: 'file',
      ip: '203.0.113.9', severity: 0 }],
    gaps: ['The capture begins after the first confirmed file timestamp.'], undated: 1,
    zone: 'UTC', tz_offsets: ['UTC'], tz_mixed: false,
  },
}

function mockCase(data: DashboardData = DATA, jobs: Job[] = [DONE], overrides: Partial<CaseDetail> = {}) {
  const detail: CaseDetail = {
    slug: 'case-1', dir: '/case', name: 'Example', reference: '', notes: '', created: '', evidence_items: data.evidence,
    log_index: { exists: Boolean(data.logs), fresh: Boolean(data.logs), reason: '', lines: data.logs?.lines ?? 0,
      clients: data.logs?.clients ?? 0, unparsed: 0, size: 0 }, ...overrides,
  }
  vi.mocked(api).mockImplementation(async (path) => {
    if (path.endsWith('/dashboard')) return data
    if (path.endsWith('/jobs')) return jobs
    if (path.endsWith('/case-1')) return detail
    if (path.endsWith('/coverage')) return { quiet: { windows: [], checked: true, total: 0 }, files: [], notes: [], tz: 0 }
    throw new Error(`Unexpected API call: ${path}`)
  })
}

function mount() {
  const gotoView = vi.fn()
  const rendered = renderWithProviders(<Dashboard slug="case-1" gotoView={gotoView} />)
  return { gotoView, ...rendered }
}

describe('actionable case dashboard', () => {
  it('shows unapplied Pattern Hunt matches with a link to the saved run', async () => {
    mockCase({ ...DATA, triage: {}, confirmed_artifacts: [], top_findings: EMPTY_HIGHLIGHTS, hunt_summary: HUNT })
    const { gotoView } = mount()
    const top = await screen.findByRole('region', { name: 'Top findings' })
    expect(within(top).getByText('2 patterns matched in the latest check')).toBeVisible()
    expect(within(top).getByText('Training marker requests · Example login pattern')).toBeVisible()
    expect(within(top).queryByText('No findings detected in the analyzed evidence')).not.toBeInTheDocument()
    expect(screen.getByText('Pattern matches to investigate')).toBeVisible()
    expect(screen.queryByText('Compromise confirmed')).not.toBeInTheDocument()
    const link = within(top).getByRole('button', { name: 'View Pattern Hunt results' })
    expect(link).toHaveStyle({ background: 'var(--review-soft)' })
    fireEvent.click(link)
    expect(gotoView).toHaveBeenCalledWith('hunt', { section: 'runs', batch: 'saved-run-7' })
  })

  it.each([
    [{ ...HUNT, complete: false, state: 'running' as const }, 'This check is still running; more results may follow.'],
    [{ ...HUNT, complete: false, state: 'cancelled' as const }, 'Partial results: some patterns could not be checked.'],
    [{ ...HUNT, fresh: false }, 'Historical results: the log evidence changed. Check patterns again before investigating these matches.'],
  ])('labels partial and historical Pattern Hunt matches', async (hunt_summary, message) => {
    mockCase({ ...DATA, hunt_summary })
    mount()
    const top = await screen.findByRole('region', { name: 'Top findings' })
    expect(within(top).getByText(message)).toBeVisible()
    expect(within(top).getByRole('button', { name: /Webshell & backdoor detections/ })).toBeVisible()
    expect(screen.getByRole('button', { name: '2 confirmed findings' })).toBeVisible()
  })

  it('keeps an unmatched check out of Top findings', async () => {
    mockCase({ ...DATA, hunt_summary: { ...HUNT, matched: 0, pattern_names: [] } })
    mount()
    await screen.findByRole('region', { name: 'Top findings' })
    expect(screen.queryByRole('button', { name: 'View Pattern Hunt results' })).not.toBeInTheDocument()
  })

  it('opens the exact outstanding artifact queue, including informational findings', async () => {
    mockCase({ ...DATA, triage: { new: 3, reviewed: 1, confirmed: 2 } })
    const { gotoView } = mount()
    const next = await screen.findByRole('region', { name: 'Recommended next step' })
    expect(within(next).getByRole('heading', { name: 'Review 4 outstanding findings' })).toBeVisible()
    fireEvent.click(within(next).getByRole('button', { name: 'Review 4 outstanding findings' }))
    expect(gotoView).toHaveBeenCalledWith('findings', { triage: 'new,reviewed', severity: '0,1,2,3' })
    expect(screen.queryByText('100')).not.toBeInTheDocument()
    const status = screen.getByRole('region', { name: 'Case status' })
    fireEvent.click(within(status).getByRole('button', { name: '4 findings need your review' }))
    expect(gotoView).toHaveBeenLastCalledWith('findings', { triage: 'new,reviewed', severity: '0,1,2,3' })
    fireEvent.click(within(status).getByRole('button', { name: '2 confirmed findings' }))
    expect(gotoView).toHaveBeenLastCalledWith('findings', { triage: 'confirmed', severity: '0,1,2,3' })
  })

  it('keeps confirmed compromise distinct from incomplete technical coverage', async () => {
    mockCase({ ...DATA, analysis_complete: false }, [{ ...DONE, state: 'failed' }])
    mount()
    expect(await screen.findByText('Compromise confirmed')).toBeVisible()
    expect(screen.getByText('An analysis check failed')).toBeVisible()
    const next = screen.getByRole('region', { name: 'Recommended next step' })
    expect(within(next).getByRole('button', { name: 'Review incomplete analysis' })).toBeVisible()
    expect(screen.queryByText('Analysis complete')).not.toBeInTheDocument()
  })

  it.each([
    ['confirmed, complete', { confirmed: 2 }, [DONE], true, 'var(--danger-soft)', 'color-mix(in srgb, var(--ok) 10%, var(--panel))'],
    ['unresolved, complete', { new: 2 }, [DONE], true, 'var(--review-soft)', 'color-mix(in srgb, var(--ok) 10%, var(--panel))'],
    ['confirmed, running', { confirmed: 2 }, [{ ...DONE, state: 'running' as const }], false, 'var(--danger-soft)', 'var(--review-soft)'],
    ['no findings, failed', {}, [{ ...DONE, state: 'failed' as const }], false, 'var(--review-soft)', 'var(--danger-soft)'],
    ['no findings, interrupted', {}, [{ ...DONE, state: 'cancelled' as const }], false, 'var(--review-soft)', 'var(--review-soft)'],
    ['reviewed, complete', { dismissed: 2 }, [DONE], true, 'color-mix(in srgb, var(--ok) 10%, var(--panel))', 'color-mix(in srgb, var(--ok) 10%, var(--panel))'],
  ])('colors assessment and coverage independently: %s', async (_label, triage, jobs, complete, assessmentColor, coverageColor) => {
    mockCase({ ...DATA, triage, analysis_complete: complete }, jobs)
    mount()
    const assessment = await screen.findByRole('heading', { name: 'Analyst assessment' })
    const coverage = screen.getByRole('heading', { name: 'Analysis coverage' })
    expect(assessment.parentElement!.parentElement).toHaveStyle({ background: assessmentColor })
    expect(coverage.parentElement!.parentElement).toHaveStyle({ background: coverageColor })
  })

  it('does not color coverage red for a superseded or unrelated engine failure', async () => {
    mockCase({ ...DATA, analysis_complete: false }, [
      { ...DONE, id: 0, state: 'failed' }, DONE,
      { ...DONE, id: 3, kind: 'sqldb', state: 'failed' },
      { ...DONE, id: 4, kind: 'hunt', state: 'failed' },
    ])
    mount()
    expect(await screen.findByText('Analysis needs attention')).toBeVisible()
    expect(screen.queryByText('An analysis check failed')).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Analysis coverage' }).parentElement!.parentElement)
      .toHaveStyle({ background: 'var(--review-soft)' })
  })

  it('does not reuse a complete aggregate while newer job data shows a running rescan', async () => {
    mockCase(DATA, [{ ...DONE, state: 'running' }])
    mount()
    expect(await screen.findByText('Compromise confirmed')).toBeVisible()
    expect(screen.getByText('Analysis in progress')).toBeVisible()
    expect(screen.queryByText('Analysis complete')).not.toBeInTheDocument()
  })

  it('shows only unresolved warnings during a targeted retry', async () => {
    const retry: Job = { ...DONE, id: 2, state: 'running', scan_context: { mode: 'retry', parent_job_id: 1 } }
    mockCase({ ...DATA, triage: {}, confirmed_artifacts: [], analysis_warnings: 2, analysis_accepted: 3,
      jobs_running: [retry] }, [DONE, retry])
    const { gotoView } = mount()
    expect(await screen.findByText('Analysis complete — no findings')).toBeVisible()
    expect(screen.getByText(/2 file\(s\) still skipped/)).toBeVisible()
    expect(screen.queryByText('Accepted coverage gaps')).not.toBeInTheDocument()
    const next = screen.getByRole('region', { name: 'Recommended next step' })
    fireEvent.click(within(next).getByRole('button', { name: /Review skipped files 2/ }))
    expect(gotoView).toHaveBeenCalledWith('evidence')
    expect(screen.queryByRole('button', { name: 'Review accepted skips' })).not.toBeInTheDocument()
    expect(screen.queryByText('Analysis in progress')).not.toBeInTheDocument()
  })

  it('clears the coverage warning once the analyst accepts all skips', async () => {
    mockCase({ ...DATA, triage: {}, confirmed_artifacts: [], analysis_warnings: 0, analysis_accepted: 3 })
    mount()
    expect(await screen.findByText('Analysis complete — no findings')).toBeVisible()
    expect(screen.queryByText('Unresolved skipped-file warnings')).not.toBeInTheDocument()
    expect(screen.queryByText('Accepted coverage gaps')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Prepare the report' })).toBeVisible()
  })

  it.each([
    ['unscanned evidence', { evidence: [{ ...DATA.evidence[0], scanned_at: '' }] }],
    ['a failed or partial rescan', { analysis_complete: false }],
  ])('does not claim a reviewed assessment with %s', async (_name, patch) => {
    mockCase({ ...DATA, triage: {}, confirmed_artifacts: [], analysis_complete: undefined, ...patch })
    mount()
    expect(await screen.findByText('Analysis not complete')).toBeVisible()
    expect(screen.queryByText('No compromise confirmed in reviewed evidence')).not.toBeInTheDocument()
    expect(screen.queryByText('Analysis complete — no findings')).not.toBeInTheDocument()
  })

  it('shows active analysis ahead of pending review and permits only two secondary tasks', async () => {
    const running = { ...DONE, state: 'running' as const }
    mockCase({ ...DATA, triage: { new: 3 }, analysis_complete: false, jobs_running: [running], analysis_warnings: 2 }, [running])
    const { gotoView } = mount()
    const next = await screen.findByRole('region', { name: 'Recommended next step' })
    fireEvent.click(within(next).getByRole('button', { name: 'View analysis progress' }))
    expect(gotoView).toHaveBeenCalledWith('evidence')
    expect(within(next).getAllByRole('button').length).toBeLessThanOrEqual(3)
    expect(within(next).queryByRole('button', { name: 'Check saved patterns' })).not.toBeInTheDocument()
  })

  it('distinguishes no findings from analyst review and keeps Pattern Hunt optional', async () => {
    mockCase({ ...DATA, triage: {}, confirmed_artifacts: [] })
    const { gotoView } = mount()
    expect(await screen.findByText('Analysis complete — no findings')).toBeVisible()
    expect(screen.getByText(/This does not rule out a compromise/)).toBeVisible()
    const next = screen.getByRole('region', { name: 'Recommended next step' })
    expect(within(next).getByRole('button', { name: 'Prepare the report' })).toBeVisible()
    fireEvent.click(within(next).getByRole('button', { name: 'Check saved patterns' }))
    expect(gotoView).toHaveBeenCalledWith('hunt')
  })

  it('does not let running Pattern Hunt change the case assessment or next step', async () => {
    const hunt = { ...DONE, id: 2, kind: 'hunt', state: 'running' as const }
    mockCase({ ...DATA, triage: { dismissed: 4 }, confirmed_artifacts: [], jobs_running: [hunt] }, [DONE, hunt])
    mount()
    expect(await screen.findByText('No compromise confirmed in reviewed evidence')).toBeVisible()
    expect(screen.getByRole('button', { name: 'Prepare the report' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'View dismissed findings' })).toBeVisible()
  })

  it('opens whole finding groups from the new section, with access to the full list', async () => {
    mockCase()
    const { gotoView } = mount()
    expect(await screen.findByText('Compromise confirmed')).toBeVisible()
    expect(screen.getAllByRole('heading', { level: 2 }).map((heading) => heading.textContent)).toEqual([
      'Case status', 'Recommended next step', 'Top findings', 'Case data overview',
    ])
    expect(screen.queryByText('Results overview')).not.toBeInTheDocument()
    expect(screen.queryByText('Reviewed path returned HTTP 200')).not.toBeInTheDocument()
    expect(screen.queryByText('Observations so far')).not.toBeInTheDocument()
    const highlights = screen.getByRole('region', { name: 'Top findings' })
    fireEvent.click(within(highlights).getByRole('button', { name: /Webshell & backdoor detections/ }))
    expect(gotoView).toHaveBeenLastCalledWith('findings', { category: 'webshell', triage: 'new,reviewed,confirmed', severity: '0,1,2,3' })
    fireEvent.click(within(highlights).getByRole('button', { name: 'View all findings' }))
    expect(gotoView).toHaveBeenLastCalledWith('findings', { severity: '0,1,2,3', triage: 'new,reviewed,confirmed,dismissed' })
    expect(within(screen.getByRole('region', { name: 'Case data overview' })).queryByText('review.php')).not.toBeInTheDocument()
  })

  it('supports a case without access logs and avoids unrelated empty metrics', async () => {
    mockCase({ ...DATA, logs: null, accounts: 0, iocs: 0, cms_installs: [] })
    mount()
    expect(await screen.findByText('Compromise confirmed')).toBeVisible()
    expect(screen.queryByText('Distinct IP addresses')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Check saved patterns' })).not.toBeInTheDocument()
    expect(vi.mocked(api).mock.calls.some(([path]) => path.endsWith('/coverage'))).toBe(false)
  })

  it('shows corrected software versions and keeps multiple installations and database sources distinguishable', async () => {
    mockCase({ ...DATA, system_summary: {
      installations: [
        { id: 1, root: '/srv/www/site-a', cms: 'wordpress', version: '2.4', version_parsed: '1.0', version_set: '2.4', version_source: 'manifest', extensions: { plugin: 3, theme: 1 } },
        { id: 2, root: '/srv/www/site-b', cms: 'Second CMS', version: '(unknown)', version_parsed: '(unknown)', version_set: '', version_source: '', extensions: {} },
      ],
      databases: [
        { id: 1, path: '/evidence/first.sql', server_version: '8.0.40' },
        { id: 2, path: '/evidence/second.sql', server_version: '' },
      ],
    }, evidence: [{ ...DATA.evidence[0], files: 512 }] })
    const { gotoView } = mount()
    const overview = await screen.findByRole('region', { name: 'Case data overview' })
    expect(within(overview).getByText('2.4')).toBeVisible()
    expect(within(overview).queryByText('1.0')).not.toBeInTheDocument()
    expect(within(overview).getByText('Analyst-corrected version')).toBeVisible()
    expect(within(overview).getByText('/srv/www/site-a')).toBeVisible()
    expect(within(overview).getByText('/srv/www/site-b')).toBeVisible()
    expect(within(overview).getByText('WordPress')).toBeVisible()
    expect(within(overview).getByText('3 plugins')).toBeVisible()
    expect(within(overview).getByText('1 theme')).toBeVisible()
    expect(within(overview).getAllByText('Version unknown')).toHaveLength(2)
    expect(within(overview).getByText('8.0.40')).toBeVisible()
    expect(within(overview).getByText('/evidence/first.sql')).toBeVisible()
    expect(within(overview).getByText('/evidence/second.sql')).toBeVisible()
    expect(within(overview).getByText(/512 files/)).toBeVisible()
    expect(within(overview).getByText(/not a live inventory/)).toBeVisible()
    fireEvent.click(within(overview).getByRole('button', { name: 'Open software inventory' }))
    expect(gotoView).toHaveBeenCalledWith('cms')
    fireEvent.click(within(overview).getByRole('button', { name: 'Open database evidence' }))
    expect(gotoView).toHaveBeenCalledWith('database')
  })

  it('separates mixed review decisions, affected items and historical results in compact highlights', async () => {
    mockCase({ ...DATA, triage: { new: 3, confirmed: 2 }, top_findings: { ...EMPTY_HIGHLIGHTS, total_groups: 2, groups: [
      { category: 'webshell', worst: 0, confirmed: 2, awaiting_review: 2, kinds: { file: 4 }, historical: 1,
        example: { artifact: '/srv/www/review/confirmed.txt', artifact_kind: 'file', rule: 'Harmless marker', source: 'webshell' } },
      { category: 'probes', worst: 1, confirmed: 0, awaiting_review: 1, kinds: { client: 1 }, historical: 0,
        example: { artifact: '203.0.113.9', artifact_kind: 'client', rule: 'Harmless marker', source: 'logs' } },
    ] } })
    const { gotoView } = mount()
    const highlights = await screen.findByRole('region', { name: 'Top findings' })
    const confirmedGroup = within(highlights).getByRole('button', { name: /Webshell & backdoor detections/ })
    expect(confirmedGroup).toHaveStyle({ background: 'var(--danger-soft)' })
    expect(within(confirmedGroup).getByText('4 files')).toBeVisible()
    expect(within(confirmedGroup).getByText('2 confirmed by analyst')).toHaveClass('text-[var(--danger-text)]')
    expect(within(confirmedGroup).getByText('2 awaiting review')).toHaveClass('text-[var(--review-text)]')
    expect(within(confirmedGroup).getByText('1 no longer reported by current scans')).toBeVisible()
    expect(within(confirmedGroup).getByText('review/confirmed.txt')).toHaveAttribute('title', '/srv/www/review/confirmed.txt')
    const pendingGroup = within(highlights).getByRole('button', { name: /Attack-pattern requests/ })
    expect(pendingGroup).toHaveStyle({ background: 'var(--review-soft)' })
    expect(within(pendingGroup).getByText('1 awaiting review')).toBeVisible()
    expect(within(pendingGroup).queryByText(/confirmed by analyst/)).not.toBeInTheDocument()
    pendingGroup.focus()
    await userEvent.setup().keyboard('{Enter}')
    expect(gotoView).toHaveBeenCalledWith('findings', { category: 'probes', triage: 'new,reviewed,confirmed', severity: '0,1,2,3' })
    expect(within(highlights).queryByText('100')).not.toBeInTheDocument()
    expect(within(highlights).queryByText('Harmless marker')).not.toBeInTheDocument()
  })

  it('explains a logs-only case without inventing a software inventory', async () => {
    mockCase({ ...DATA, triage: {}, confirmed_artifacts: [], cms_installs: [],
      system_summary: { installations: [], databases: [] },
      evidence: [{ ...DATA.evidence[0], kind: 'access_logs', path: '/evidence/access.log' }],
    }, [{ ...DONE, kind: 'index_logs' }])
    mount()
    expect(await screen.findByText('Access logs alone do not provide a complete software inventory.')).toBeVisible()
    expect(screen.getByText('Access-log period')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Open software inventory' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Open database evidence' })).not.toBeInTheDocument()
  })

  it('asks for evidence in an empty case without implying an assessment', async () => {
    mockCase({ ...DATA, evidence: [], triage: {}, notable_artifacts: [], confirmed_artifacts: [], top_findings: EMPTY_HIGHLIGHTS }, [])
    const { gotoView } = mount()
    expect(await screen.findByText(/^This case has no registered evidence\./)).toBeVisible()
    expect(screen.getAllByRole('heading', { level: 2 }).map((heading) => heading.textContent)).toEqual([
      'Case status', 'Recommended next step', 'Top findings', 'Case data overview',
    ])
    expect(screen.getByText('No assessment yet')).toBeVisible()
    expect(screen.getByText('Waiting for evidence')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Add evidence' }))
    expect(gotoView).toHaveBeenCalledWith('evidence')
    expect(screen.queryByText('Compromise confirmed')).not.toBeInTheDocument()
  })

  it('keeps confirmed decisions visible when the last evidence source is removed', async () => {
    mockCase({ ...DATA, evidence: [] }, [])
    mount()
    expect(await screen.findByText('Compromise confirmed')).toBeVisible()
    expect(screen.getByText('Waiting for evidence')).toBeVisible()
    expect(screen.getByRole('button', { name: '2 confirmed findings' })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Add evidence' })).toBeVisible()
  })

  it('offers retry instead of an empty overview when a required request fails', async () => {
    mockCase()
    const implementation = vi.mocked(api).getMockImplementation()!
    let failing = true
    vi.mocked(api).mockImplementation((path, options) => path.endsWith('/jobs') && failing
      ? Promise.reject(new Error('Unavailable')) : implementation(path, options))
    mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('The case overview could not be loaded.')
    expect(screen.queryByRole('button', { name: 'Prepare the report' })).not.toBeInTheDocument()
    expect(screen.queryByText('No findings detected in the analyzed evidence')).not.toBeInTheDocument()
    failing = false
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
    expect(await screen.findByText('Compromise confirmed')).toBeVisible()
  })

  it.each([
    ['complete with no detections', true, {}, EMPTY_HIGHLIGHTS, 'No findings detected in the analyzed evidence', true],
    ['all dismissed', true, { dismissed: 3 }, EMPTY_HIGHLIGHTS, 'All identified findings dismissed by the analyst', true],
    ['incomplete', false, {}, EMPTY_HIGHLIGHTS, 'Analysis is not complete yet', false],
    ['informational only', true, { new: 2 }, { ...EMPTY_HIGHLIGHTS, informational: 2 }, 'No findings to highlight here', false],
    ['hidden only', true, {}, { ...EMPTY_HIGHLIGHTS, hidden: 1 }, 'No findings to highlight here', false],
    ['missing summary', true, {}, undefined, 'Finding highlights are unavailable', false],
    ['inconsistent summary', true, { confirmed: 1 }, EMPTY_HIGHLIGHTS, 'Finding highlights are unavailable', false],
  ])('keeps the empty highlight assessment accurate: %s', async (_label, complete, triage, top, title, green) => {
    mockCase({ ...DATA, analysis_complete: complete, triage, top_findings: top, confirmed_artifacts: [] })
    mount()
    const highlights = await screen.findByRole('region', { name: 'Top findings' })
    const message = within(highlights).getByText(title)
    expect(message).toBeVisible()
    if (green) expect(message.parentElement).toHaveStyle({ background: 'color-mix(in srgb, var(--ok) 10%, var(--panel))' })
    else expect(message.parentElement).not.toHaveStyle({ background: 'color-mix(in srgb, var(--ok) 10%, var(--panel))' })
    if (!complete) expect(message.parentElement).toHaveStyle({ background: 'var(--review-soft)' })
    if (top?.informational) expect(within(highlights).getByText('2 informational observations')).toBeVisible()
    if (top?.hidden) expect(within(highlights).getByText('1 hidden finding')).toBeVisible()
  })
})
