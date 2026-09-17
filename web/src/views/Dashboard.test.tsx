import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, type CaseDetail, type Dashboard as DashboardData, type Job } from '../api'
import { renderWithProviders } from '../test/setup'
import { Dashboard } from './Dashboard'

vi.mock('../components/casework/CaseProfile', () => ({ CaseProfileButton: () => <button>Case profile</button> }))

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
  incident_summary: { first_action: AT, last_action: AT + 120, attacker_ips: 2, confirmed_ips: 2, pending_ips: 3, malware_files: 1, pending_malware_files: 4, last_action_event_id: 'last-log-event' },
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
    if (path.includes('/timeline-preview')) return { buckets: [], totals: { filesystem_confirmed: 0, filesystem_pending: 0, log_confirmed: 0, log_pending: 0 }, span: { first: null, last: null }, interval: 0, undated: 0, unavailable: 0, zone: 'UTC' }
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

describe('case overview dashboard', () => {
  it('opens the exact review queue from its compact header action and status counts', async () => {
    mockCase({ ...DATA, triage: { new: 3, reviewed: 1, confirmed: 2 } })
    const { gotoView } = mount()
    const header = await screen.findByRole('banner')
    fireEvent.click(within(header).getByRole('button', { name: 'Review 4 outstanding findings' }))
    expect(gotoView).toHaveBeenLastCalledWith('findings', { triage: 'new,reviewed', severity: '0,1,2,3' })
    expect(screen.queryByRole('region', { name: 'Recommended next step' })).toBeNull()
    const status = screen.getByRole('region', { name: 'Case status' })
    fireEvent.click(within(status).getByRole('button', { name: '2 confirmed findings' }))
    expect(gotoView).toHaveBeenLastCalledWith('findings', { triage: 'confirmed', severity: '0,1,2,3' })
    expect(screen.getByText('Analysis complete')).toBeVisible()
  })

  it('keeps confirmed compromise distinct from incomplete technical coverage', async () => {
    mockCase({ ...DATA, analysis_complete: false }, [{ ...DONE, state: 'failed' }])
    mount()
    expect(await screen.findByText('Compromise confirmed')).toBeVisible()
    expect(screen.getByText('An analysis check failed')).toBeVisible()
    expect(screen.queryByText('Analysis complete')).toBeNull()
  })

  it('shows a running analysis before review and does not report completion', async () => {
    mockCase({ ...DATA, triage: { new: 2 }, analysis_complete: false }, [{ ...DONE, state: 'running' }])
    mount()
    const header = await screen.findByRole('banner')
    expect(within(header).getByRole('button', { name: 'View analysis progress' })).toBeVisible()
    expect(screen.getByText('Analysis in progress')).toBeVisible()
    expect(screen.queryByText('Analysis complete')).toBeNull()
  })

  it('does not leave accepted scan warnings in coverage gaps', async () => {
    mockCase({ ...DATA, triage: {}, analysis_warnings: 0, analysis_accepted: 12 })
    mount()
    expect(await screen.findByText('Analysis complete')).toBeVisible()
    expect(screen.queryByText('Unresolved scan warnings')).toBeNull()
    expect(within(screen.getByRole('banner')).getByRole('button', { name: 'Prepare case hand-off' })).toBeVisible()
  })

  it('gives an empty case an evidence action without suggesting a clean system', async () => {
    mockCase({ ...DATA, evidence: [], triage: {}, analysis_complete: false, logs: null, incident_summary: undefined }, [])
    mount()
    expect(await screen.findByRole('button', { name: 'Add evidence' })).toBeVisible()
    expect(screen.queryByText('Analysis complete — no findings')).toBeNull()
    expect(screen.getAllByText('Summary unavailable')).toHaveLength(2)
  })

  it('shows separate confirmed and pending group counts that link to exact findings sets', async () => {
    mockCase()
    const { gotoView } = mount()
    const summary = await screen.findByRole('region', { name: 'Evidence at a glance' })
    fireEvent.click(within(summary).getByRole('button', { name: '2 confirmed · Linked IPs' }))
    expect(gotoView).toHaveBeenLastCalledWith('findings', { summary_group: 'ips', triage: 'confirmed', severity: '0,1,2,3' })
    fireEvent.click(within(summary).getByRole('button', { name: '4 awaiting review · Webshells / malware' }))
    expect(gotoView).toHaveBeenLastCalledWith('findings', { summary_group: 'malware_files', triage: 'new,reviewed', severity: '0,1,2,3' })
    expect(screen.queryByRole('region', { name: 'Top findings' })).toBeNull()
  })

  it('links the latest confirmed observation by stable event ID and coverage to logs', async () => {
    mockCase()
    const { gotoView } = mount()
    const summary = await screen.findByRole('region', { name: 'Evidence at a glance' })
    const latest = within(summary).getByText('Latest observed activity').parentElement!
    fireEvent.click(within(latest).getByRole('button'))
    expect(gotoView).toHaveBeenLastCalledWith('timeline', { scope: 'confirmed', event: 'last-log-event' })
    const coverage = within(summary).getByText('Log coverage').parentElement!
    fireEvent.click(within(coverage).getByRole('button'))
    expect(gotoView).toHaveBeenLastCalledWith('logs')
    fireEvent.click(screen.getByRole('button', { name: 'Open full timeline' }))
    expect(gotoView).toHaveBeenLastCalledWith('timeline', { scope: 'all' })
  })

  it('does not substitute capture dates for unknown observed activity', async () => {
    mockCase({ ...DATA, incident_summary: { ...DATA.incident_summary!, last_action: null } })
    mount()
    const summary = await screen.findByRole('region', { name: 'Evidence at a glance' })
    expect(within(summary).getByText('Not observed')).toBeVisible()
    expect(within(within(summary).getByText('Latest observed activity').parentElement!).queryByRole('button')).toBeNull()
  })

  it('retains unapplied Pattern Hunt results as a separate run link', async () => {
    mockCase({ ...DATA, triage: {}, hunt_summary: { ...HUNT, fresh: false } })
    const { gotoView } = mount()
    fireEvent.click(await screen.findByRole('button', { name: /Pattern Hunt: 2 matched patterns/ }))
    expect(gotoView).toHaveBeenCalledWith('hunt', { section: 'runs', batch: 'saved-run-7' })
    expect(screen.getByText('Historical check — needs a new run')).toBeVisible()
    expect(screen.queryByText('Compromise confirmed')).toBeNull()
  })

  it('keeps status and evidence available if the independent timeline query fails', async () => {
    mockCase()
    const original = vi.mocked(api).getMockImplementation()!
    vi.mocked(api).mockImplementation(path => path.includes('/timeline-preview') ? Promise.reject(new Error('Offline')) : original(path))
    mount()
    expect(await screen.findByText('Compromise confirmed')).toBeVisible()
    expect(await screen.findByRole('alert')).toHaveTextContent('evidence timeline could not be loaded')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(vi.mocked(api).mock.calls.filter(([path]) => path.includes('/timeline-preview')).length).toBeGreaterThan(1))
  })

  it('does not render failed dashboard data as an empty case', async () => {
    mockCase()
    const original = vi.mocked(api).getMockImplementation()!
    vi.mocked(api).mockImplementation(path => path.endsWith('/dashboard') ? Promise.reject(new Error('Offline')) : original(path))
    mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
    expect(screen.queryByText('Analysis complete')).toBeNull()
    expect(screen.queryByText('Not observed')).toBeNull()
  })
})
