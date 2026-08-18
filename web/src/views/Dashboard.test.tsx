import { fireEvent, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, type Dashboard as DashboardData } from '../api'
import { renderWithProviders } from '../test/setup'
import { Dashboard } from './Dashboard'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
}))

const AT = 1_752_000_000

const DASHBOARD: DashboardData = {
  severity: { '0': 4 },
  triage: { confirmed: 2 },
  confirmed_kinds: { file: 1, client: 1 },
  confirmed_severity: { '0': 2 },
  confirmed_artifacts: [
    { artifact: '/srv/www/images/shell.php', artifact_kind: 'file', worst: 0 },
    { artifact: '203.0.113.9', artifact_kind: 'client', worst: 0 },
  ],
  findings_total: 4,
  iocs: 7,
  accounts: 8,
  admins: 2,
  cms_installs: [{ id: 1, root: '/srv/www', cms: 'WordPress', version: '6.7' }],
  evidence: [{
    id: 1,
    kind: 'webroot',
    path: '/srv/www',
    added: '2026-08-01T00:00:00Z',
    scanned_at: '2026-08-01T00:00:00Z',
    stats: {},
  }],
  jobs_running: [],
  logs: {
    lines: 12_400,
    clients: 390,
    unparsed: 3,
    alerted_clients: 6,
    first_epoch: AT,
    last_epoch: AT + 86_400,
  },
  timeline: [],
  chronology: {
    total_events: 2,
    event_span: { first: AT, last: AT + 86_400 },
    first_success_at: AT + 120,
    observations: [{
      role: 'first_success',
      at: AT + 120,
      kind: 'erfolg',
      title: 'Confirmed web shell returned HTTP 200',
      detail: '/images/shell.php',
      source: 'log',
      artifact: '/srv/www/images/shell.php',
      artifact_kind: 'file',
      ip: '203.0.113.9',
      severity: 0,
    }],
    gaps: ['The capture begins after the first confirmed file timestamp.'],
    undated: 1,
    zone: 'UTC',
    tz_offsets: ['UTC'],
    tz_mixed: false,
  },
}

describe('forensic dashboard briefing', () => {
  it('separates confirmed compromise from observed context and states evidence limits', async () => {
    const gotoView = vi.fn()
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.endsWith('/dashboard')) return DASHBOARD
      if (path.endsWith('/coverage')) return {
        quiet: { windows: [], checked: true, total: 0 },
        files: [], notes: [], tz: 0,
      }
      throw new Error(`unexpected API call: ${path}`)
    })

    renderWithProviders(<Dashboard slug="case-1" gotoView={gotoView} />)

    expect(await screen.findByText('Compromise confirmed')).toBeInTheDocument()
    expect(screen.getByText('Confirmed scope')).toBeInTheDocument()
    expect(screen.getByText('Only artifacts confirmed in this case.')).toBeInTheDocument()

    expect(screen.getByText('Observed context')).toBeInTheDocument()
    expect(screen.getByText(/not automatically confirmed as part of the compromise/)).toBeInTheDocument()
    expect(screen.getAllByText('Notable clients')).toHaveLength(1)
    expect(screen.queryByText('Dated observations')).not.toBeInTheDocument()

    expect(screen.getByText('First 2xx fetch of a confirmed path')).toBeInTheDocument()
    expect(screen.getByText(/proves neither successful exploitation nor system access/)).toBeInTheDocument()
    expect(screen.getByText(/1 confirmed artifacts have no measured time reference/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Notable clients/ }))
    expect(gotoView).toHaveBeenCalledWith('actors')
  })
})
