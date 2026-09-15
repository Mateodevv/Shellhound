import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, type Dashboard as DashboardData } from '../api'
import { renderWithProviders } from '../test/setup'
import { Dashboard } from './Dashboard'
import { copyText } from '../copy'

vi.mock('../copy', () => ({ copyText: vi.fn().mockResolvedValue(true) }))
vi.mock('../api', async orig => ({ ...(await orig<typeof import('../api')>()), api: vi.fn() }))
vi.mock('../components/casework/CaseChain', () => ({ CaseChain: () => <div>Confirmed chronology</div> }))
vi.mock('../components/casework/CaseProfile', () => ({ CaseProfileButton: () => <button>Case profile</button> }))
vi.mock('../components/ui/TimelineChart', () => ({ TimelineChart: () => <div>Request timeline</div> }))
vi.mock('../components/logview/LogCoverage', () => ({ LogCoverage: () => <div>Coverage detail</div> }))
const DATA = { incident_summary: { first_action: 1788858000, last_action: 1788858240, attacker_ips: 2, malware_files: 1 },
  logs: { first_epoch: 1788854400, last_epoch: 1788865200, lines: 7 }, timeline: [] } as unknown as DashboardData
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async path => {
    if (path.endsWith('/dashboard')) return DATA
    if (path.endsWith('/first-sign')) return { state: 'no_confirmed' }
    if (path.endsWith('/case-1')) return { evidence_items: [] }
    if (path.includes('settings')) return { configured: false }
    throw new Error(`Unexpected API call ${path}`)
  })
})
describe('timeline dashboard', () => {
  it('shows confirmed counts, activity times and full log coverage with copy actions', async () => {
    renderWithProviders(<Dashboard slug="case-1" gotoView={vi.fn()} />)
    const summary = await screen.findByRole('region', { name: 'Confirmed incident summary' })
    expect(within(summary).getByText('2')).toBeVisible()
    expect(within(summary).getByText('1')).toBeVisible()
    expect(within(summary).getAllByRole('button')).toHaveLength(5)
    expect(within(summary).getByText('2026-09-08 09:00:00 UTC')).toBeVisible()
    expect(within(summary).getByText('2026-09-08 09:04:00 UTC')).toBeVisible()
    expect(within(summary).getByText('2026-09-08 08:00:00 UTC – 2026-09-08 11:00:00 UTC')).toBeVisible()
    expect(screen.getByText('Confirmed chronology')).toBeVisible()
    fireEvent.click(within(summary).getByRole('button', { name: 'Copy First observed action' }))
    await waitFor(() => expect(copyText).toHaveBeenCalledWith('2026-09-08 09:00:00 UTC'))
  })
  it('does not substitute capture dates or zero for unknown activity', async () => {
    const original = vi.mocked(api).getMockImplementation()!
    vi.mocked(api).mockImplementation(path => path.endsWith('/dashboard') ? Promise.resolve({ ...DATA, incident_summary: { first_action: null, last_action: null, attacker_ips: 0, malware_files: 0 } }) : original(path))
    renderWithProviders(<Dashboard slug="case-1" gotoView={vi.fn()} />)
    const summary = await screen.findByRole('region', { name: 'Confirmed incident summary' })
    expect(within(summary).getAllByText('Not observed')).toHaveLength(2)
    expect(within(summary).getAllByText('0')).toHaveLength(2)
    expect(within(summary).queryByRole('button', { name: 'Copy First observed action' })).toBeNull()
  })
  it('keeps case profile without the removed dashboard controls', async () => {
    renderWithProviders(<Dashboard slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByRole('button', { name: 'Case profile' })).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Evidence & analysis' })).not.toBeInTheDocument()
    expect(screen.queryByText('First known sign of compromise')).not.toBeInTheDocument()
  })
  it('offers retry after a dashboard request fails', async () => {
    vi.mocked(api).mockRejectedValue(new Error('Unavailable'))
    renderWithProviders(<Dashboard slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(vi.mocked(api).mock.calls.filter(([path]) => path.endsWith('/dashboard')).length).toBeGreaterThan(1))
  })
})
