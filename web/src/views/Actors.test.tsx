import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import {
  api, post, type Actor, type ActorComparison, type ActorDetail,
  type ActorsResponse, type CaseDetail,
} from '../api'
import { renderWithProviders } from '../test/setup'
import { Actors } from './Actors'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
}))

const ACTOR: Actor = {
  ip_id: 1,
  ip: '203.0.113.42',
  requests: 96,
  first_epoch: 1_752_000_000,
  last_epoch: 1_752_003_600,
  tz: 0,
  err4: 2,
  err5: 0,
  bytes: 12_400,
  bytes_unknown: 0,
  posts: 1,
  login_posts: 0,
  login_redirects: 0,
  admin_ok: 0,
  login_statuses: '[]',
  scanner_uas: '[]',
  sqli_attempts: 0,
  sqli_ok: 0,
  traversal_attempts: 0,
  traversal_ok: 0,
  upload_php_attempts: 0,
  upload_php_ok: 0,
  cms_dir_php_attempts: 0,
  cms_dir_php_ok: 0,
  login_first: null,
  login_last: null,
  login_burst: 0,
  agents: 1,
  alerts: [],
  sparkline: [1, 4, 2],
  in_box: false,
  triage: 'confirmed',
}

const RESPONSE: ActorsResponse = {
  total: 75,
  actors: [ACTOR],
  span: null,
  bf_threshold: 30,
  facets: {
    all: 38_952,
    quiet: 38_877,
    relevant: 75,
    alerted: 36,
    scanner: 39,
    bruteforce: 2,
    probes: 77,
    ioc: 4,
    triage: { new: 1, reviewed: 1, confirmed: 34, dismissed: 2 },
  },
}

const SECOND_ACTOR: Actor = {
  ...ACTOR, ip_id: 2, ip: '198.51.100.8', requests: 12,
  triage: null, alerts: [],
}

const COMPARISON: ActorComparison = {
  actors: [ACTOR, SECOND_ACTOR],
  time_overlap: { from_epoch: ACTOR.first_epoch!, to_epoch: ACTOR.last_epoch! },
  shared_paths: [{ uri: '/uploads/drop.php', actors: 2, hits: 5, ok: 4 }],
  shared_agents: [],
}

const DETAIL: ActorDetail = {
  actor: ACTOR,
  alerts: [],
  top_paths: [{ uri: '/index.php', n: 40, ok: 39 }],
  top_agents: [{ agent: 'Mozilla/5.0', n: 96 }],
  triage: 'confirmed',
  triage_note: 'Correlated with the shell access window.',
  triaged_at: '2026-08-01T10:00:00Z',
  worst: 0,
  findings: [],
  in_box: false,
  relations: [{
    ip: '198.51.100.8', shared_requests: 3, successful: 2,
    shared_paths: ['/uploads/drop.php'], triage: null, in_box: false,
  }],
}

const CASE = {
  evidence_items: [],
  log_index: { exists: true, fresh: true, reason: '', lines: 100, clients: 1, unparsed: 0, size: 10 },
} as unknown as CaseDetail

function mockApi() {
  vi.mocked(api).mockImplementation(async (path) => {
    if (path.includes('/actors?')) return RESPONSE
    if (path.includes('/actor?')) return DETAIL
    if (path.endsWith('/case-1')) return CASE
    throw new Error(`unexpected API call: ${path}`)
  })
  vi.mocked(post).mockImplementation(async (path) => {
    if (path === '/api/geo') return {
      available: false, source: '', why: '', results: {},
    }
    throw new Error(`unexpected POST call: ${path}`)
  })
}

describe('actors investigation workspace', () => {
  it('starts with relevant evidence sorting and keeps analyst confirmation separate', async () => {
    mockApi()
    renderWithProviders(<Actors slug="case-1" gotoView={vi.fn()} />)

    await screen.findByText('Clients & actors')
    await waitFor(() => expect(vi.mocked(api).mock.calls.some(([path]) =>
      path.includes('/actors?') && path.includes('hide=quiet')
      && path.includes('sort=evidence') && path.includes('limit=50'))).toBe(true))

    expect(screen.getAllByText('Analyst-confirmed client').length).toBeGreaterThan(0)
    expect(screen.queryByText('unremarkable')).not.toBeInTheDocument()
    expect(await screen.findByText('Correlated with the shell access window.')).toBeInTheDocument()
  })

  it('maps investigation views and pagination to explicit server queries', async () => {
    mockApi()
    renderWithProviders(<Actors slug="case-1" gotoView={vi.fn()} />)
    await screen.findByText('Clients & actors')

    fireEvent.click(screen.getByRole('button', { name: /^Confirmed/ }))
    await waitFor(() => expect(vi.mocked(api).mock.calls.some(([path]) =>
      path.includes('/actors?') && path.includes('triage_states=confirmed'))).toBe(true))

    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(vi.mocked(api).mock.calls.some(([path]) =>
      path.includes('/actors?') && path.includes('offset=50'))).toBe(true))
  })

  it('keeps secondary investigation filters out of the primary navigation', async () => {
    mockApi()
    renderWithProviders(<Actors slug="case-1" gotoView={vi.fn()} />)
    await screen.findByText('Clients & actors')

    expect(screen.queryByRole('button', { name: /^Notable/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Filters' }))
    fireEvent.click(screen.getByRole('button', { name: 'Notable' }))
    await waitFor(() => expect(vi.mocked(api).mock.calls.some(([path]) =>
      path.includes('/actors?') && path.includes('flag=alerted'))).toBe(true))
  })

  it('compares a small selected scope and labels overlap as evidence, not attribution', async () => {
    mockApi()
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.includes('/actors?')) return { ...RESPONSE, actors: [ACTOR, SECOND_ACTOR] }
      if (path.includes('/actor?')) return DETAIL
      if (path.endsWith('/case-1')) return CASE
      throw new Error(`unexpected API call: ${path}`)
    })
    vi.mocked(post).mockImplementation(async (path) => {
      if (path === '/api/geo') return {
        available: false, source: '', why: '', results: {},
      }
      if (path.endsWith('/actors/compare')) return COMPARISON
      throw new Error(`unexpected POST call: ${path}`)
    })
    renderWithProviders(<Actors slug="case-1" gotoView={vi.fn()} />)
    await screen.findByText('Clients & actors')

    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select client 203.0.113.42' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select client 198.51.100.8' }))
    fireEvent.click(screen.getByRole('button', { name: 'Compare' }))

    expect(await screen.findByRole('dialog', { name: 'Compare actors' })).toBeInTheDocument()
    expect(await screen.findByText('/uploads/drop.php')).toBeInTheDocument()
    expect(screen.getByText(/not automatic campaign attribution/i)).toBeInTheDocument()
  })

  it('opens a deep-linked client directly in its activity detail', async () => {
    history.replaceState(null, '', '/?case=case-1&view=actors&search=203.0.113.42'
      + '&actor=203.0.113.42&section=activity')
    mockApi()
    renderWithProviders(<Actors slug="case-1" gotoView={vi.fn()} />)

    expect(await screen.findByRole('button', { name: 'Activity' })).toHaveAttribute(
      'aria-pressed', 'true')
    expect(await screen.findByText('/index.php')).toBeInTheDocument()
    await waitFor(() => expect(vi.mocked(api).mock.calls.some(([path]) =>
      path.includes('/actors?') && path.includes('search=203.0.113.42'))).toBe(true))
  })
})
