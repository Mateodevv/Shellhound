import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import {
  api, del, post, type AccessLogRow, type AccessOverview,
  type AccessPatternsResponse, type AccessRequestContext,
  type AccessSearchResponse, type CaseDetail,
} from '../api'
import { renderWithProviders } from '../test/setup'
import { AccessLogs } from './AccessLogs'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
  del: vi.fn(),
}))

const ROW: AccessLogRow = {
  request_id: 7,
  request_key: '0123456789abcdef:42',
  client: '203.0.113.42',
  epoch: 1_752_000_000,
  tz: 0,
  method: 'POST',
  uri: '/wp-content/uploads/drop.php',
  status: 200,
  size: 512,
  referrer: '-',
  agent: 'sqlmap/1.8',
  source: 'access.log',
  source_id: 1,
  line_no: 42,
  signals: ['upload_php', 'scanner_ua'],
}

const SEARCH: AccessSearchResponse = {
  total: 1,
  rows: [ROW],
  next_cursor: null,
  summary: {
    first_epoch: ROW.epoch,
    last_epoch: ROW.epoch,
    ok: 1,
    redirects: 0,
    client_errors: 0,
    server_errors: 0,
  },
}

const OVERVIEW: AccessOverview = {
  total: 1,
  bucket_seconds: 60,
  timeline: [{
    start_epoch: ROW.epoch,
    end_epoch: ROW.epoch + 59,
    requests: 1,
    ok: 1,
    errors: 0,
    signals: 1,
  }],
  facets: {
    status: [{ value: '2xx', count: 1 }],
    methods: [{ value: 'POST', count: 1 }],
    clients: [{ value: ROW.client, count: 1 }],
    paths: [{ value: ROW.uri, count: 1 }],
    agents: [{ value: ROW.agent, count: 1 }],
    sources: [{ value: 1, label: ROW.source, count: 1 }],
  },
}

const CONTEXT: AccessRequestContext = {
  request: ROW,
  before: [],
  after: [],
  raw_line: `${ROW.client} - - [10/Jul/2025:12:00:00 +0000] "POST ${ROW.uri} HTTP/1.1" 200 512`,
  raw_truncated: false,
}

const PATTERNS: AccessPatternsResponse = {
  patterns: [{
    pattern: '/api/users/:n',
    requests: 9,
    clients: 2,
    ok: 8,
    errors: 1,
    first_epoch: ROW.epoch,
    last_epoch: ROW.epoch + 60,
    examples: ['/api/users/123'],
    signals: [],
  }],
  sampled_uris: 1,
  truncated: false,
}

const CASE = {
  evidence_items: [],
  log_index: {
    exists: true, fresh: true, reason: '', lines: 1, clients: 1,
    unparsed: 0, size: 1,
  },
} as unknown as CaseDetail

function mockApi() {
  vi.mocked(api).mockImplementation(async (path) => {
    if (path.endsWith('/case-1')) return CASE
    if (path.endsWith('/access/saved')) return []
    if (path.endsWith('/access/clips')) return []
    if (path.endsWith('/access/request/7')) return CONTEXT
    throw new Error(`unexpected API call: ${path}`)
  })
  vi.mocked(post).mockImplementation(async (path) => {
    if (path.endsWith('/access/search')) return SEARCH
    if (path.endsWith('/access/overview')) return OVERVIEW
    if (path.endsWith('/access/patterns')) return PATTERNS
    if (path.endsWith('/access/segments')) return {
      requires_client: true, truncated: false, segments: [],
    }
    throw new Error(`unexpected POST call: ${path}`)
  })
  vi.mocked(del).mockResolvedValue({ ok: true })
}

describe('access-log investigation workspace', () => {
  it('starts with the complete request stream and opens citable raw context', async () => {
    mockApi()
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)

    await screen.findByText(ROW.uri, { selector: 'span' })
    expect(await screen.findByText(ROW.uri, { selector: 'span' })).toBeInTheDocument()
    expect(screen.queryByText('access.log:42')).not.toBeInTheDocument()
    expect(screen.getByText('Traffic overview and distributions').closest('details'))
      .not.toHaveAttribute('open')
    expect(screen.queryByText('Field distributions')).not.toBeInTheDocument()

    fireEvent.click(screen.getByText(ROW.uri, { selector: 'span' }))
    expect(await screen.findByText(CONTEXT.raw_line)).toBeInTheDocument()
    expect(screen.queryByText('PHP in upload path')).not.toBeInTheDocument()
    expect(screen.getByText(ROW.agent)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Copy User-Agent' })).toBeVisible()
  })

  it('turns facet choices into structured server filters', async () => {
    mockApi()
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    await screen.findByText(ROW.uri, { selector: 'span' })

    fireEvent.click(screen.getByRole('button', { name: 'Filters' }))
    const clientFacet = await screen.findByTitle(ROW.client)
    fireEvent.click(clientFacet)
    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) =>
      path.endsWith('/access/search')
      && (body as { clients: string[] }).clients.includes(ROW.client))).toBe(true))
  })

  it('drills a normalized pattern through a real example URI', async () => {
    mockApi()
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    await screen.findByText(ROW.uri, { selector: 'span' })

    fireEvent.click(screen.getByRole('button', { name: 'Patterns' }))
    fireEvent.click(await screen.findByRole('button', { name: /\/api\/users\/:n/ }))

    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) =>
      path.endsWith('/access/search')
      && (body as { search: string }).search === '/api/users/123')).toBe(true))
  })

  it('seeds Pattern Hunt from the inspected original request', async () => {
    mockApi()
    const gotoView = vi.fn()
    renderWithProviders(<AccessLogs slug="case-1" gotoView={gotoView} />)
    await screen.findByText(ROW.uri, { selector: 'span' })
    fireEvent.click(await screen.findByText(ROW.uri, { selector: 'span' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Use as pattern' }))
    expect(gotoView).toHaveBeenCalledWith('hunt', { request: '7' })
  })
  it('shows missing User-Agent explicitly and closes the mobile detail overlay', async () => {
    mockApi()
    const original = vi.mocked(api).getMockImplementation()!
    vi.mocked(api).mockImplementation(async path => path.endsWith('/access/request/7') ? { ...CONTEXT, request: { ...ROW, agent: '', referrer: 'https://example.test/' } } : original(path))
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByText(ROW.uri, { selector: 'span' }))
    expect(await screen.findByText('Not recorded')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Copy User-Agent' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /^Close/ }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('resizes desktop details by keyboard and restores table space on close', async () => {
    mockApi()
    vi.spyOn(window, 'matchMedia').mockReturnValue({ matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() } as unknown as MediaQueryList)
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    expect(screen.queryByRole('separator')).not.toBeInTheDocument()
    fireEvent.click(await screen.findByText(ROW.uri, { selector: 'span' }))
    const divider = screen.getByRole('separator')
    fireEvent.keyDown(divider, { key: 'ArrowLeft' })
    expect(divider).toHaveAttribute('aria-valuenow', '400')
    expect(localStorage.getItem('shellhound.logs.inspectorWidth')).toBe('400')
    fireEvent.keyDown(divider, { key: 'End' })
    expect(divider).toHaveAttribute('aria-valuenow', '560')
    fireEvent.click(screen.getByRole('button', { name: /^Close/ }))
    expect(screen.queryByRole('separator')).not.toBeInTheDocument()
  })

  it('copies the full User-Agent and expands the raw record', async () => {
    mockApi()
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } })
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByText(ROW.uri, { selector: 'span' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Copy User-Agent' }))
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(ROW.agent))
    fireEvent.click(screen.getByRole('button', { name: 'Expand' }))
    expect(screen.getAllByText(CONTEXT.raw_line)).toHaveLength(2)
  })

  it('applies a UTC range and clears all filters', async () => {
    mockApi()
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    await screen.findByText(ROW.uri, { selector: 'span' })
    fireEvent.click(screen.getByRole('button', { name: 'Time range' }))
    fireEvent.change(screen.getByLabelText('From (UTC)'), { target: { value: '2026-09-08T09:00' } })
    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) => path.endsWith('/access/search') && (body as { from_epoch: number }).from_epoch === Date.parse('2026-09-08T09:00:00Z') / 1000)).toBe(true))
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
    await waitFor(() => expect(vi.mocked(post).mock.calls.filter(([path]) => path.endsWith('/access/search')).at(-1)?.[1]).toEqual(expect.objectContaining({ from_epoch: null, signals_only: false })))
  })

  it('keeps export scoped and saves queries and observations through existing endpoints', async () => {
    mockApi()
    const original = vi.mocked(post).getMockImplementation()!
    vi.mocked(post).mockImplementation(async (path, body) => path.endsWith('/access/saved') || path.endsWith('/access/clips') ? {} : original(path, body))
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByText(ROW.uri, { selector: 'span' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Add to evidence basket' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case-1/access/clips', { request_id: 7, note: '' }))
    fireEvent.click(screen.getByRole('button', { name: /^Close/ }))
    fireEvent.click(screen.getByLabelText('Log actions'))
    const exportLink = screen.getByRole('link', { name: 'Export scope' })
    expect(exportLink.getAttribute('href')).toContain('/access/export?filters=')
    fireEvent.click(screen.getByRole('button', { name: 'Save search' }))
    fireEvent.change(screen.getByPlaceholderText('Investigation name…'), { target: { value: 'Synthetic search' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case-1/access/saved', expect.objectContaining({ name: 'Synthetic search' })))
  })

})
