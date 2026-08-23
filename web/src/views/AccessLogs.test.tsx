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

    await screen.findByText('Access Log Explorer')
    expect(await screen.findByText(ROW.uri, { selector: 'span' })).toBeInTheDocument()
    expect(screen.getByText('access.log:42')).toBeInTheDocument()

    fireEvent.click(screen.getByText(ROW.uri, { selector: 'span' }))
    expect(await screen.findByText(CONTEXT.raw_line)).toBeInTheDocument()
    expect(screen.getAllByText('PHP in upload path').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Scanner User-Agent').length).toBeGreaterThan(0)
  })

  it('turns facet choices into structured server filters', async () => {
    mockApi()
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    await screen.findByText('Access Log Explorer')

    const clientFacet = await screen.findByTitle(ROW.client)
    fireEvent.click(clientFacet)
    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) =>
      path.endsWith('/access/search')
      && (body as { clients: string[] }).clients.includes(ROW.client))).toBe(true))
  })

  it('drills a normalized pattern through a real example URI', async () => {
    mockApi()
    renderWithProviders(<AccessLogs slug="case-1" gotoView={vi.fn()} />)
    await screen.findByText('Access Log Explorer')

    fireEvent.click(screen.getByRole('button', { name: 'Patterns' }))
    fireEvent.click(await screen.findByRole('button', { name: /\/api\/users\/:n/ }))

    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) =>
      path.endsWith('/access/search')
      && (body as { search: string }).search === '/api/users/123')).toBe(true))
  })
})
