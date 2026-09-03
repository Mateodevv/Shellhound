import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import {
  api, del, patch, post, type ActorDetail, type HuntPattern, type HuntRuleV2, type HuntTest,
} from '../api'
import { renderWithProviders } from '../test/setup'
import { Hunt } from './Hunt'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn(),
}))

vi.mock('@tanstack/react-virtual', () => ({
  useVirtualizer: ({ count }: { count: number }) => {
    const items = Array.from({ length: count }, (_, index) => ({
      index, key: index, start: index * 43, size: 43, end: (index + 1) * 43,
    }))
    return {
      getVirtualItems: () => items,
      getTotalSize: () => count * 43,
      measureElement: () => {},
    }
  },
}))

const RULE: HuntRuleV2 = { client_match: 'any', requests: [{ clauses: [
  { field: 'uri', operator: 'equals', values: ['/wp-content/uploads/drop.php'] },
] }] }

const PATTERN: HuntPattern = {
  id: 'bundled-sample', patterns: ['/wp-content/uploads/drop.php'], match: 'any',
  request: { methods: [], user_agents: [] }, name: 'Bundled sample', cve: '',
  description: 'The request matches the selected path.', added: '2026-01-01',
  source: 'bundled', enabled: true, rule: RULE, rule_hash: 'rule-hash',
  dsl: 'client any\nrequest\n  uri equals ["/wp-content/uploads/drop.php"]\nend',
  technology: 'wordpress', version: 1, archived: false, own_enabled: true,
  created_at: '2026-01-01', updated_at: '2026-01-01', derived_from: null,
}

const TEST: HuntTest = {
  id: 41, pattern_id: PATTERN.id, pattern_version: 1, rule_hash: 'rule-hash',
  rule: RULE, dsl: PATTERN.dsl, tested_at: '2026-08-31T10:00:00',
  index_fingerprint: 'index-1', hits: 3, ok_hits: 2, clients: 1,
  ok_clients: 1, uris: 1, first_epoch: 1_700_000_000,
  last_epoch: 1_700_000_060, tz: 0, truncated: false,
  coverage: { requests: 30, fields: { uri: { present: 30, total: 30, ratio: 1 } } },
  batch_id: '',
}

const CLUSTER = {
  cluster_key: 'cluster-1', client: '203.0.113.42', method: 'GET',
  uri_pattern: '/wp-content/uploads/drop.php', status_class: '2xx',
  requests: 2, ok_hits: 2, first_epoch: 1_700_000_000,
  last_epoch: 1_700_000_060, tz: 0, request_id: 7,
  example_uri: '/wp-content/uploads/drop.php',
}

const ACTOR_DETAIL = {
  actor: {
    ip_id: 1, ip: CLUSTER.client, requests: 8,
    first_epoch: CLUSTER.first_epoch, last_epoch: CLUSTER.last_epoch, tz: 0,
    err4: 0, err5: 0, bytes: 1000, bytes_unknown: 0, posts: 0,
    login_posts: 0, login_redirects: 0, admin_ok: 0, login_statuses: '[]',
    scanner_uas: '[]', sqli_attempts: 1, sqli_ok: 1,
    traversal_attempts: 0, traversal_ok: 0, upload_php_attempts: 6,
    upload_php_ok: 6, cms_dir_php_attempts: 0, cms_dir_php_ok: 0,
    login_first: null, login_last: null, login_burst: 0, agents: 1,
    alerts: [], sparkline: [1, 3, 4], in_box: false, triage: null,
  },
  alerts: [],
  top_paths: [{ uri: CLUSTER.example_uri, n: 6, ok: 6 }],
  top_agents: [{ agent: 'Mozilla/5.0', n: 8 }],
  triage: null, triage_note: '', triaged_at: '', worst: null,
  findings: [], in_box: false, relations: [],
} as ActorDetail

const OWN: HuntPattern = {
  ...PATTERN, id: 'own-variant', source: 'own', name: 'Edited sample',
  version: 1, derived_from: { id: PATTERN.id, version: 1, source: 'bundled' },
}

function mocks() {
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/patterns') return { patterns: [PATTERN], path: 'patterns.json' }
    if (path.includes('/hunt/tests?')) return { tests: [] }
    if (path.endsWith('/versions')) return { versions: [{ version: 1 }] }
    if (path.includes('/access/request/7')) return {
      request: { ...CLUSTER, request_key: 'source:7', source_id: 1, line_no: 7,
        epoch: CLUSTER.first_epoch, status: 200, size: 12, referrer: '-', agent: 'curl',
        source: 'access.log', signals: [] },
      before: [], after: [], raw_line: '203.0.113.42 GET /wp-content/uploads/drop.php 200',
      raw_truncated: false,
    }
    if (path.includes('/actor?ip=')) return {
      ...ACTOR_DETAIL,
    }
    throw new Error(`unexpected API call: ${path}`)
  })
  vi.mocked(post).mockImplementation(async (path) => {
    if (path.endsWith('/hunt/tests')) return { test: TEST, result: {
      hits: 3, ok_hits: 2, clients_total: 1, ok_clients: 1, uri_total: 1,
      clients: [], uris: [], first_epoch: TEST.first_epoch, last_epoch: TEST.last_epoch,
      tz: 0, timeline: [], truncated: false, clients_truncated: false,
      uris_truncated: false, rule: RULE, rule_hash: TEST.rule_hash,
      coverage: TEST.coverage,
    } }
    if (path.endsWith('/clusters')) return { clusters: [CLUSTER], total: 1, next_cursor: null }
    if (path.endsWith('/clone')) return OWN
    if (path.endsWith('/apply')) return {
      application_id: 5, pattern: OWN, findings: 1, already_applied: false,
    }
    throw new Error(`unexpected POST call: ${path}`)
  })
  vi.mocked(patch).mockResolvedValue(OWN)
  vi.mocked(del).mockResolvedValue({})
}

describe('Pattern Hunt forensic workbench', () => {
  it('does not query while editing and applies only an explicitly selected cluster', async () => {
    sessionStorage.clear()
    sessionStorage.setItem('shellhound:hunt-workbench:case-1', JSON.stringify({
      resultCollapsed: true,
    }))
    history.replaceState(null, '', '/?case=case-1&view=hunt')
    mocks()
    const gotoView = vi.fn()
    renderWithProviders(<Hunt slug="case-1" gotoView={gotoView} />)

    expect(screen.queryByRole('textbox', { name: 'Name' })).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: 'Edit rule' }))
    const name = await screen.findByDisplayValue('Bundled sample')
    fireEvent.change(name, { target: { value: 'Edited sample' } })
    expect(vi.mocked(post).mock.calls.some(([path]) => path.endsWith('/hunt/tests'))).toBe(false)
    expect(screen.getByRole('button', { name: 'Save rule' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Apply selected (0)' })).toBeDisabled()

    fireEvent.click(screen.getByRole('button', { name: 'Test' }))
    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path]) =>
      path.endsWith('/hunt/tests'))).toBe(true))
    expect(screen.queryByTitle('Hits and evidence')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Apply selected (0)' })).toBeDisabled()
    expect(screen.getByText(/Save the rule first/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save rule' }))
    expect(await screen.findByText('Create an own variant')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save own variant' }))
    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path]) =>
      path.endsWith('/clone'))).toBe(true))
    expect(screen.getByText(/Select at least one request cluster on the right/)).toBeInTheDocument()
    expect(screen.queryByText('Request inspector')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Requests · Sort ascending' }))
    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) =>
      path.endsWith('/clusters')
      && (body as { sort: string; direction: string }).sort === 'requests'
      && (body as { sort: string; direction: string }).direction === 'asc')).toBe(true))
    fireEvent.click(await screen.findByRole('button', { name: '203.0.113.42' }))
    expect(await screen.findByRole('button', { name: 'Activity' })).toHaveAttribute(
      'aria-pressed', 'true')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect((await screen.findAllByText('/wp-content/uploads/drop.php')).length).toBeGreaterThan(1)
    expect(gotoView).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Close (Esc)' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    const checkbox = await screen.findByLabelText('Select request cluster')
    fireEvent.click(checkbox)
    expect(screen.getByRole('button', { name: 'Apply selected (1)' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Apply selected (1)' }))

    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) =>
      path.endsWith('/apply')
      && (body as { cluster_keys: string[]; pattern_id: string }).cluster_keys.join() === 'cluster-1'
      && (body as { pattern_id: string }).pattern_id === OWN.id)).toBe(true))
    await waitFor(() => expect(screen.queryByRole('textbox', { name: 'Name' })).not.toBeInTheDocument())
  })

  it('restores the open draft when the analyst leaves and returns', async () => {
    sessionStorage.clear()
    history.replaceState(null, '', '/?case=case-state&view=hunt')
    mocks()
    const first = renderWithProviders(<Hunt slug="case-state" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Edit rule' }))
    const name = await screen.findByDisplayValue('Bundled sample')
    fireEvent.change(name, { target: { value: 'Draft kept across tabs' } })
    await waitFor(() => expect(JSON.parse(
      sessionStorage.getItem('shellhound:hunt-workbench:case-state') || '{}')
      .draft.name).toBe('Draft kept across tabs'))
    first.unmount()

    renderWithProviders(<Hunt slug="case-state" gotoView={vi.fn()} />)
    expect(await screen.findByDisplayValue('Draft kept across tabs')).toBeInTheDocument()
  })

  it('always expands results when the editor is closed, even with an old collapsed session', async () => {
    sessionStorage.clear()
    sessionStorage.setItem('shellhound:hunt-workbench:case-collapsed', JSON.stringify({
      resultCollapsed: true,
    }))
    history.replaceState(null, '', '/?case=case-collapsed&view=hunt')
    mocks()
    renderWithProviders(<Hunt slug="case-collapsed" gotoView={vi.fn()} />)

    expect(await screen.findByText('No audited test selected')).toBeInTheDocument()
    expect(await screen.findByText('Selected rule')).toBeInTheDocument()
    expect(screen.getByText('The request matches the selected path.')).toBeInTheDocument()
    expect(screen.queryByTitle('Hits and evidence')).not.toBeInTheDocument()
  })
})
