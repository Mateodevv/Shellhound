import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, del, patch, post, type HuntBatch, type HuntPattern, type HuntRuleV2, type HuntTest } from '../api'
import { renderWithProviders } from '../test/setup'
import { Hunt } from './Hunt'
import { DEFAULT_SESSION, emptyDraft, patternDraft, saveSession } from './hunt/state'

vi.mock('../api', async (original) => ({ ...(await original<typeof import('../api')>()),
  api: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }))

const RULE: HuntRuleV2 = { client_match: 'any', requests: [{ clauses: [
  { field: 'uri', operator: 'equals', values: ['/training-marker'] },
] }] }
const PATTERN: HuntPattern = {
  id: 'sample', patterns: ['/training-marker'], match: 'any', request: { methods: [], user_agents: [] },
  name: 'Training marker', cve: '', description: 'Requests for the training marker.', added: '2026-01-01',
  source: 'own', enabled: true, rule: RULE, rule_hash: 'rule-hash',
  dsl: 'client any\nrequest\n  uri equals ["/training-marker"]\nend', technology: 'generic', version: 1,
  archived: false, own_enabled: true, created_at: '2026-01-01', updated_at: '2026-01-01', derived_from: null,
}
const TEST: HuntTest = { id: 41, pattern_id: PATTERN.id, pattern_version: 1, rule_hash: PATTERN.rule_hash,
  rule: RULE, dsl: PATTERN.dsl, tested_at: '2026-09-08T10:00:00', index_fingerprint: 'index-1',
  hits: 3, clients: 1, ok_hits: 2, first_epoch: 1_700_000_000, last_epoch: 1_700_000_060,
  tz: 0, coverage: { requests: 30, fields: {} }, batch_id: 'run-1' }
const RUN: HuntBatch = { batch_id: 'run-1', job_id: 7, state: 'done', created: '2026-09-08T10:00:00',
  started: '2026-09-08T10:00:00', finished: '2026-09-08T10:00:01', progress: 1,
  index_fingerprint: 'index-1', fresh: true, roster_known: true,
  counts: { total: 1, checked: 1, matched: 1, failed: 0, remaining: 0 },
  patterns: [{ id: PATTERN.id, name: PATTERN.name, cve: '', description: PATTERN.description,
    technology: 'generic', version: 1, rule_hash: PATTERN.rule_hash, status: 'done', error: '', test: TEST }], error: '' }
const CLUSTER = { cluster_key: 'group-1', client: '203.0.113.42', method: 'GET', uri_pattern: '/training-marker',
  status_class: '2xx', requests: 2, ok_hits: 2, first_epoch: TEST.first_epoch, last_epoch: TEST.last_epoch,
  tz: 0, request_id: 7, example_uri: '/training-marker' }
let allRuns: HuntBatch[]
let applied: unknown
let paginateGroups = false
function mocks() {
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/patterns') return { patterns: [PATTERN], path: 'patterns.json' }
    if (/\/api\/cases\/[^/]+$/.test(path)) return { evidence_items: [{ id: 1, kind: 'access_logs', scanned_at: '2026-09-08' }],
      log_index: { exists: true, fresh: true, lines: 30, clients: 1 } }
    if (path.endsWith('/dashboard')) return { logs: null }
    if (path.endsWith('/jobs')) return []
    if (path.includes('/hunt/tests?')) return { tests: [TEST] }
    if (path.endsWith('/hunt/batch-tests')) return { runs: allRuns }
    if (path.includes('/hunt/batch-tests/')) return allRuns.find((r) => path.endsWith(r.batch_id))
    if (path.endsWith('/versions')) return { versions: [] }
    throw new Error(`Unexpected API call: ${path}`)
  })
  vi.mocked(post).mockImplementation(async (path, body) => {
    if (path.endsWith('/batch-tests')) {
      const batchId = `run-${allRuns.length + 1}`
      allRuns = [{ ...RUN, batch_id: batchId, job_id: allRuns.length + 7 }, ...allRuns]
      return { job_id: allRuns[0].job_id, batch_id: batchId, patterns: 1 }
    }
    if (path.endsWith('/clients')) return { clients: [{ ...CLUSTER }], total: 1, next_cursor: null }
    if (path.endsWith('/clusters')) {
      const next = (body as { cursor: string }).cursor === 'page-2'
      return { clusters: [{ ...CLUSTER, cluster_key: next ? 'group-2' : 'group-1', uri_pattern: next ? '/second-marker' : CLUSTER.uri_pattern }],
        total: paginateGroups ? 51 : 1, next_cursor: paginateGroups && !next ? 'page-2' : null }
    }
    if (path.endsWith('/hunt/tests')) return { test: { ...TEST, batch_id: '' }, result: {} }
    if (path.endsWith('/apply')) { applied = body; return { findings: 1, already_applied: false } }
    throw new Error(`Unexpected POST call: ${path}`)
  })
  vi.mocked(patch).mockResolvedValue(PATTERN)
  vi.mocked(del).mockResolvedValue({})
}

beforeEach(() => {
  vi.clearAllMocks(); sessionStorage.clear(); history.replaceState(null, '', '/?case=case-1&view=hunt')
  allRuns = [structuredClone(RUN)]; applied = undefined; paginateGroups = false; mocks()
})

describe('Pattern Hunt investigation workflow', () => {
  it('opens IOC query evidence without replacing the saved editor draft', async () => {
    saveSession('case-1', { ...DEFAULT_SESSION, draft: emptyDraft({ name: 'Keep my draft' }) })
    history.replaceState(null, '', '/?case=case-1&view=hunt&section=41')
    const original = vi.mocked(api).getMockImplementation()!
    vi.mocked(api).mockImplementation(async path => path.endsWith('/hunt/tests?limit=500') ? { tests: [] } : original(path))
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByText('Saved query #41')).toBeVisible()
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case-1/hunt/tests/41/clients', expect.anything()))
    expect(vi.mocked(post).mock.calls.some(([path]) => /\/(apply|batch-tests|tests)$/.test(path))).toBe(false)
    expect(new URLSearchParams(location.search).get('section')).toBe('41')
    fireEvent.click(screen.getAllByRole('button', { name: 'Back to Pattern Hunt' })[0])
    fireEvent.click(await screen.findByRole('button', { name: 'Resume draft' }))
    expect(await screen.findByDisplayValue('Keep my draft')).toBeVisible()
  })

  it('passes explicit draft CVE metadata when previewing a query', async () => {
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Open pattern library' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    fireEvent.change(await screen.findByPlaceholderText('CVE-…'), { target: { value: 'CVE-2026-12345' } })
    fireEvent.click(screen.getByRole('button', { name: 'Preview in this case' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case-1/hunt/tests', expect.objectContaining({ name: PATTERN.name, cve: 'CVE-2026-12345' })))
  })

  it('opens the dashboard-linked run instead of the saved selection and preserves the draft', async () => {
    allRuns = [{ ...RUN, batch_id: 'newer-run' }, RUN]
    saveSession('case-1', { ...DEFAULT_SESSION, batchId: 'newer-run', runPatternId: 'sample',
      draft: emptyDraft({ name: 'Keep my unsaved investigation' }), page: 'editor' })
    history.replaceState(null, '', '/?case=case-1&view=hunt&section=runs&batch=run-1')
    const mounted = renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByRole('button', { name: 'Inspect matches' })).toBeEnabled()
    expect(screen.getByRole('combobox', { name: 'Run' })).toHaveValue('run-1')
    fireEvent.click(screen.getByRole('button', { name: 'Inspect matches' }))
    await waitFor(() => expect(new URLSearchParams(location.search).get('pattern')).toBe('sample'))
    mounted.unmount()
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByRole('button', { name: 'Back to run overview' })).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: 'Back to Pattern Hunt' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Resume draft' }))
    expect(await screen.findByDisplayValue('Keep my unsaved investigation')).toBeVisible()
    expect(vi.mocked(post).mock.calls.some(([path]) => /\/(apply|batch-tests|tests)$/.test(path))).toBe(false)
  })

  it('keeps both summaries visible when a check starts and opens details explicitly', async () => {
    allRuns = []
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    const summary = await screen.findByRole('region', { name: 'Pattern check' })
    const start = await within(summary).findByRole('button', { name: 'Check all patterns (1)' })
    await waitFor(() => expect(start).toBeEnabled())
    expect(screen.getByRole('region', { name: 'Pattern library' })).toBeInTheDocument()
    fireEvent.click(start)
    const details = await within(summary).findByRole('button', { name: 'View full results' })
    expect(screen.getByRole('region', { name: 'Pattern library' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Inspect matches' })).not.toBeInTheDocument()
    fireEvent.click(details)
    expect(await screen.findByRole('button', { name: 'Inspect matches' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Back to Pattern Hunt' }))
    expect(await screen.findByRole('region', { name: 'Pattern library' })).toBeInTheDocument()
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('opens the overview on a sidebar visit while keeping the selected run and draft', async () => {
    const first = renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Open pattern library' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    fireEvent.change(await screen.findByDisplayValue(PATTERN.name), { target: { value: 'Keep this draft' } })
    first.unmount()
    history.replaceState(null, '', '/?case=case-1&view=hunt')
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByRole('region', { name: 'Pattern library' })).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Resume draft' }))
    expect(await screen.findByDisplayValue('Keep this draft')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })

  it('opens full results from the match summary and omits a finished remaining count', async () => {
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    const summary = await screen.findByRole('button', { name: 'Matches worth a closer look' })
    expect(screen.queryByText('Remaining')).not.toBeInTheDocument()
    fireEvent.click(summary)
    expect(await screen.findByRole('button', { name: 'Inspect matches' })).toBeEnabled()
    expect(screen.queryByText('Remaining')).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })

  it('explains missing indexing beside the start action and still allows managing patterns', async () => {
    allRuns = []
    const original = vi.mocked(api).getMockImplementation()!
    vi.mocked(api).mockImplementation((path) => /\/api\/cases\/[^/]+$/.test(path)
      ? Promise.resolve({ evidence_items: [{ kind: 'access_logs' }], log_index: { exists: false, fresh: false } }) : original(path))
    const gotoView = vi.fn()
    renderWithProviders(<Hunt slug="case-1" gotoView={gotoView} />)
    const start = await screen.findByRole('button', { name: 'Check all patterns (1)' })
    expect(start).toBeDisabled()
    fireEvent.click(await screen.findByRole('button', { name: 'View analysis' }))
    expect(gotoView).toHaveBeenCalledWith('evidence')
    fireEvent.click(screen.getByRole('button', { name: 'Open pattern library' }))
    expect(await screen.findByRole('button', { name: 'Add a pattern' })).toBeEnabled()
    expect(post).not.toHaveBeenCalled()
  })

  it.each(['running', 'cancelled', 'failed'] as const)('preserves partial results and the library for a %s check', async (state) => {
    allRuns[0] = { ...RUN, state, progress: 0.5, counts: { total: 2, checked: 1, matched: 1, failed: state === 'failed' ? 1 : 0, remaining: 1 } }
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByRole('button', { name: 'View full results' })).toBeEnabled()
    expect(screen.getByRole('region', { name: 'Pattern library' })).toBeInTheDocument()
    expect(screen.queryByText('Check complete')).not.toBeInTheDocument()
    if (state === 'running') {
      expect(screen.getByText('Remaining')).toBeInTheDocument()
      expect(screen.getByRole('progressbar')).toHaveAttribute('value', '0.5')
      expect(screen.getByRole('button', { name: 'Stop check' })).toBeEnabled()
    } else expect(screen.getByText('Not checked')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })

  it('starts all or one enabled pattern explicitly without adding findings', async () => {
    allRuns = []
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    const checkAll = await screen.findByRole('button', { name: 'Check all patterns (1)' })
    await waitFor(() => expect(checkAll).toBeEnabled())
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(checkAll)
    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) => path.endsWith('/batch-tests') && JSON.stringify(body) === '{}')).toBe(true))
    fireEvent.click(screen.getByRole('button', { name: 'Open pattern library' }))
    const single = await screen.findByRole('button', { name: /Check this pattern/ })
    fireEvent.click(single)
    await waitFor(() => expect(vi.mocked(post).mock.calls.some(([path, body]) => path.endsWith('/batch-tests') && (body as { ids?: string[] }).ids?.join() === PATTERN.id)).toBe(true))
    expect(applied).toBeUndefined()
  })

  it('adds only the current page selection and clears it when changing pages', async () => {
    paginateGroups = true
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'View full results' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect matches' }))
    fireEvent.click(await screen.findByRole('button', { name: CLUSTER.client }))
    await screen.findByLabelText('Select GET /training-marker 2xx')
    fireEvent.click(screen.getByLabelText('Select this page'))
    expect(screen.getByRole('button', { name: 'Add selected to Findings (1)' })).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await screen.findByText('/second-marker')
    expect(screen.getByRole('button', { name: 'Add selected to Findings (0)' })).toBeDisabled()
    fireEvent.click(screen.getByLabelText('Select GET /second-marker 2xx'))
    fireEvent.click(screen.getByRole('button', { name: 'Add selected to Findings (1)' }))
    await waitFor(() => expect(applied).toEqual({ cluster_keys: ['group-2'], pattern_id: PATTERN.id, expected_version: 1 }))
  })

  it('restores a selected historical run without mixing in newer pattern results', async () => {
    const old = { ...structuredClone(RUN), batch_id: 'older', created: '2026-09-07T10:00:00' }
    old.patterns[0].name = 'Earlier pattern name'; old.patterns[0].test!.hits = 1
    allRuns.push(old)
    const first = renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'View full results' }))
    fireEvent.change(await screen.findByRole('combobox', { name: 'Run' }), { target: { value: 'older' } })
    await screen.findByText('Earlier pattern name')
    first.unmount()
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByText('Earlier pattern name')).toBeInTheDocument()
    expect(screen.queryByText('Training marker')).not.toBeInTheDocument()
  })

  it('shows stale historical counts while blocking evidence inspection', async () => {
    allRuns[0].fresh = false
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'View full results' }))
    expect(await screen.findByRole('button', { name: 'Inspect matches' })).toBeDisabled()
    expect(screen.getByText(/These are historical counts/)).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })

  it('preserves an edited draft across navigation and refresh without searching', async () => {
    const first = renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Open pattern library' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    fireEvent.change(await screen.findByDisplayValue(PATTERN.name), { target: { value: 'Unsaved investigator note' } })
    fireEvent.click(screen.getByRole('button', { name: 'Back to Pattern Hunt' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Resume draft' }))
    expect(await screen.findByDisplayValue('Unsaved investigator note')).toBeInTheDocument()
    first.unmount()
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByDisplayValue('Unsaved investigator note')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })

  it.each(['preview', 'save'])('keeps newer draft edits when a delayed %s finishes', async (operation) => {
    let finish!: (result: unknown) => void
    const response = new Promise((resolve) => { finish = resolve })
    const originalPost = vi.mocked(post).getMockImplementation()!
    if (operation === 'preview') vi.mocked(post).mockImplementation((path, body) => path.endsWith('/hunt/tests') ? response : originalPost(path, body))
    else vi.mocked(patch).mockReturnValue(response)
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Open pattern library' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    fireEvent.change(await screen.findByDisplayValue(PATTERN.name), { target: { value: 'Submitted draft' } })
    fireEvent.click(screen.getByRole('button', { name: operation === 'preview' ? 'Preview in this case' : 'Save pattern' }))
    fireEvent.change(screen.getByDisplayValue('Submitted draft'), { target: { value: 'Newer unsaved draft' } })
    await act(async () => { finish(operation === 'preview' ? { test: TEST, result: {} } : { ...PATTERN, version: 2, name: 'Submitted draft' }); await response })
    expect(await screen.findByDisplayValue('Newer unsaved draft')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Back to editor' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save pattern' })).toBeEnabled()
    if (operation === 'save') {
      fireEvent.click(screen.getByRole('button', { name: 'Save pattern' }))
      await waitFor(() => expect(vi.mocked(patch).mock.calls.at(-1)?.[1]).toMatchObject({ expected_version: 2, name: 'Newer unsaved draft' }))
    }
  })

  it('does not leak a selected run or draft into another case', async () => {
    const view = renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Open pattern library' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Edit' }))
    fireEvent.change(await screen.findByDisplayValue(PATTERN.name), { target: { value: 'Case one draft' } })
    view.rerender(<Hunt slug="case-2" gotoView={vi.fn()} />)
    expect(await screen.findByRole('button', { name: 'View full results' })).toBeInTheDocument()
    expect(screen.queryByDisplayValue('Case one draft')).not.toBeInTheDocument()
  })

  it.each(['new', 'bundled'] as const)('keeps newer edits attached to the pattern created from a %s draft', async (source) => {
    const draft = source === 'new'
      ? emptyDraft({ name: 'Submitted pattern', rule: RULE, dsl: PATTERN.dsl })
      : { ...patternDraft({ ...PATTERN, source: 'bundled' }), name: 'Submitted pattern' }
    saveSession('case-1', { ...DEFAULT_SESSION, draft })
    history.replaceState(null, '', '/?case=case-1&view=hunt&section=editor')
    const saved = { ...PATTERN, id: 'created-pattern', name: draft.name }
    let finish!: (result: unknown) => void
    const response = new Promise((resolve) => { finish = resolve })
    const originalPost = vi.mocked(post).getMockImplementation()!
    vi.mocked(post).mockImplementation((path, body) =>
      path === '/api/patterns' || path === '/api/patterns/sample/clone' ? response : originalPost(path, body))
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: source === 'new' ? 'Save pattern' : 'Save as workspace pattern' }))
    if (source === 'bundled') {
      fireEvent.click(screen.getByRole('button', { name: 'Save own variant' }))
      fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    }
    fireEvent.change(screen.getByDisplayValue('Submitted pattern'), { target: { value: 'Newer investigator edits' } })
    await act(async () => { finish(source === 'new' ? { entry: saved } : saved); await response })
    expect(await screen.findByDisplayValue('Newer investigator edits')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save pattern' }))
    await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/patterns/created-pattern',
      expect.objectContaining({ expected_version: 1, name: 'Newer investigator edits' })))
    expect(vi.mocked(post).mock.calls.filter(([path]) => path === '/api/patterns' || path.endsWith('/clone'))).toHaveLength(1)
  })

  it('does not attach a delayed creation to a different new draft', async () => {
    saveSession('case-1', { ...DEFAULT_SESSION, draft: emptyDraft({ name: 'First draft', rule: RULE, dsl: PATTERN.dsl }) })
    history.replaceState(null, '', '/?case=case-1&view=hunt&section=editor')
    let finish!: (result: unknown) => void
    const response = new Promise((resolve) => { finish = resolve })
    const originalPost = vi.mocked(post).getMockImplementation()!
    vi.mocked(post).mockImplementation((path, body) => path === '/api/patterns' ? response : originalPost(path, body))
    renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'Save pattern' }))
    fireEvent.click(screen.getByRole('button', { name: 'Back to Pattern Hunt' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Add a pattern' }))
    fireEvent.click(screen.getByRole('button', { name: 'Discard draft and continue' }))
    fireEvent.change(await screen.findByRole('textbox', { name: 'Name' }), { target: { value: 'Separate draft' } })
    await act(async () => { finish({ entry: { ...PATTERN, id: 'created-pattern', name: 'First draft' } }); await response })
    expect(await screen.findByDisplayValue('Separate draft')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save pattern' }))
    await waitFor(() => expect(vi.mocked(post).mock.calls.filter(([path]) => path === '/api/patterns')).toHaveLength(2))
    expect(patch).not.toHaveBeenCalled()
  })

  it('hides cached request context when the saved search becomes stale', async () => {
    let stale = false
    const originalApi = vi.mocked(api).getMockImplementation()!
    const originalPost = vi.mocked(post).getMockImplementation()!
    vi.mocked(api).mockImplementation((path) => path.includes('/access/request/') ? Promise.resolve({
      request: { request_id: 7, client: CLUSTER.client, epoch: TEST.first_epoch, tz: 0, method: 'GET',
        uri: '/training-marker', status: 200, source: 'training-context.log', line_no: 2 }, before: [], after: [],
    }) : originalApi(path))
    vi.mocked(post).mockImplementation((path, body) => path.endsWith('/clusters') && stale
      ? Promise.reject(new Error('The log index changed. Run this check again.')) : originalPost(path, body))
    const { qc } = renderWithProviders(<Hunt slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: 'View full results' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect matches' }))
    fireEvent.click(await screen.findByRole('button', { name: CLUSTER.client }))
    fireEvent.click(await screen.findByRole('button', { name: 'Inspect first request' }))
    expect(await screen.findByRole('button', { name: 'Activity after this request' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Request and surrounding activity' })).toHaveFocus()
    stale = true
    await act(async () => { await qc.invalidateQueries({ queryKey: ['hunt-clusters', 'case-1'] }) })
    expect(await screen.findByRole('alert')).toHaveTextContent('The log index changed')
    expect(screen.queryByRole('heading', { name: 'Request and surrounding activity' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Activity after this request' })).not.toBeInTheDocument()
  })
})
