import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, post, del, type Ioc } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { IocField } from './IocField'
import { IocDetails } from './IocDetails'
import { IocEditDialog } from './IocEditDialog'
import { iocOrigins } from './iocPresentation'

vi.mock('../../api', async orig => ({ ...(await orig<typeof import('../../api')>()), api: vi.fn(), post: vi.fn(), del: vi.fn(), patch: vi.fn() }))
vi.mock('../../geo', () => ({ useGeo: () => ({ iso: 'de', name: 'Germany', special: false }) }))
vi.mock('../../flags', () => ({ useFlagUrl: () => '/flags/de.svg' }))
const ip: Ioc = { id: 1, type: 'ip', value: '198.51.100.9', note: '', origin: 'Test source', tags: [],
  added: '', first_seen: null, last_seen: null, links: [], assessment: 'unassessed' }
const cve: Ioc = { ...ip, id: 2, type: 'vulnerability', value: 'CVE-2026-12345' }
const detail = { object: ip, observations: [{ id: 'obs-1', kind: 'http-request', source_ref: 'access-log-1', path: '/sample.txt',
  local_path: 'C:/evidence/raw.log', finding_id: null, evidence_id: 1, count: 5, first_seen: '', last_seen: '', detail: 'Five requests', active: true }],
  sources: [], findings: [], assessments: [], relationships: [],
  relationship_types: { 'exploit-attempt': { sources: ['ip'], targets: ['vulnerability'] },
    executed: { sources: ['ip'], targets: ['file'] } } }

beforeEach(() => {
  vi.mocked(api).mockImplementation(async url => url === '/api/opencti/settings' ? { configured: true } : url.endsWith('/detail') ? detail : { lookups: [] })
  vi.mocked(post).mockResolvedValue({})
  vi.clearAllMocks()
})
const show = () => renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip, cve]} onClose={() => {}} />)

describe('Structured IOC details', () => {
  it('keeps its original edit baseline when the object refreshes and retains a conflicted draft', async () => {
    const initial = { ...ip, type: 'path', value: 'example.test', note: 'original', tags: ['old'] }
    const onClose = vi.fn()
    vi.mocked(post).mockRejectedValueOnce(new Error('This IOC changed. Reopen the editor to load its current values.'))
    const { rerender } = renderWithProviders(<IocEditDialog slug="synthetic" object={initial} onClose={onClose} />)
    fireEvent.change(screen.getByLabelText('Type'), { target: { value: 'domain' } })
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: 'draft' } })
    fireEvent.change(screen.getByLabelText(/Tags/), { target: { value: 'new' } })
    fireEvent.change(screen.getByLabelText('Reason for correction'), { target: { value: 'Correction' } })
    rerender(<IocEditDialog slug="synthetic" object={{ ...initial, type: 'other', value: 'updated', note: 'changed', assessment: 'benign', tags: ['remote'] }} onClose={onClose} />)
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/iocs/1/edit', expect.objectContaining({
      expected_type: 'path', expected_value: 'example.test', expected_note: 'original', expected_assessment: 'unassessed',
      type: 'domain', note: 'draft', add_tags: ['new'], remove_tags: ['old'],
    })))
    expect(await screen.findByRole('alert')).toHaveTextContent('This IOC changed')
    expect(screen.getByLabelText('Note')).toHaveValue('draft')
    expect(screen.getByLabelText('Type')).toHaveValue('domain')
    expect(onClose).not.toHaveBeenCalled()
  })
  it('shows copy reuse and incomplete-index feedback after an explicit hash assessment', async () => {
    const hash = { ...ip, type: 'hash', value: 'a'.repeat(64) }
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: hash } : { configured: false, lookups: [] })
    vi.mocked(post).mockResolvedValue({ content_assessment: { applied: ['/synthetic/copy.txt'], conflicts: [], incomplete: true } })
    const { qc } = renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[hash]} onClose={() => {}} embedded />)
    qc.setQueryData(['findings', 'synthetic'], { seeded: true })
    fireEvent.click(await screen.findByRole('button', { name: 'IOC actions' }))
    fireEvent.click(screen.getByRole('button', { name: 'Edit IOC' }))
    fireEvent.change(screen.getByRole('combobox', { name: 'Assessment' }), { target: { value: 'benign' } })
    fireEvent.change(screen.getByRole('textbox', { name: /Reason/ }), { target: { value: 'Harmless synthetic content' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Applied to 1 verified identical copy.')).toBeInTheDocument()
    expect(screen.getByText(/The content index is incomplete/)).toBeInTheDocument()
    expect(qc.getQueryState(['findings', 'synthetic'])?.isInvalidated).toBe(true)
  })

  it('confirms individual deletion, retains the IOC on failure and closes only after success', async () => {
    const onDeleted = vi.fn()
    vi.mocked(del).mockRejectedValueOnce(new Error('Database unavailable')).mockResolvedValueOnce({ deleted_ids: [ip.id] })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip]} onClose={() => {}} onDeleted={onDeleted} embedded />)
    fireEvent.click(await screen.findByRole('button', { name: 'IOC actions' }))
    fireEvent.click(screen.getByRole('button', { name: 'Delete IOC' }))
    expect(del).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(del).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'IOC actions' }))
    fireEvent.click(screen.getByRole('button', { name: 'Delete IOC' }))
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Database unavailable')
    expect(onDeleted).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(onDeleted).toHaveBeenCalledWith([ip.id]))
    expect(del).toHaveBeenLastCalledWith('/api/cases/synthetic/iocs/1')
  })

  it('opens recorded file content on click even without OpenCTI and ignores unrelated source paths', async () => {
    const file = { ...ip, type: 'file', value: 'sample.txt' }
    const path = 'C:/synthetic/evidence/sample.txt'
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: file,
      observations: [detail.observations[0], { ...detail.observations[0], id: 'location', kind: 'file-location', local_path: path, path: 'sample.txt' }] }
      : url.includes('/file?') ? { mode: 'raw', size: 6, window: 262144, offset: 0, length: 6, eof: true, lines: ['sample'], from_line: 1 }
      : { configured: false })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[file]} onClose={() => {}} embedded />)
    const button = await screen.findByRole('tab', { name: 'Content' })
    expect(vi.mocked(api).mock.calls.some(([url]) => url.includes('/file?'))).toBe(false)
    fireEvent.click(button)
    expect(await screen.findByText('sample')).toBeVisible()
    expect(api).toHaveBeenCalledWith(`/api/cases/synthetic/file?path=${encodeURIComponent(path)}&mode=raw&offset=0`)
    expect(post).not.toHaveBeenCalled()
  })

  it('requires a choice between file locations and excludes withdrawn observations', async () => {
    const file = { ...ip, type: 'file', value: 'sample.txt' }
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: file,
      observations: [1, 2, 3].map(n => ({ ...detail.observations[0], id: `location-${n}`, kind: 'file-location',
        local_path: `C:/synthetic/source-${n}/sample.txt`, path: `source-${n}/sample.txt`, evidence_id: n, active: n < 3 })) }
      : url.includes('/file?') ? { mode: 'raw', size: 6, window: 262144, offset: 0, length: 6, eof: true, lines: ['sample'], from_line: 1 }
      : { configured: false })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[file]} onClose={() => {}} embedded />)
    fireEvent.click(await screen.findByRole('tab', { name: 'Content' }))
    expect(await screen.findByText('Choose evidence location')).toBeVisible()
    expect(screen.queryByRole('button', { name: /source-3/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /source-2\/sample.txt/ }))
    expect(await screen.findByText('sample')).toBeVisible()
    expect(api).toHaveBeenCalledWith('/api/cases/synthetic/file?path=C%3A%2Fsynthetic%2Fsource-2%2Fsample.txt&mode=raw&offset=0')
  })

  it('offers an embedded trace tab for the selected IP without requiring OpenCTI', async () => {
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? detail : { configured: false })
    vi.mocked(post).mockImplementation(async url => url.endsWith('/timeline') ? { timeline: [] } : { total: 0, methods: [], rows: [] })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip]} onClose={() => {}} embedded />)
    const button = await screen.findByRole('tab', { name: 'Trace' })
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(button)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/trace', expect.objectContaining({ ips: [ip.value] })))
  })

  it('does not load unavailable file content and passes domain searches to access logs', async () => {
    const file = { ...ip, type: 'file', value: 'sample.txt' }
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: file } : { configured: false })
    const view = renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[file]} onClose={() => {}} embedded />)
    fireEvent.click(await screen.findByRole('tab', { name: 'Content' }))
    expect(vi.mocked(api).mock.calls.some(([url]) => url.includes('/file?'))).toBe(false)
    view.unmount()
    const domain = { ...ip, type: 'domain', value: 'example.test' }
    const navigate = vi.fn()
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: domain } : { configured: false })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[domain]} gotoView={navigate} onClose={() => {}} embedded />)
    fireEvent.click(await screen.findByRole('button', { name: 'Search access logs' }))
    expect(navigate).toHaveBeenCalledWith('logs', { search: domain.value })
  })

  it('keeps scan dates out of object activity and uses only active request evidence', async () => {
    const domain = { ...ip, type: 'domain', value: 'example.test', first_seen: '2026-09-09', last_seen: '2026-09-09' }
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: domain, observations: [
      { ...detail.observations[0], kind: 'finding', first_seen: '2026-09-09', last_seen: '2026-09-09' },
      { ...detail.observations[0], id: 'withdrawn', active: false, first_seen: '2020-01-01', last_seen: '2020-01-01' },
    ] } : { configured: false })
    const view = renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[domain]} onClose={() => {}} />)
    await screen.findByText('DNS name')
    expect(screen.queryByText('First observed')).not.toBeInTheDocument()
    expect(screen.queryByText('2026-09-09')).not.toBeInTheDocument()
    view.unmount()
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: domain, observations: [
      { ...detail.observations[0], first_seen: '2026-06-01', last_seen: '2026-06-02' },
    ] } : { configured: false })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[domain]} onClose={() => {}} />)
    expect(await screen.findByText('2026-06-01')).toBeVisible()
    expect(screen.getByText('2026-06-02')).toBeVisible()
    expect(post).not.toHaveBeenCalled()
  })
  it('shows database registration attributes with their sources instead of observation dates', async () => {
    const user = { ...ip, type: 'user', value: 'account-test', account_sources: [
      { source_key: 'one', cms: 'joomla', table: 'cms_users', registered: '2024-01-02 03:04:05' },
      { source_key: 'two', cms: 'wordpress', table: 'wp_users', registered: '' },
    ] }
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: user } : { configured: false })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[user]} onClose={() => {}} />)
    expect(await screen.findByText('Registered')).toBeVisible()
    expect(screen.getByText('2024-01-02 03:04:05')).toBeVisible()
    expect(screen.getByText('joomla · cms_users')).toBeVisible()
    expect(screen.getByText('Not recorded in the database')).toBeVisible()
    expect(screen.queryByText('First observed')).not.toBeInTheDocument()
    expect(screen.queryByText('Last observed')).not.toBeInTheDocument()
  })
  it('loads Trace through its button and scopes requests to the selected IP', async () => {
    vi.mocked(post).mockImplementation(async url => url.endsWith('/timeline') ? { timeline: [] } : { total: 1, methods: ['GET'], rows: [
      { client: ip.value, epoch: 1, tz: 0, method: 'GET', uri: '/documentation', status: 200, agent: 'Synthetic browser' },
    ] })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip, cve]} onClose={() => {}} embedded />)
    const trace = await screen.findByRole('tab', { name: 'Trace' })
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(trace)
    expect(await screen.findByText('/documentation')).toBeVisible()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Trace' })).toBeVisible()
    expect(post).toHaveBeenCalledWith('/api/cases/synthetic/trace', expect.objectContaining({ ips: [ip.value], offset: 0 }))
    fireEvent.change(screen.getByPlaceholderText('URI or user agent…'), { target: { value: 'documentation' } })
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/trace', expect.objectContaining({ ips: [ip.value], search: 'documentation' })))
    expect(vi.mocked(post).mock.calls.every(([url]) => url.startsWith('/api/cases/synthetic/trace'))).toBe(true)
  })

  it('falls back to Overview for a non-IP opened with a saved Trace tab', async () => {
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: cve } : { lookups: [] })
    renderWithProviders(<IocDetails slug="synthetic" id={2} iocs={[ip, cve]} tab="Trace" onClose={() => {}} embedded />)
    await screen.findByRole('heading', { name: cve.value })
    expect(screen.queryByRole('tab', { name: 'Trace' })).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
    expect(post).not.toHaveBeenCalled()
  })

  it('explains the field with a descriptive tooltip on keyboard focus', async () => {
    const { container } = renderWithProviders(<IocField name="Origin">Pattern Hunt</IocField>)
    fireEvent.focus(container.querySelector('[tabindex="0"]')!)
    const tooltip = await screen.findByRole('tooltip')
    expect(tooltip).toHaveTextContent('The analysis, hunt or analyst action that added this object to the case.')
    expect(tooltip.children).toHaveLength(1)
  })

  it('loads local detail without starting enrichment or transfers', async () => {
    show()
    await screen.findByRole('heading', { name: ip.value })
    expect(post).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Save assessment' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('tab').map(tab => tab.textContent)).toEqual(['Overview', 'Trace'])
    expect(post).not.toHaveBeenCalled()
  })

  it('shows the country and historical rule names as plain origin text', async () => {
    const observation = { ...detail.observations[0], kind: 'pattern-hunt',
      detail: 'Saved rule; variant A; CVE metadata: CVE-2026-12345; 5 matching requests' }
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail')
      ? { ...detail, observations: [observation, { ...observation, id: 'obs-2' },
        { ...observation, id: 'obs-3', detail: 'Other rule; CVE metadata: CVE-2026-12346' },
        { ...observation, id: 'obs-4', active: false, detail: 'Withdrawn rule; CVE metadata: CVE-2026-12347' }] }
      : { lookups: [] })
    show()
    expect(await screen.findByLabelText('Germany')).toHaveAttribute('src', '/flags/de.svg')
    const origin = await screen.findByText('Pattern Hunt: Saved rule; variant A')
    expect(origin.closest('button, a')).toBeNull()
    expect(screen.getAllByText('Pattern Hunt: Saved rule; variant A')).toHaveLength(1)
    expect(screen.getByText('Pattern Hunt: Other rule')).toBeInTheDocument()
    expect(screen.queryByText('Pattern Hunt: Withdrawn rule')).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })

  it('uses finding names and an analyst origin when no hunt evidence exists', () => {
    expect(iocOrigins(ip, [{ ...detail.observations[0], finding_id: 12 }],
      [{ id: 12, rule: 'Synthetic finding', triage: 'new' }])).toEqual(['Finding: Synthetic finding'])
    expect(iocOrigins(ip, [], [])).toEqual(['Test source'])
    expect(iocOrigins({ ...ip, origin: '' }, [], [])).toEqual(['Analyst'])
    expect(iocOrigins(ip, [{ ...detail.observations[0], kind: 'pattern-hunt' }], [])).toEqual(['Pattern Hunt'])
  })

  it('cancels an assessment draft without submitting it', async () => {
    show()
    vi.spyOn(window, 'confirm').mockReturnValueOnce(true)
    fireEvent.click(await screen.findByRole('button', { name: 'IOC actions' }))
    fireEvent.click(screen.getByRole('button', { name: 'Edit IOC' }))
    fireEvent.change(screen.getByLabelText('Assessment'), { target: { value: 'suspicious' } })
    fireEvent.change(screen.getByLabelText('Reason for correction'), { target: { value: 'Unfinished assessment' } })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(post).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Save assessment' })).not.toBeInTheDocument()
  })

  it('saves value, note and assessment together through Edit IOC', async () => {
    show()
    await screen.findByRole('heading', { name: ip.value })
    fireEvent.click(screen.getByRole('button', { name: 'IOC actions' }))
    fireEvent.click(screen.getByRole('button', { name: 'Edit IOC' }))
    fireEvent.change(screen.getByLabelText('Value'), { target: { value: '192.0.2.8' } })
    fireEvent.change(screen.getByLabelText('Note'), { target: { value: 'Reviewed IOC' } })
    fireEvent.change(screen.getByLabelText('Assessment'), { target: { value: 'suspicious' } })
    fireEvent.change(screen.getByLabelText('Reason for correction'), { target: { value: 'Hostile request in log line 5' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/iocs/1/edit', expect.objectContaining({
      value: '192.0.2.8', note: 'Reviewed IOC', assessment: 'suspicious', reason: 'Hostile request in log line 5', expected_value: ip.value,
    })))
  })

  it.each(['Evidence', 'Relationships', 'OpenCTI'])('opens Overview for the removed %s tab', async tab => {
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip]} tab={tab} onClose={() => {}} embedded />)
    await screen.findByRole('heading', { name: ip.value })
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByRole('tab', { name: tab })).not.toBeInTheDocument()
  })

  it('adds and removes tags with local deltas', async () => {
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: { ...ip, tags: ['IOC'] } } : { lookups: [] })
    show()
    fireEvent.click(await screen.findByRole('button', { name: 'Add tag' }))
    fireEvent.change(screen.getByLabelText('Tag name'), { target: { value: 'true positive' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/iocs/1/tags', { add: ['true positive'] }))
    fireEvent.click(await screen.findByRole('button', { name: 'Remove tag IOC' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/iocs/1/tags', { remove: ['IOC'] }))
  })

  it('shows saved OpenCTI tags without a manual import step or display-time mutation', async () => {
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail')
      ? { ...detail, object: { ...ip, tags: ['IOC', 'scanner'] } } : { lookups: [] })
    show()
    expect(await screen.findByRole('button', { name: 'Remove tag scanner' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Import from OpenCTI' })).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })

  it('shows directed relationships with explanatory tooltips in a three-column table', async () => {
    const navigate = vi.fn()
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, relationships: [{
      id: 4, src: 1, dst: 2, kind: 'exploit-attempt', origin: 'manual', active: true, events: [],
      evidence: [{ id: 'e1', reference: 'Log line 5', detail: 'Synthetic evidence', first_seen: '', last_seen: '2026-09-08T12:00:00' }],
    }] } : { lookups: [] })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip, cve]} onClose={() => {}} onNavigate={navigate} />)
    expect(await screen.findByRole('columnheader', { name: 'Relationship' })).toBeInTheDocument()
    expect(screen.getByText('Exploitation attempt')).toBeInTheDocument()
    expect(screen.getByLabelText('Outgoing relationship')).toBeInTheDocument()
    expect(screen.queryByText('Synthetic evidence')).not.toBeInTheDocument()
    expect(screen.queryByText('Assessment history')).not.toBeInTheDocument()
    expect(screen.queryByText('OpenCTI match')).not.toBeInTheDocument()
    expect(screen.getAllByRole('columnheader').map(cell => cell.textContent)).toEqual(['Relationship', 'Type', 'Object'])
    expect(screen.queryByRole('button', { name: /Relationship details/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /View all/ })).not.toBeInTheDocument()
    fireEvent.focus(screen.getByRole('table').querySelector('[tabindex="0"]')!)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Evidence records an attempt to exploit the linked vulnerability.')
    fireEvent.click(screen.getByRole('button', { name: 'CVE-2026-12345' }))
    expect(navigate).toHaveBeenCalledWith(2)
  })

})

it('does not revive cached OpenCTI scores or lookup actions', async () => {
  vi.mocked(api).mockImplementation(async url => url === '/api/opencti/settings' ? { configured: true } : url.endsWith('/detail') ? detail : { lookups: [{ ioc_id: 1, entities: [{ score: 58 }] }] })
  show()
  await screen.findByRole('heading', { name: ip.value })
  expect(screen.getByText('Unassessed')).toBeVisible()
  expect(screen.queryByText('58 / 100')).not.toBeInTheDocument()
  expect(screen.queryByRole('tab', { name: 'Enrichment' })).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})
