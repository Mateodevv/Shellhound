import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, post, del, type Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { IocField } from './IocField'
import { IocDetails } from './IocDetails'
import { iocOrigins } from './iocPresentation'

vi.mock('../api', async orig => ({ ...(await orig<typeof import('../api')>()), api: vi.fn(), post: vi.fn(), del: vi.fn(), patch: vi.fn() }))
vi.mock('../geo', () => ({ useGeo: () => ({ iso: 'de', name: 'Germany', special: false }) }))
vi.mock('../flags', () => ({ useFlagUrl: () => '/flags/de.svg' }))
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
    const button = await screen.findByRole('button', { name: 'View file content' })
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
    fireEvent.click(await screen.findByRole('button', { name: 'View file content' }))
    expect(await screen.findByRole('dialog', { name: 'Choose evidence location' })).toBeVisible()
    expect(screen.queryByRole('button', { name: /source-3/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /source-2\/sample.txt/ }))
    expect(await screen.findByText('sample')).toBeVisible()
    expect(api).toHaveBeenCalledWith('/api/cases/synthetic/file?path=C%3A%2Fsynthetic%2Fsource-2%2Fsample.txt&mode=raw&offset=0')
  })

  it('offers a trace popup for the selected IP without requiring OpenCTI', async () => {
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? detail : { configured: false })
    vi.mocked(post).mockImplementation(async url => url.endsWith('/timeline') ? { timeline: [] } : { total: 0, methods: [], rows: [] })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip]} onClose={() => {}} embedded />)
    const button = await screen.findByRole('button', { name: 'Open trace' })
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(button)
    expect(await screen.findByRole('dialog')).toBeVisible()
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/trace', expect.objectContaining({ ips: [ip.value] })))
  })

  it('leaves unavailable file content disabled and passes domain searches to access logs', async () => {
    const file = { ...ip, type: 'file', value: 'sample.txt' }
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: file } : { configured: false })
    const view = renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[file]} onClose={() => {}} embedded />)
    expect(await screen.findByRole('button', { name: 'View file content' })).toBeDisabled()
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
    const trace = await screen.findByRole('button', { name: 'Open trace' })
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(trace)
    expect(await screen.findByText('/documentation')).toBeVisible()
    expect(screen.getByRole('dialog')).toBeVisible()
    expect(screen.queryByRole('tab', { name: 'Trace' })).not.toBeInTheDocument()
    expect(post).toHaveBeenCalledWith('/api/cases/synthetic/trace', expect.objectContaining({ ips: [ip.value], offset: 0 }))
    fireEvent.change(screen.getByPlaceholderText('URI or user agent…'), { target: { value: 'documentation' } })
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/trace', expect.objectContaining({ ips: [ip.value], search: 'documentation' })))
    expect(vi.mocked(post).mock.calls.every(([url]) => url.startsWith('/api/cases/synthetic/trace'))).toBe(true)
  })

  it.each(['ip', 'file', 'hash', 'domain', 'url', 'email', 'user', 'vulnerability'])('shows cached enrichment for %s without starting network work', async type => {
    const object = { ...ip, type, context: type === 'user' ? 'account-context' : '' }
    vi.mocked(api).mockImplementation(async url => url === '/api/opencti/settings' ? { configured: true }
      : url.endsWith('/detail') ? { ...detail, object } : { lookups: [{ ioc_id: 1, status: 'known', checked_at: '2026-09-10', stale: true,
        entities: [{ id: 'remote', type: type === 'vulnerability' ? 'Vulnerability' : 'IPv4-Addr', name: 'Remote result', description: 'Saved provider details', labels: ['provider-tag'], sources: [{ source_name: 'Example provider', url: 'https://example.test/report' }],
          x_opencti_epss_score: 0.025, x_opencti_epss_percentile: 0.8, x_opencti_cvss_base_score: 9.8 }] }] })
    renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[object]} onClose={() => {}} embedded />)
    fireEvent.click(await screen.findByRole('tab', { name: 'Enrichment' }))
    expect(screen.getByText('Saved provider details')).toBeVisible()
    expect(screen.getByText('Example provider')).toBeVisible()
    expect(screen.queryByRole('tab', { name: 'Trace' })).not.toBeInTheDocument()
    if (type === 'vulnerability') {
      expect(screen.getByText('2.50%')).toBeVisible()
      expect(screen.getByText('80.00%')).toBeVisible()
      expect(screen.getByText('9.8 / 10')).toBeVisible()
    }
    expect(post).not.toHaveBeenCalled()
  })

  it('falls back to Overview for a non-IP opened with a saved Trace tab', async () => {
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: cve } : { lookups: [] })
    renderWithProviders(<IocDetails slug="synthetic" id={2} iocs={[ip, cve]} tab="Trace" onClose={() => {}} embedded />)
    await screen.findByRole('heading', { name: cve.value })
    expect(screen.queryByRole('tab', { name: 'Trace' })).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
    expect(post).not.toHaveBeenCalled()
  })

  it('shows the cached OpenCTI score and explains it without changing the case assessment', async () => {
    vi.mocked(api).mockImplementation(async url => url === '/api/opencti/settings' ? { configured: true } : url.endsWith('/detail') ? detail : { lookups: [
      { ioc_id: 1, status: 'known', stale: true, checked_at: '2026-09-08 12:00 UTC', entities: [{ id: 'cti-ip', name: ip.value, score: 58 }] },
    ] })
    const { container } = show()
    expect(await screen.findByText('58 / 100')).toBeVisible()
    expect(screen.getByText('Unassessed')).toBeVisible()
    expect(screen.queryByText(/2026-09-08 12:00 UTC/)).not.toBeInTheDocument()
    const score = [...container.querySelectorAll('div')].find(el => el.textContent === 'Score')!
    fireEvent.focus(score.querySelector('[tabindex="0"]')!)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('Higher values indicate a stronger assessment of maliciousness.')
    expect(screen.getByRole('tooltip')).toHaveTextContent('2026-09-08 12:00 UTC')
    expect(post).not.toHaveBeenCalled()
  })

  it('uses identical editable tags and score badges in Overview and Enrichment', async () => {
    const object = { ...ip, tags: ['CVE-2026-12345', 'Provider tag', 'Manual tag'] }
    vi.mocked(api).mockImplementation(async url => url === '/api/opencti/settings' ? { configured: true }
      : url.endsWith('/detail') ? { ...detail, object } : { lookups: [{ ioc_id: 1, status: 'known', checked_at: '2026-09-11',
        entities: [{ id: 'remote', type: 'IPv4-Addr', name: ip.value, score: 58, labels: ['Provider tag'], sources: [] }] }] })
    const { container } = show()
    const badge = await screen.findByText('58 / 100')
    const overviewScore = badge.outerHTML
    const tags = () => [...container.querySelectorAll('.ioc-tag')].map(el => el.textContent).sort()
    const overviewTags = tags()
    expect(overviewTags).toEqual([...object.tags].sort())
    fireEvent.click(screen.getByRole('tab', { name: 'Enrichment' }))
    expect(screen.getByText('58 / 100').outerHTML).toEqual(overviewScore)
    expect(tags()).toEqual(overviewTags)
    expect(screen.getByRole('button', { name: 'Add tag' })).toBeVisible()
    expect(post).not.toHaveBeenCalled()
  })

  it('keeps different entity scores distinct, including zero, and shows missing scores explicitly', async () => {
    vi.mocked(api).mockImplementation(async url => url === '/api/opencti/settings' ? { configured: true } : url.endsWith('/detail') ? detail : { lookups: [
      { ioc_id: 1, status: 'known', entities: [{ id: 'a', name: 'First observable', score: 0 }, { id: 'b', name: 'Second observable', score: 100 }] },
    ] })
    const view = show()
    expect(await screen.findByText('0 / 100')).toBeVisible()
    expect(screen.getByText('100 / 100')).toBeVisible()
    expect(screen.getByText('First observable')).toBeVisible()
    view.unmount()
    vi.mocked(api).mockImplementation(async url => url === '/api/opencti/settings' ? { configured: true } : url.endsWith('/detail') ? detail : { lookups: [{ ioc_id: 1, status: 'known', entities: [{ id: 'a', score: null }] }] })
    show()
    expect(await screen.findByText('No score available')).toBeVisible()
    expect(screen.queryByText('0 / 100')).not.toBeInTheDocument()
  })

  it('groups object actions while retaining the associated file hash scope', async () => {
    const file = { ...ip, type: 'file', value: 'sample.php', assessment: 'malicious' as const }
    const hash = { ...ip, id: 3, type: 'hash', value: 'a'.repeat(64), file_ids: [1] }
    vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? { ...detail, object: file }
      : url === '/api/opencti/settings' ? { configured: true } : { lookups: [] })
    const { container } = renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[file, hash, cve]} onClose={() => {}} embedded />)
    await screen.findByRole('heading', { name: 'sample.php' })
    expect(container.querySelector('header summary')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'IOC actions' })).toBeVisible()
    const toggle = await screen.findByRole('button', { name: 'OpenCTI actions' })
    expect(screen.queryByRole('button', { name: 'Check in OpenCTI' })).not.toBeInTheDocument()
    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    fireEvent.keyDown(toggle, { key: 'Escape' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(toggle)
    fireEvent.pointerDown(document.body)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(toggle)
    expect(screen.queryByRole('button', { name: 'Transfer to OpenCTI' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Enrich via OpenCTI' })).toBeVisible()
    const check = screen.getByRole('button', { name: 'Check in OpenCTI' })
    await waitFor(() => expect(check).toBeEnabled())
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(check)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/opencti/lookup', { ioc_ids: [1, 3] }))
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
    expect(screen.getAllByRole('tab').map(tab => tab.textContent)).toEqual(['Overview', 'Enrichment'])
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

  it('links to the cached OpenCTI object and rejects unsafe links', async () => {
    vi.mocked(api).mockImplementation(async url => url === '/api/opencti/settings' ? { configured: true } : url.endsWith('/detail') ? detail : { lookups: [{ ioc_id: 1, entities: [
      { id: 'remote', name: ip.value, url: 'https://cti.example/dashboard/observations/observables/remote' },
      { id: 'unsafe', name: 'Unsafe URL', url: 'javascript:void(0)' },
    ] }] })
    show()
    const link = await screen.findByRole('link', { name: 'Open in OpenCTI' })
    expect(link).toHaveAttribute('href', 'https://cti.example/dashboard/observations/observables/remote')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
    expect(screen.getAllByRole('link')).toHaveLength(1)
    expect(post).not.toHaveBeenCalled()
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
