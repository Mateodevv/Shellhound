import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { post, type TraceRow } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { TraceWindow, type TraceAnchor } from './TraceWindow'

vi.mock('../../api', async (original) => ({
  ...(await original<typeof import('../../api')>()), post: vi.fn(),
}))
vi.mock('../ui/IpFlag', () => ({ IpFlag: () => null }))
vi.mock('../ui/TimelineChart', () => ({ TimelineChart: () => <div>Activity timeline</div> }))

const IPS = ['203.0.113.42']
const MARKS = { exact: ['/selected-marker'], reason: 'Selected pattern request' }
const ANCHOR: TraceAnchor = {
  requestId: 7, epoch: 1_700_000_000, tz: 0,
  method: 'GET', uri: '/selected-marker', source: 'sample-access.log', lineNo: 12,
  indexFingerprint: 'sample-index-1',
}
const LATER: TraceRow = {
  client: IPS[0], epoch: 1_700_000_060, tz: 0, method: 'GET', uri: '/documentation',
  status: 200, size: 123, referrer: '-', agent: 'Example browser', source: 'sample-access.log',
}
const EARLIER: TraceRow = { ...LATER, epoch: 1_699_999_990, uri: '/earlier-page' }

function installTraceResponses() {
  vi.mocked(post).mockImplementation(async (path, body) => {
    if (path.endsWith('/timeline')) return { timeline: [] }
    const filters = body as Record<string, unknown>
    const rows = filters.after_request_id == null ? [EARLIER, LATER] : [LATER]
    return { total: rows.length, rows, methods: ['GET'] }
  })
}

function traceBodies() {
  return vi.mocked(post).mock.calls.filter(([path]) => path.endsWith('/trace'))
    .map(([, body]) => body as Record<string, unknown>)
}

describe('Pattern Hunt follow-up activity', () => {
  it('loads every later request from the anchored index and can include earlier activity', async () => {
    installTraceResponses()
    renderWithProviders(<TraceWindow slug="sample" ips={IPS} marks={MARKS} anchor={ANCHOR} onClose={() => {}} />)

    const selected = screen.getByRole('region', { name: 'Selected request' })
    expect(within(selected).getByText('GET')).toBeInTheDocument()
    expect(within(selected).getByText('sample-access.log · line 12')).toBeInTheDocument()
    expect(within(selected).getByText(/UTC/)).toBeInTheDocument()
    expect(await screen.findByText('/documentation')).toBeInTheDocument()
    expect(traceBodies().at(-1)).toMatchObject({
      ips: IPS, after_request_id: 7, index_fingerprint: 'sample-index-1', evidence_only: false,
    })
    expect(screen.queryByRole('button', { name: 'Evidence requests' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Export with checksum' })).not.toBeInTheDocument()
    expect(vi.mocked(post).mock.calls.some(([path]) => path.endsWith('/timeline'))).toBe(false)

    fireEvent.click(screen.getByRole('button', { name: 'Full activity' }))
    expect(await screen.findByText('/earlier-page')).toBeInTheDocument()
    expect(traceBodies().at(-1)).toMatchObject({
      after_request_id: null, index_fingerprint: 'sample-index-1', evidence_only: false,
    })
    expect(screen.getByRole('button', { name: 'Full activity' })).toHaveAttribute('aria-pressed', 'true')

    fireEvent.click(screen.getByRole('button', { name: 'Activity after this request' }))
    await waitFor(() => expect(traceBodies().at(-1)).toMatchObject({ after_request_id: 7 }))
    await waitFor(() => expect(screen.queryByText('/earlier-page')).not.toBeInTheDocument())
  })

  it('resets filters and follow-up scope when the selected request changes', async () => {
    installTraceResponses()
    const view = renderWithProviders(<TraceWindow slug="sample" ips={IPS} marks={MARKS} anchor={ANCHOR} onClose={() => {}} />)
    await screen.findByText('/documentation')
    fireEvent.click(screen.getByRole('button', { name: 'Full activity' }))
    fireEvent.change(screen.getByPlaceholderText('URI or user agent…'), { target: { value: 'documentation' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Request order' }), { target: { value: 'time_desc' } })
    await waitFor(() => expect(traceBodies().at(-1)).toMatchObject({ search: 'documentation', sort: 'time_desc' }))

    view.rerender(<TraceWindow slug="sample" ips={[...IPS]} marks={{ ...MARKS }}
      anchor={{ ...ANCHOR, requestId: 9, indexFingerprint: 'sample-index-2' }} onClose={() => {}} />)
    await waitFor(() => expect(traceBodies().at(-1)).toMatchObject({
      after_request_id: 9, index_fingerprint: 'sample-index-2', search: '', status: '',
      method: '', sort: 'time', offset: 0, evidence_only: false,
    }))
    expect(screen.getByPlaceholderText('URI or user agent…')).toHaveValue('')
  })

  it('hides cached rows and gives recovery guidance when the saved index becomes stale', async () => {
    installTraceResponses()
    const { qc } = renderWithProviders(<TraceWindow slug="sample" ips={IPS} anchor={ANCHOR} onClose={() => {}} />)
    await screen.findByText('/documentation')
    vi.mocked(post).mockRejectedValue(new Error('The access-log index changed; check patterns again.'))
    await qc.invalidateQueries({ queryKey: ['trace', 'sample'] })

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('The access-log index changed; check patterns again.')
    expect(alert).toHaveTextContent('close this window and check the pattern again')
    expect(screen.queryByText('/documentation')).not.toBeInTheDocument()
    expect(within(alert).getByRole('button', { name: 'Try loading again' })).toBeInTheDocument()
  })

  it('uses full activity when the selected request has no usable timestamp', async () => {
    installTraceResponses()
    renderWithProviders(<TraceWindow slug="sample" ips={IPS} anchor={{ ...ANCHOR, epoch: null }} onClose={() => {}} />)
    await screen.findByText('/earlier-page')
    expect(screen.getByText(/no usable timestamp/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Activity after this request' })).toBeDisabled()
    expect(traceBodies().at(-1)).toMatchObject({ after_request_id: null, index_fingerprint: 'sample-index-1' })
  })

  it('preserves the evidence scope, timeline, and export for an ordinary trace', async () => {
    installTraceResponses()
    renderWithProviders(<TraceWindow slug="sample" ips={IPS} marks={MARKS} onClose={() => {}} />)
    await screen.findByText('/documentation')
    expect(traceBodies().at(-1)).toMatchObject({ evidence_only: true })
    expect(traceBodies().at(-1)).not.toHaveProperty('after_request_id')
    expect(traceBodies().at(-1)).not.toHaveProperty('index_fingerprint')
    expect(screen.getByRole('button', { name: 'Evidence requests' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('link', { name: 'Export with checksum' })).toBeInTheDocument()
    expect(vi.mocked(post).mock.calls.some(([path]) => path.endsWith('/timeline'))).toBe(true)
  })
})


it('marks every server-verified finding match rather than every request to one example URI', async () => {
  const rows = [
    {...LATER,uri:'/tmp/first.php',finding_match:true},
    {...LATER,uri:'/tmp/second.php',finding_match:true},
    {...LATER,uri:'/tmp/first.php',status:404,finding_match:false},
  ]
  vi.mocked(post).mockImplementation(async path => path.endsWith('/timeline') ? {timeline:[]} : {total:3,rows,methods:['GET']})
  renderWithProviders(<TraceWindow slug="sample" ips={IPS} marks={{findingIds:[4],exact:['/tmp/first.php']}} onClose={() => {}} />)
  expect(await screen.findByText('/tmp/second.php')).toBeVisible()
  expect(document.querySelectorAll('tr[data-finding-match="true"]')).toHaveLength(2)
  expect(document.querySelectorAll('tr[data-finding-match="false"]')).toHaveLength(1)
  expect(traceBodies().at(-1)).toMatchObject({finding_ids:[4],evidence_only:true})
  fireEvent.click(screen.getByRole('button',{name:'All requests'}))
  await waitFor(() => expect(traceBodies().at(-1)).toMatchObject({finding_ids:[4],evidence_only:false}))
})
