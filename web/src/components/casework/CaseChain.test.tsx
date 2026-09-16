import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { api, type CaseChain as ChainData, type ChainEvent } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { CaseChain } from './CaseChain'

vi.mock('../../api', async (original) => ({
  ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn(),
}))

const event = (index: number, over: Partial<ChainEvent> = {}): ChainEvent => ({
  id: `request:sample-${index}`, at: 1750000000 + index, epoch: 1750000000 + index,
  kind: 'alarm', title: `Observed request ${index}`, detail: 'Harmless sample evidence',
  source: 'log', artifact: '/evidence/sample.txt', artifact_kind: 'file', ip: '', severity: 1,
  first_sign_selectable: true, first_sign_eligible: true, first_sign_basis: 'request', ...over,
})

function page(offset: number, count: number, total = count, over: Partial<ChainData> = {}): ChainData {
  return {
    events: Array.from({ length: count }, (_, i) => event(offset + i)),
    span: { first: 1750000000, last: 1750000000 + total },
    event_span: { first: 1750000000, last: 1750000000 + total }, gaps: [], undated: [],
    confirmed: 1, total_events: total, truncated: offset + count < total,
    offset, limit: 80, order: 'asc', offsets: { logs: 0, dump: 0 },
    tz_mode: 'utc', zone: 'UTC', tz_offsets: ['+00:00'], tz_mixed: false, ...over,
  }
}

beforeEach(() => { vi.mocked(api).mockReset() })

describe('timeline first sign links', () => {
  it('renders and opens a confirmed dated log observation', async () => {
    const observation = event(0, { kind: 'log-observation', title: 'FTP upload recorded',
      artifact: 'log-observation:sample', artifact_kind: 'log_observation',
      first_sign_basis: 'log_observation' })
    vi.mocked(api).mockResolvedValue(page(0, 1, 1, { events: [observation] }))
    const open = vi.fn()
    renderWithProviders(<CaseChain slug="sample" onOpen={open} onTrace={() => {}} />)
    expect(await screen.findByText('FTP upload recorded')).toBeVisible()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Artifact' }))
    expect(open).toHaveBeenCalledWith('log-observation:sample', 'log_observation')
  })
  it('jumps beyond the first 80 events, focuses the exact event, and pages backward without repeating the jump', async () => {
    const focusId = 'request:sample-125'
    vi.mocked(api).mockImplementation(async (path) => {
      const url = new URL(path, 'http://localhost')
      if (url.searchParams.has('focus')) return page(80, 80, 200, { focus_found: true })
      return url.searchParams.get('offset') === '0' ? page(0, 80, 200) : page(160, 40, 200)
    })
    const scroll = vi.spyOn(Element.prototype, 'scrollIntoView')
    const { rerender } = renderWithProviders(<CaseChain slug="sample" focusId={focusId} onOpen={() => {}} onTrace={() => {}} />)
    const focused = await screen.findByLabelText('Linked timeline event')
    expect(within(focused).getByText('Observed request 125')).toBeVisible()
    await waitFor(() => expect(focused).toHaveFocus())
    expect(api).toHaveBeenCalledWith('/api/cases/sample/chain?limit=80&offset=0&order=asc&focus=request%3Asample-125')
    expect(scroll).toHaveBeenCalledTimes(1)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Show preceding events' }))
    expect(await screen.findByText('Observed request 0')).toBeVisible()
    expect(api).toHaveBeenLastCalledWith('/api/cases/sample/chain?limit=80&offset=0&order=asc')
    expect(screen.queryByRole('button', { name: 'Show preceding events' })).not.toBeInTheDocument()
    expect(screen.getAllByText('Observed request 125')).toHaveLength(1)
    expect(scroll).toHaveBeenCalledTimes(1)
    await user.click(screen.getByRole('button', { name: 'Show 40 more' }))
    expect(await screen.findByText('Observed request 199')).toBeVisible()
    expect(api).toHaveBeenLastCalledWith('/api/cases/sample/chain?limit=80&offset=160&order=asc')
    expect(scroll).toHaveBeenCalledTimes(1)
    // Another deliberate link click revisits the same row without reloading
    // the chain or losing pages the analyst already opened.
    rerender(<CaseChain slug="sample" focusId={focusId} focusRequest={1} onOpen={() => {}} onTrace={() => {}} />)
    await waitFor(() => expect(focused).toHaveFocus())
    expect(scroll).toHaveBeenCalledTimes(2)
    expect(api).toHaveBeenCalledTimes(3)
  })

  it('explains a missing deep link without highlighting an unrelated event', async () => {
    vi.mocked(api).mockResolvedValue(page(0, 2, 2, { focus_found: false }))
    renderWithProviders(<CaseChain slug="sample" focusId="removed-event" onOpen={() => {}} onTrace={() => {}} />)
    expect(await screen.findByText(/The linked event is no longer in the current timeline/)).toBeVisible()
    expect(screen.queryByLabelText('Linked timeline event')).not.toBeInTheDocument()
    expect(screen.getByText('Observed request 0')).toBeVisible()
  })

  it('shows loading and recoverable errors without reporting an empty timeline', async () => {
    let fail!: (error: Error) => void
    vi.mocked(api).mockImplementationOnce(() => new Promise((_, reject) => { fail = reject }))
      .mockResolvedValueOnce(page(0, 1))
    renderWithProviders(<CaseChain slug="sample" focusId="request:sample-0" onOpen={() => {}} onTrace={() => {}} />)
    expect(screen.getByRole('status')).toHaveTextContent(/Loading/)
    fail(new Error('Temporary read failure'))
    expect(await screen.findByRole('alert')).toHaveTextContent('The timeline could not be loaded.')
    expect(screen.queryByText(/The linked event is no longer/)).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('Observed request 0')).toBeVisible()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('offers marker selection only for selectable events and passes the event unchanged', async () => {
    const selectable = event(1)
    vi.mocked(api).mockResolvedValue(page(0, 3, 3, { events: [
      selectable, event(2, { first_sign_selectable: false }), event(3, { id: undefined }),
      event(4, { review_state: 'pending' }), event(5, { fresh: false }),
    ] }))
    const choose = vi.fn()
    const open = vi.fn()
    renderWithProviders(<CaseChain slug="sample" onOpen={open} onTrace={() => {}} onSelectFirstSign={choose} />)
    const button = await screen.findByRole('button', { name: 'Use as first sign: Observed request 1' })
    expect(screen.getAllByRole('button', { name: /Use as first sign:/ })).toHaveLength(1)
    await userEvent.setup().click(button)
    expect(choose).toHaveBeenCalledWith(selectable)
    expect(open).not.toHaveBeenCalled()
  })

  it('keeps dashboard segment filters on every page and does not call pending observations confirmed', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      const offset = Number(new URL(path, location.origin).searchParams.get('offset'))
      return page(offset, offset === 0 ? 80 : 1, 81, { events: [event(offset, { review_state: 'pending' })], truncated: offset === 0 })
    })
    renderWithProviders(<CaseChain slug="sample" filters={{ scope: 'pending', event_source: 'log',
      from_epoch: '1749999900', to_epoch: '1750000100' }} onOpen={() => {}} onTrace={() => {}} />)
    expect(await screen.findByText('Awaiting review')).toBeVisible()
    expect(screen.queryByText('Confirmed')).not.toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: /Show .* more/ }))
    await waitFor(() => expect(api).toHaveBeenCalledTimes(2))
    for (const [path] of vi.mocked(api).mock.calls) {
      const params = new URL(path, location.origin).searchParams
      expect(params.get('scope')).toBe('pending')
      expect(params.get('event_source')).toBe('log')
      expect(params.get('from_epoch')).toBe('1749999900')
      expect(params.get('to_epoch')).toBe('1750000100')
    }
  })

  it('labels database context neutrally and never offers it as a confirmed first sign', async () => {
    vi.mocked(api).mockResolvedValue(page(0, 2, 2, { events: [
      event(1, { source: 'dump', kind: 'konto', title: 'Account creation recorded', artifact: '', artifact_kind: '', review_state: 'context' }),
      event(2, { source: 'dump', kind: 'konto', title: 'Legacy account context', artifact: '', artifact_kind: '', review_state: undefined }),
    ] }))
    renderWithProviders(<CaseChain slug="sample" onOpen={vi.fn()} onTrace={vi.fn()} onSelectFirstSign={vi.fn()} />)
    expect(await screen.findByText('Account creation recorded')).toBeVisible()
    expect(screen.getAllByText('Context observation')).toHaveLength(2)
    expect(screen.queryByText('Confirmed')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Use as first sign:/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Artifact' })).not.toBeInTheDocument()
  })
})
