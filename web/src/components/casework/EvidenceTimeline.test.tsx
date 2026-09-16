import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { cloneElement, type ReactElement } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, type FirstSign, type TimelinePreview } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { EvidenceTimeline } from './EvidenceTimeline'

vi.mock('../../api', async orig => ({ ...(await orig<typeof import('../../api')>()), api: vi.fn() }))
vi.mock('recharts', async orig => ({
  ...(await orig<typeof import('recharts')>()),
  ResponsiveContainer: ({ children }: { children: ReactElement }) => cloneElement(children, { width: 800, height: 260 } as object),
}))

const START = 1788858000
const DATA: TimelinePreview = {
  buckets: [
    { start: START, end: START + 3600, filesystem_confirmed: 1, filesystem_pending: 2, log_confirmed: 3, log_pending: 4 },
    { start: START + 3600, end: START + 7200, filesystem_confirmed: 0, filesystem_pending: 0, log_confirmed: 0, log_pending: 0 },
    { start: START + 7200, end: START + 10800, filesystem_confirmed: 2, filesystem_pending: 0, log_confirmed: 1, log_pending: 0 },
  ],
  totals: { filesystem_confirmed: 3, filesystem_pending: 2, log_confirmed: 4, log_pending: 4 },
  span: { first: START + 60, last: START + 7250 }, interval: 3600, undated: 2, unavailable: 1, zone: 'UTC',
}
beforeEach(() => vi.mocked(api).mockResolvedValue(DATA))

function mount(firstSign?: FirstSign) {
  const gotoView = vi.fn()
  return { gotoView, ...renderWithProviders(<EvidenceTimeline slug="case-1" firstSign={firstSign} gotoView={gotoView} />) }
}

describe('evidence timeline preview', () => {
  it('shows four separately labelled event totals and includes empty intervals', async () => {
    mount()
    const legend = await screen.findByRole('list', { name: 'Evidence timeline legend' })
    const entries = within(legend).getAllByRole('listitem')
    expect(entries.map(item => item.textContent)).toEqual([
      'File system · Confirmed3', 'File system · Awaiting review2', 'Logs · Confirmed4', 'Logs · Awaiting review4',
    ])
    const interval = screen.getByRole('combobox', { name: 'Time interval (UTC)' })
    expect(within(interval).getAllByRole('option')).toHaveLength(3)
    fireEvent.change(interval, { target: { value: String(START + 3600) } })
    expect(screen.getByRole('button', { name: 'View 0 events' })).toBeDisabled()
    expect(screen.getByText('2 observations have no reliable date and are not plotted.')).toBeVisible()
    expect(screen.getByText('1 observation refers to stale or unavailable evidence and is not plotted.')).toBeVisible()
  })

  it('provides keyboard navigation to the same source, state and exact interval as a segment', async () => {
    const user = userEvent.setup()
    const { gotoView } = mount()
    const interval = await screen.findByRole('combobox', { name: 'Time interval (UTC)' })
    await user.selectOptions(interval, String(START + 7200))
    await user.selectOptions(screen.getByRole('combobox', { name: 'Evidence and decision' }), 'log_confirmed')
    await user.tab()
    expect(screen.getByRole('button', { name: 'View 1 event' })).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(gotoView).toHaveBeenLastCalledWith('timeline', {
      scope: 'confirmed', event_source: 'log', from_epoch: String(START + 7200), to_epoch: String(START + 10800),
    })
    await user.selectOptions(interval, String(START))
    await user.selectOptions(screen.getByRole('combobox', { name: 'Evidence and decision' }), 'filesystem_pending')
    await user.click(screen.getByRole('button', { name: 'View 2 events' }))
    expect(gotoView).toHaveBeenLastCalledWith('timeline', {
      scope: 'pending', event_source: 'filesystem', from_epoch: String(START), to_epoch: String(START + 3600),
    })
  })

  it('opens exact log buckets when a chart segment is clicked', async () => {
    const { container, gotoView } = mount()
    await screen.findByRole('list', { name: 'Evidence timeline legend' })
    const bars = container.querySelectorAll('.recharts-bar-rectangles')
    expect(bars).toHaveLength(4)
    const segment = bars[3].querySelector('.recharts-rectangle')!
    fireEvent.click(segment)
    expect(gotoView).toHaveBeenCalledWith('timeline', {
      scope: 'pending', event_source: 'log', from_epoch: String(START), to_epoch: String(START + 3600),
    })
  })

  it('keeps both stacked bars visible and separate when all events share one interval', async () => {
    vi.mocked(api).mockResolvedValue({
      ...DATA, buckets: [DATA.buckets[0]],
      totals: { filesystem_confirmed: 1, filesystem_pending: 2, log_confirmed: 3, log_pending: 4 },
      span: { first: START + 60, last: START + 60 }, undated: 0, unavailable: 0,
    })
    const { container } = mount()
    await screen.findByRole('list', { name: 'Evidence timeline legend' })
    const segments = [...container.querySelectorAll('.recharts-bar-rectangles .recharts-rectangle')]
      .map(node => Object.fromEntries(['x', 'y', 'width', 'height'].map(key => [key, Number(node.getAttribute(key))])))
    expect(segments).toHaveLength(4)
    for (const segment of segments) {
      expect(segment.width).toBeGreaterThan(0)
      expect(segment.height).toBeGreaterThan(0)
      expect(segment.x).toBeGreaterThanOrEqual(40)
      expect(segment.x + segment.width).toBeLessThanOrEqual(790)
      expect(segment.y).toBeGreaterThanOrEqual(0)
    }
    expect(segments[0].x).toBe(segments[1].x)
    expect(segments[2].x).toBe(segments[3].x)
    expect(segments[0].x + segments[0].width).toBeLessThan(segments[2].x)
  })

  it('requests no more than twelve intervals for a narrow screen', async () => {
    vi.spyOn(window, 'matchMedia').mockImplementation(query => ({ matches: true, media: query, addEventListener: vi.fn(), removeEventListener: vi.fn() }) as unknown as MediaQueryList)
    mount()
    await screen.findByRole('list', { name: 'Evidence timeline legend' })
    expect(api).toHaveBeenCalledWith('/api/cases/case-1/timeline-preview?bins=12')
  })

  it('keeps absent dates separate from a zero-valued completed result', async () => {
    vi.mocked(api).mockResolvedValue({ ...DATA, buckets: [], totals: { filesystem_confirmed: 0, filesystem_pending: 0, log_confirmed: 0, log_pending: 0 } })
    const { gotoView } = mount()
    expect(await screen.findByText('No dated evidence events to plot yet')).toBeVisible()
    expect(screen.queryByRole('combobox')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Review timeline and limits' }))
    expect(gotoView).toHaveBeenCalledWith('timeline', { scope: 'all' })
  })

  it('marks a current first sign with its exact time but excludes stale overrides', async () => {
    const sign = { state: 'metadata_only', event: { epoch: START + 60, fresh: true } } as FirstSign
    const { rerender } = mount(sign)
    expect(await screen.findByText('First known sign of compromise:', { exact: false })).toHaveTextContent('2026-09-08 09:01:00 UTC')
    rerender(<EvidenceTimeline slug="case-1" firstSign={{ ...sign, state: 'stale_override' }} gotoView={vi.fn()} />)
    expect(screen.queryByText('First known sign of compromise:', { exact: false })).toBeNull()
  })

  it('offers retry without presenting an error as no events', async () => {
    vi.mocked(api).mockRejectedValueOnce(new Error('Unavailable'))
    mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
    expect(screen.queryByText('No dated evidence events to plot yet')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByRole('list', { name: 'Evidence timeline legend' })).toBeVisible())
  })
})
