import { fireEvent, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, type CaseChain, type ChainEvent } from '../api'
import type { Navigate } from '../App'
import type { ArtifactStub } from '../components/review/ArtifactWindow'
import { renderWithProviders } from '../test/setup'
import { Timeline } from './Timeline'

vi.mock('../api', async original => ({ ...(await original<typeof import('../api')>()), api: vi.fn() }))
vi.mock('../components/casework/CaseProfile', () => ({ CaseProfileButton: () => null }))
vi.mock('../components/logview/LogCoverage', () => ({ LogCoverage: () => null }))
vi.mock('../components/logview/TraceWindow', () => ({ TraceWindow: () => null }))
vi.mock('../components/review/FileViewer', () => ({ FileViewer: () => null }))
vi.mock('../components/review/triage', () => ({ TriageFollowUp: () => null }))
vi.mock('../components/review/ArtifactWindow', () => ({ ArtifactWindow: ({ artifact }: { artifact: ArtifactStub | null }) =>
  artifact && <div role="dialog" aria-label="Evidence decision">{artifact.triage}: {artifact.triage_note}</div> }))

const event: ChainEvent = {
  id: 'sample-event', epoch: 1750000000, at: 1750000000, source: 'log', review_state: 'pending',
  fresh: true, kind: 'alarm', artifact: '/evidence/sample.txt', artifact_kind: 'file',
  severity: 1, title: 'Harmless observed request', detail: '', ip: '', first_sign_selectable: false,
}
const chain: CaseChain = {
  events: [event], span: { first: event.at, last: event.at }, event_span: { first: event.at, last: event.at },
  gaps: [], undated: [], confirmed: 0, total_events: 1, truncated: false, offset: 0,
  limit: 80, order: 'asc', offsets: { logs: 0, dump: 0 }, tz_mode: 'utc', zone: 'UTC', tz_offsets: [], tz_mixed: false,
}

const gotoView: Navigate = (view, params = {}) => {
  const next = new URLSearchParams({ case: 'sample', view })
  for (const [key, value] of Object.entries(params)) if (value) next.set(key, value)
  history.pushState(null, '', `/?${next}`)
  window.dispatchEvent(new Event('shellhound:navigated'))
}

beforeEach(() => {
  history.replaceState(null, '', '/?case=sample&view=timeline&scope=pending&event_source=log&from_epoch=1749999900&to_epoch=1750000100')
  vi.mocked(api).mockReset().mockImplementation(async path => {
    if (path.endsWith('/dashboard')) return { timeline: [], logs: null }
    if (path.endsWith('/first-sign')) return { state: 'no_confirmed', mode: 'automatic', event: null }
    if (path.includes('/chain?')) return chain
    if (path.includes('/artifact?')) return { artifact: event.artifact, kind: 'file', worst: 1, triage: 'reviewed', triage_note: 'Needs another look' }
    return { evidence_items: [] }
  })
})

describe('timeline dashboard drill-downs', () => {
  it('restores source, decision and time bounds, removes individual filters, and respects browser Back', async () => {
    const first = renderWithProviders(<Timeline slug="sample" gotoView={gotoView} />)
    await screen.findByText(event.title)
    expect(screen.getByRole('combobox', { name: 'Decision' })).toHaveValue('pending')
    expect(screen.getByRole('combobox', { name: 'Evidence source' })).toHaveValue('log')
    const firstRequest = vi.mocked(api).mock.calls.find(([path]) => path.includes('/chain?'))![0]
    expect(new URL(firstRequest, location.origin).searchParams.get('from_epoch')).toBe('1749999900')
    const original = location.href
    fireEvent.click(screen.getByRole('button', { name: 'Remove Evidence source filter' }))
    expect(new URL(location.href).searchParams.has('event_source')).toBe(false)
    expect(new URL(location.href).searchParams.get('scope')).toBe('pending')
    history.replaceState(null, '', original)
    fireEvent.popState(window)
    expect(screen.getByRole('combobox', { name: 'Evidence source' })).toHaveValue('log')
    first.unmount()
    renderWithProviders(<Timeline slug="sample" gotoView={gotoView} />)
    expect(await screen.findByRole('combobox', { name: 'Decision' })).toHaveValue('pending')
    expect(screen.getByRole('combobox', { name: 'Evidence source' })).toHaveValue('log')
  })

  it('opens the artifact with its authoritative decision, never an assumed confirmation', async () => {
    renderWithProviders(<Timeline slug="sample" gotoView={gotoView} />)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Artifact' }))
    expect(await screen.findByRole('dialog', { name: 'Evidence decision' })).toHaveTextContent('reviewed: Needs another look')
    expect(screen.queryByRole('button', { name: /Use as first sign/ })).not.toBeInTheDocument()
  })

  it('resets a mounted timeline when the sidebar leads to its unfiltered URL', async () => {
    renderWithProviders(<Timeline slug="sample" gotoView={gotoView} />)
    await screen.findByText(event.title)
    history.pushState(null, '', '/?case=sample&view=timeline')
    fireEvent(window, new Event('shellhound:navigated'))
    expect(screen.getByRole('combobox', { name: 'Decision' })).toHaveValue('confirmed')
    expect(screen.getByRole('combobox', { name: 'Evidence source' })).toHaveValue('')
    expect(screen.getByLabelText('From (UTC)')).toHaveValue('')
    expect(screen.getByLabelText('Before (UTC)')).toHaveValue('')
  })

  it('does not open an invented artifact when its current decision cannot be loaded', async () => {
    const normal = vi.mocked(api).getMockImplementation()!
    vi.mocked(api).mockImplementation(async path => {
      if (path.includes('/artifact?')) throw new Error('Unavailable')
      return normal(path)
    })
    renderWithProviders(<Timeline slug="sample" gotoView={gotoView} />)
    await userEvent.setup().click(await screen.findByRole('button', { name: 'Artifact' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The evidence could not be opened.')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('rejects a reversed range before querying and lets the analyst clear it', async () => {
    history.replaceState(null, '', '/?case=sample&view=timeline&from_epoch=1750000100&to_epoch=1749999900')
    renderWithProviders(<Timeline slug="sample" gotoView={gotoView} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('The end must be later than the start.')
    expect(vi.mocked(api).mock.calls.some(([path]) => path.includes('/chain?'))).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Remove Time range filter' }))
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
    expect(await screen.findByText(event.title)).toBeVisible()
  })
})
