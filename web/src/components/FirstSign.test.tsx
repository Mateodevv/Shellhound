import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { post, type ChainEvent, type FirstSign as FirstSignData } from '../api'
import { renderWithProviders, testQueryClient } from '../test/setup'
import { FirstSign, FirstSignEditor } from './FirstSign'

vi.mock('../api', async (original) => ({
  ...(await original<typeof import('../api')>()), post: vi.fn(),
}))

const EVENT: ChainEvent = {
  id: 'request:sample-12', at: 1750000000, epoch: 1750000000,
  kind: 'alarm', title: 'Request involving a confirmed finding',
  detail: 'Sample access log, request 12', source: 'log',
  artifact: '/evidence/sample.txt', artifact_kind: 'file', ip: '', severity: 1,
  first_sign_eligible: true, first_sign_selectable: true, first_sign_basis: 'request',
}

const summary = (over: Partial<FirstSignData> = {}): FirstSignData => ({
  mode: 'automatic', state: 'suggested', event: EVENT, automatic_event: EVENT,
  note: '', earlier_candidate: false, stale_reason: null, ...over,
})

beforeEach(() => { vi.mocked(post).mockReset() })

describe('first known sign summary', () => {
  it('shows an automatic observation and forwards its stable event ID from both links', async () => {
    const onTimeline = vi.fn()
    renderWithProviders(<FirstSign slug="sample" data={summary()} onTimeline={onTimeline} />)
    expect(screen.getByText(/Automatically suggested.*Access log observation/)).toBeVisible()
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /Request involving a confirmed finding/ }))
    await user.click(screen.getByRole('button', { name: 'View in timeline' }))
    expect(onTimeline.mock.calls).toEqual([[EVENT.id], [EVENT.id]])
  })

  it('distinguishes no confirmations, undated confirmations and an unavailable summary', () => {
    const { rerender } = renderWithProviders(<FirstSign slug="sample"
      data={summary({ state: 'no_confirmed', event: null, automatic_event: null })} onTimeline={() => {}} />)
    expect(screen.getByRole('status')).toHaveTextContent('No findings have been confirmed by the analyst yet.')
    rerender(<FirstSign slug="sample"
      data={summary({ state: 'undated', event: null, automatic_event: null })} onTimeline={() => {}} />)
    expect(screen.getByRole('status')).toHaveTextContent('Confirmed findings exist; timing not established.')
    rerender(<FirstSign slug="sample" onTimeline={() => {}} />)
    expect(screen.getByRole('status')).toHaveTextContent('The first-sign summary is unavailable.')
    expect(screen.queryByText(/No findings have been confirmed/)).not.toBeInTheDocument()
  })

  it('labels evidence-copy timestamps and keeps manual choices and stale evidence explicit', () => {
    const fileEvent: ChainEvent = { ...EVENT, first_sign_basis: 'filesystem', source: 'filesystem' }
    const { rerender } = renderWithProviders(<FirstSign slug="sample"
      data={summary({ state: 'metadata_only', event: fileEvent })} onTimeline={() => {}} />)
    expect(screen.getByText(/File timestamp — needs review/)).toBeVisible()
    expect(screen.getByText(/metadata of the evidence copy/)).toBeVisible()
    rerender(<FirstSign slug="sample" data={summary({ mode: 'manual', state: 'stale_override',
      note: 'Chosen from corroborated activity', earlier_candidate: true,
      stale_reason: 'The source was removed.' })} onTimeline={() => {}} />)
    expect(screen.getByText(/Selected by analyst/)).toBeVisible()
    expect(screen.getByText(/This saved choice needs review.*The source was removed/)).toBeVisible()
    expect(screen.getByText(/Earlier relevant evidence is available/)).toBeVisible()
    expect(screen.getByText(/Analyst note: Chosen from corroborated activity/)).toBeVisible()
  })

  it('restores the automatic choice only after a successful save and reports a failed attempt', async () => {
    const qc = testQueryClient()
    const manual = summary({ mode: 'manual', note: 'My choice' })
    qc.setQueryData(['first-sign', 'sample'], manual)
    qc.setQueryData(['dashboard', 'sample'], {})
    qc.setQueryData(['chain', 'sample'], {})
    vi.mocked(post).mockRejectedValueOnce(new Error('Save unavailable')).mockResolvedValueOnce(summary())
    renderWithProviders(<FirstSign slug="sample" data={manual} editing onTimeline={() => {}} />, qc)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Restore automatic suggestion' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Save unavailable')
    expect(qc.getQueryData(['first-sign', 'sample'])).toEqual(manual)
    await user.click(screen.getByRole('button', { name: 'Restore automatic suggestion' }))
    await waitFor(() => expect(qc.getQueryData(['first-sign', 'sample'])).toEqual(summary()))
    expect(post).toHaveBeenLastCalledWith('/api/cases/sample/first-sign', { event_id: null })
    expect(qc.getQueryState(['dashboard', 'sample'])?.isInvalidated).toBe(true)
    expect(qc.getQueryState(['chain', 'sample'])?.isInvalidated).toBe(true)
  })
})

describe('first sign override editor', () => {
  it('preserves a draft through refresh and a failed save, then posts that exact event and note', async () => {
    const onSaved = vi.fn()
    const qc = testQueryClient()
    const editor = (initialNote: string) => <FirstSignEditor slug="sample" event={EVENT}
      initialNote={initialNote} onClose={() => {}} onSaved={onSaved} />
    const { rerender } = renderWithProviders(editor('Saved note'), qc)
    const user = userEvent.setup()
    const note = screen.getByRole('textbox', { name: 'Why this event? (optional)' })
    await user.clear(note)
    await user.type(note, 'Earlier evidence checked; keep this request.')
    await act(async () => { qc.setQueryData(['first-sign', 'sample'], summary({ note: 'Server refresh' })) })
    rerender(editor('Server refresh'))
    expect(note).toHaveValue('Earlier evidence checked; keep this request.')
    vi.mocked(post).mockRejectedValueOnce(new Error('Source changed; review again'))
      .mockResolvedValueOnce(summary({ mode: 'manual', note: 'Earlier evidence checked; keep this request.' }))
    await user.click(screen.getByRole('button', { name: 'Set as first known sign' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Source changed; review again')
    expect(onSaved).not.toHaveBeenCalled()
    expect(note).toHaveValue('Earlier evidence checked; keep this request.')
    await user.click(screen.getByRole('button', { name: 'Set as first known sign' }))
    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1))
    expect(post).toHaveBeenLastCalledWith('/api/cases/sample/first-sign', {
      event_id: EVENT.id, note: 'Earlier evidence checked; keep this request.',
    })
    expect(qc.getQueryData<FirstSignData>(['first-sign', 'sample'])?.mode).toBe('manual')
  })

  it('warns about file metadata before selection and does not submit when cancelled', async () => {
    const onClose = vi.fn()
    renderWithProviders(<FirstSignEditor slug="sample" event={{ ...EVENT, first_sign_basis: 'filesystem' }}
      initialNote="" onClose={onClose} onSaved={() => {}} />)
    expect(screen.getByText(/metadata of the evidence copy/)).toBeVisible()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(post).not.toHaveBeenCalled()
  })
})
