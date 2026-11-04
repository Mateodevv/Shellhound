import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { RebuildLogIndex } from './RebuildLogIndex'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))

describe('managed log rebuild', () => {
  it('queues the case-scoped rebuild and clears old request selection', async () => {
    vi.mocked(api).mockResolvedValue([])
    vi.mocked(post).mockResolvedValue({ started: [{ kind: 'index_logs', job: 1 }] })
    const onStarted = vi.fn()
    renderWithProviders(<RebuildLogIndex slug="synthetic-case" onStarted={onStarted} />)
    const button = screen.getByRole('button', { name: 'Rebuild log index' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    await waitFor(() => expect(onStarted).toHaveBeenCalledOnce())
    expect(post).toHaveBeenCalledWith('/api/cases/synthetic-case/access/reindex', {})
  })

  it('prevents overlap with an active analysis', async () => {
    vi.mocked(api).mockResolvedValue([{ id: 1, kind: 'index_logs', state: 'running' }])
    renderWithProviders(<RebuildLogIndex slug="busy-case" />)
    expect(await screen.findByRole('button', { name: 'Wait for analysis to finish, or stop it before rebuilding.' })).toBeDisabled()
    expect(screen.getByText('Rebuilding log index…')).toBeInTheDocument()
  })

  it('keeps server refusal visible without reporting success', async () => {
    vi.mocked(api).mockResolvedValue([])
    vi.mocked(post).mockRejectedValue(new Error('Analysis is already running in this case.'))
    const onStarted = vi.fn()
    renderWithProviders(<RebuildLogIndex slug="raced-case" onStarted={onStarted} />)
    const button = screen.getByRole('button', { name: 'Rebuild log index' })
    await waitFor(() => expect(button).toBeEnabled())
    fireEvent.click(button)
    expect(await screen.findByRole('alert')).toHaveTextContent('Analysis is already running in this case.')
    expect(onStarted).not.toHaveBeenCalled()
  })
})
