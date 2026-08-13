import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { api, del, post, type ArchivesResponse } from '../api'
import { renderWithProviders } from '../test/setup'
import { Start } from './Start'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
  del: vi.fn(),
}))

const STATE = {
  workspace: 'C:/ws',
  cases: [{
    slug: 'the-case', name: 'The case', reference: 'IR-7',
    created: '2026-08-01T00:00:00', artifacts: 3, confirmed: 1, iocs: 2,
  }],
}
const NO_ARCHIVES: ArchivesResponse = { archive_dir: 'C:/ws/archive', archives: [] }

beforeEach(() => {
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/state') return STATE
    if (path === '/api/archives') return NO_ARCHIVES
    throw new Error(`unexpected API call: ${path}`)
  })
  vi.mocked(post).mockResolvedValue({})
  vi.mocked(del).mockResolvedValue({})
})

describe('leaving a case from the start page', () => {
  it('deletes only on the second click -- the first one arms', async () => {
    renderWithProviders(<Start onOpen={() => {}} />)
    await screen.findByText('The case')

    const remove = screen.getByRole('button', { name: 'Remove' })
    fireEvent.click(remove)
    // Armed, said out loud, nothing sent yet: a case takes its findings
    // and its triage with it, and there is no way back.
    expect(await screen.findByText('Sure?')).toBeInTheDocument()
    expect(del).not.toHaveBeenCalled()

    fireEvent.click(screen.getByText('Sure?'))
    await waitFor(() =>
      expect(del).toHaveBeenCalledWith('/api/cases/the-case'))
  })

  it('archives on a single click -- the zip below is the way back', async () => {
    renderWithProviders(<Start onOpen={() => {}} />)
    await screen.findByText('The case')

    fireEvent.click(screen.getByRole('button', { name: 'Archive' }))
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/cases/the-case/archive', {}))
    expect(del).not.toHaveBeenCalled()
  })
})
