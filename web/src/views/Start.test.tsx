import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { api, del, post, type ArchivesResponse } from '../api'
import { renderWithProviders } from '../test/setup'
import { Start } from './Start'

vi.mock('../geo', () => ({ useGeoStatus: () => ({ data: { available: true } }) }))
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
    if (path === '/api/opencti/settings') return { configured: false }
    if (path === '/api/state') return STATE
    if (path === '/api/archives') return NO_ARCHIVES
    throw new Error(`unexpected API call: ${path}`)
  })
  vi.mocked(post).mockResolvedValue({})
  vi.mocked(del).mockResolvedValue({})
})

describe('leaving a case from the start page', () => {
  it('requires the case name before permanent deletion', async () => {
    renderWithProviders(<Start onOpen={() => {}} />)
    await screen.findByText('The case')

    const remove = screen.getByRole('button', { name: 'Remove' })
    fireEvent.click(remove)
    expect(await screen.findByRole('dialog', { name: 'Permanently delete this case?' })).toBeInTheDocument()
    expect(del).not.toHaveBeenCalled()

    const confirm = screen.getByRole('button', { name: 'Delete permanently' })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'The case' } })
    fireEvent.click(confirm)
    await waitFor(() =>
      expect(del).toHaveBeenCalledWith('/api/cases/the-case'))
  })

  it('explains the recoverable archive before creating it', async () => {
    renderWithProviders(<Start onOpen={() => {}} />)
    await screen.findByText('The case')

    fireEvent.click(screen.getByRole('button', { name: 'Archive' }))
    expect(await screen.findByRole('dialog', { name: 'Archive this case?' })).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Archive case' }))
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/cases/the-case/archive', {}))
    expect(del).not.toHaveBeenCalled()
  })
})


it('keeps closed cases collapsed until the heading is clicked', async () => {
  const original = vi.mocked(api).getMockImplementation()!
  vi.mocked(api).mockImplementation(path => path === '/api/archives' ? Promise.resolve({ archive_dir: 'C:/ws/archive', archives: [
    { file: 'closed.zip', size: 100, modified: '2026-09-01', readable: true },
  ] }) : original(path))
  renderWithProviders(<Start onOpen={() => {}} />)
  const toggle = await screen.findByRole('button', { name: /Closed cases/ })
  expect(toggle).toHaveAttribute('aria-expanded', 'false')
  expect(screen.queryByRole('button', { name: 'Restore' })).not.toBeInTheDocument()
  fireEvent.click(toggle)
  expect(toggle).toHaveAttribute('aria-expanded', 'true')
  expect(screen.getByRole('button', { name: 'Restore' })).toBeVisible()
  fireEvent.click(toggle)
  expect(screen.queryByRole('button', { name: 'Restore' })).not.toBeInTheDocument()
})
