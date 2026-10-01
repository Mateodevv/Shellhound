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
    if (path.endsWith('/jobs')) return [] as never
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

it('generates a local testcase and opens the returned case', async () => {
  const onOpen = vi.fn()
  vi.mocked(post).mockResolvedValue({ slug: 'training-case', job_id: 1 })
  renderWithProviders(<Start onOpen={onOpen} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Generate Testcase' }))
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/testcase/jobs', { size: 'small', run_analysis: true }))
  fireEvent.click(await screen.findByRole('button', { name: 'Open case' }))
  await waitFor(() => expect(onOpen).toHaveBeenCalledWith('training-case'))
})
it('shows generation errors without opening a case', async () => {
  const onOpen = vi.fn()
  vi.mocked(post).mockRejectedValue(new Error('Cannot write the workspace'))
  renderWithProviders(<Start onOpen={onOpen} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Generate Testcase' }))
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Cannot write the workspace')
  expect(onOpen).not.toHaveBeenCalled()
})


it('offers large quantities and permits generation without analysis', async () => {
  vi.mocked(post).mockResolvedValue({ slug: 'large-case', job_id: 9 })
  renderWithProviders(<Start onOpen={() => {}} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Generate Testcase' }))
  fireEvent.change(screen.getByRole('combobox', { name: 'Size' }), { target: { value: 'large' } })
  expect(screen.getByText(/5 million requests over 30 days/)).toBeVisible()
  expect(screen.getByText(/At least 8 GB free/)).toBeVisible()
  fireEvent.click(screen.getByRole('checkbox', { name: 'Run analysis afterwards' }))
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/testcase/jobs', { size: 'large', run_analysis: false }))
})

it('shows background progress and cancels the case jobs', async () => {
  const initial = vi.mocked(api).getMockImplementation()!
  let stopped = false
  vi.mocked(api).mockImplementation(async path => path.endsWith('/jobs') ? [{ id: 9, kind: 'generate_testcase', state: stopped ? 'cancelled' : 'running', progress: .2, message: 'Files: 50,000 / 50,000', error: '' }] : initial(path))
  vi.mocked(post).mockImplementation(async path => {
    if (path.endsWith('/cancel')) { stopped = true; return { ok: true } as never }
    return { slug: 'large-case', job_id: 9 } as never
  })
  renderWithProviders(<Start onOpen={() => {}} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Generate Testcase' }))
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }))
  expect(await screen.findByText('Files: 50,000 / 50,000')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/large-case/jobs/9/cancel', {}))
  expect(await screen.findByText('cancelled')).toBeVisible()
})
