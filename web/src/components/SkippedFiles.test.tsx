import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api } from '../api'
import { renderWithProviders } from '../test/setup'
import { SkippedFiles } from './SkippedFiles'

vi.mock('../api', () => ({ api: vi.fn() }))
beforeEach(() => vi.clearAllMocks())

it('loads paths and reasons on demand and can page beyond the first hundred', async () => {
  vi.mocked(api).mockImplementation(async (path) => ({
    recorded: true, total: 101,
    items: path.includes('offset=100')
      ? [{ path: 'C:/Evidence # ä/last.php', reason: 'unreadable' }]
      : Array.from({ length: 100 }, (_, i) => ({ path: `file-${i}.php`, reason: 'too large' })),
  }))
  renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  expect(api).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  expect(await screen.findByText('file-0.php')).toBeInTheDocument()
  expect(screen.getByText('1–100 of 101')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(await screen.findByText('C:/Evidence # ä/last.php')).toBeInTheDocument()
  expect(screen.getByText('unreadable')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Previous' }))
  expect(await screen.findByText('file-0.php')).toBeInTheDocument()
})

it('explains missing historical detail without showing another run’s files', async () => {
  vi.mocked(api).mockResolvedValue({ recorded: false, total: 0, items: [] })
  renderWithProviders(<SkippedFiles slug="case" jobId={1} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  expect(await screen.findByText(/File details were not recorded/)).toBeInTheDocument()
})

it('offers a retry if loading fails', async () => {
  vi.mocked(api).mockRejectedValue(new Error('offline'))
  renderWithProviders(<SkippedFiles slug="case" jobId={1} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('could not be loaded')
  vi.mocked(api).mockResolvedValue({ recorded: true, total: 0, items: [] })
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }))
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
  expect(await screen.findByText(/before individual files/)).toBeInTheDocument()
})
