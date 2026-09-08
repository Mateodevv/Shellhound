import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../api'
import { renderWithProviders } from '../test/setup'
import { SkippedFiles } from './SkippedFiles'

vi.mock('../api', () => ({ api: vi.fn(), post: vi.fn() }))
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

const skipped = (id: number) => ({ id, path: `file-${id}.php`, reason: 'read failed',
  category: 'file' as const, status: 'unresolved' as const, retryable: true })

it('keeps selections across pages and refetches, then retries only selected IDs', async () => {
  vi.mocked(api).mockImplementation(async (path) => ({
    recorded: true, total: 101, unresolved: 101, retryable: 101, busy: false,
    items: path.includes('offset=100') ? [skipped(100)] : Array.from({ length: 100 }, (_, id) => skipped(id)),
  }))
  vi.mocked(post).mockResolvedValue({ jobs: [8], run_id: 'retry' })
  const { qc } = renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select file-0.php for retry' }))
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select file-100.php for retry' }))
  await act(() => qc.invalidateQueries({ queryKey: ['job-skips', 'case', 7] }))
  expect(screen.getByRole('checkbox', { name: 'Select file-100.php for retry' })).toBeChecked()
  fireEvent.click(screen.getByRole('button', { name: 'Previous' }))
  expect(await screen.findByRole('checkbox', { name: 'Select file-0.php for retry' })).toBeChecked()
  fireEvent.click(screen.getByRole('button', { name: 'Retry selected (2)' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/jobs/7/retry-skipped', {
    mode: 'selected', ids: [0, 100],
  }))
  expect(await screen.findByText(/Retry started/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Retry selected (0)' })).toBeDisabled()
})

it('retries all unresolved files through one request and disables duplicate clicks', async () => {
  vi.mocked(api).mockResolvedValue({ recorded: true, total: 1, unresolved: 1, retryable: 1, items: [skipped(0)] })
  let complete: (value: { jobs: number[]; run_id: string }) => void = () => {}
  vi.mocked(post).mockImplementation(() => new Promise((resolve) => { complete = resolve }))
  renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Retry all skipped files (1)' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Retry all skipped files (1)' })).toBeDisabled())
  expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/case/jobs/7/retry-skipped', { mode: 'all' })
  await act(async () => complete({ jobs: [8], run_id: 'retry' }))
})

it('shows resolved history, blocks unsafe retries and reports current retry errors', async () => {
  const response = { recorded: true, total: 2, unresolved: 1, retryable: 1, blocked_reason: '', items: [
    skipped(0), { ...skipped(1), status: 'resolved', retryable: false, retry_job_id: 9 },
  ] }
  vi.mocked(api).mockResolvedValue(response)
  vi.mocked(post).mockRejectedValue(new Error('Rules changed. Run a full analysis.'))
  const { qc, rerender } = renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  expect(await screen.findByText('Resolved')).toBeInTheDocument()
  expect(screen.getByText('Retry #9')).toBeInTheDocument()
  expect(screen.getByRole('checkbox', { name: 'Select file-1.php for retry' })).toBeDisabled()
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select file-0.php for retry' }))
  fireEvent.click(screen.getByRole('button', { name: 'Retry selected (1)' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Rules changed')
  vi.mocked(api).mockResolvedValue({ ...response, blocked_reason: 'Rules changed. Run a full analysis.' })
  await act(() => qc.invalidateQueries({ queryKey: ['job-skips', 'case', 7] }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Retry selected (1)' })).toBeDisabled())
  rerender(<SkippedFiles slug="other" jobId={7} />)
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  expect(await screen.findByRole('button', { name: 'Retry selected (0)' })).toBeDisabled()
})

const large = (id: number) => ({ ...skipped(id), reason: 'File size exceeds the content scan limit',
  group: 'size_limit' as const, acceptable: true, forceable: true,
  size_bytes: 6 * 1024 * 1024, limit_bytes: 5 * 1024 * 1024 })

it('selects all size skips across pages, allows individual unticking, and accepts only the remaining IDs', async () => {
  const ids = Array.from({ length: 101 }, (_, id) => id)
  vi.mocked(api).mockImplementation(async (path) => ({
    recorded: true, total: 101, counts: { size_limit: 101, other: 2, accepted: 0 },
    selection_ids: { retryable: ids, acceptable: ids, forceable: ids },
    items: path.includes('offset=100') ? [large(100)] : ids.slice(0, 100).map(large),
  }))
  vi.mocked(post).mockResolvedValue({ accepted: 100 })
  const { qc } = renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Size limit (101)' })).toHaveAttribute('aria-pressed', 'true'))
  fireEvent.click(screen.getByRole('button', { name: 'Select all (101)' }))
  expect(screen.getByRole('checkbox', { name: 'Select file-0.php' })).toBeChecked()
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  const last = await screen.findByRole('checkbox', { name: 'Select file-100.php' })
  expect(last).toBeChecked()
  fireEvent.click(last)
  await act(() => qc.invalidateQueries({ queryKey: ['job-skips', 'case', 7] }))
  expect(screen.getByRole('checkbox', { name: 'Select file-100.php' })).not.toBeChecked()
  fireEvent.click(screen.getByRole('button', { name: 'Accept size skip (100)' }))
  await waitFor(() => expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/case/jobs/7/accept-skipped', {
    mode: 'selected', ids: ids.slice(0, 100), group: 'size_limit', status: 'pending',
  }))
  expect(await screen.findByRole('status')).toHaveTextContent('decisions are saved')
})

it('can accept large skips when scanning is blocked', async () => {
  vi.mocked(api).mockResolvedValue({
    recorded: true, total: 2, counts: { size_limit: 2, other: 0, accepted: 0 },
    blocked_reason: 'Rules changed. Run a full analysis before retrying.',
    selection_ids: { retryable: [], acceptable: [0, 1], forceable: [] },
    items: [large(0), { ...large(1), size_bytes: 300 * 1024 * 1024, forceable: false,
      action_reason: 'Above the 256 MiB limit for this attempt.' }],
  })
  vi.mocked(post).mockResolvedValue({ accepted: 2 })
  renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Size limit (2)' })).toHaveAttribute('aria-pressed', 'true'))
  fireEvent.click(screen.getByRole('button', { name: 'Select all (2)' }))
  expect(screen.getByRole('button', { name: 'Scan despite size limit (0)' })).toBeDisabled()
  expect(screen.getByText('Above the 256 MiB limit for this attempt.')).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Accept size skip (2)' }))
  await waitFor(() => expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/case/jobs/7/accept-skipped', {
    mode: 'selected', ids: [0, 1], group: 'size_limit', status: 'pending',
  }))
})

it('limits forced scans to eligible selected files while allowing larger and legacy skips to be accepted', async () => {
  vi.mocked(api).mockResolvedValue({ recorded: true, total: 3,
    counts: { size_limit: 3, other: 0, accepted: 0 },
    selection_ids: { retryable: [0, 1, 2], acceptable: [0, 1, 2], forceable: [0] },
    items: [large(0), { ...large(1), size_bytes: 300 * 1024 * 1024, forceable: false },
      { ...large(2), category: 'other', forceable: false }],
  })
  vi.mocked(post).mockResolvedValue({ jobs: [8], run_id: 'larger-file-retry' })
  renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Size limit (3)' })).toHaveAttribute('aria-pressed', 'true'))
  fireEvent.click(screen.getByRole('button', { name: 'Select all (3)' }))
  expect(screen.getByRole('checkbox', { name: 'Select file-2.php' })).toBeChecked()
  expect(screen.getByRole('button', { name: 'Accept size skip (3)' })).toBeEnabled()
  fireEvent.click(screen.getByRole('button', { name: 'Scan despite size limit (1)' }))
  await waitFor(() => expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/case/jobs/7/retry-skipped', {
    mode: 'selected', ids: [0], group: 'size_limit', status: 'pending', allow_large_files: true,
  }))
})

it('keeps accepted files distinct from scanned files and permits a later explicit larger-file scan', async () => {
  vi.mocked(api).mockImplementation(async (path) => ({
    recorded: true, total: path.includes('status=accepted') ? 1 : 0,
    counts: { size_limit: 1, other: 0, accepted: 1 },
    selection_ids: { retryable: [], acceptable: [], forceable: path.includes('status=accepted') ? [0] : [] },
    items: path.includes('status=accepted') ? [{ ...large(0), status: 'accepted', acceptable: false }] : [],
  }))
  vi.mocked(post).mockResolvedValue({ jobs: [8], run_id: 'larger-file-retry' })
  renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Size limit (1)' })).toHaveAttribute('aria-pressed', 'true'))
  fireEvent.change(screen.getByRole('combobox', { name: 'Show' }), { target: { value: 'accepted' } })
  expect(await screen.findByText('Accepted · not scanned')).toBeInTheDocument()
  expect(screen.queryByText('Resolved')).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select file-0.php' }))
  expect(screen.getByRole('button', { name: 'Accept size skip (0)' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Scan despite size limit (1)' }))
  await waitFor(() => expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/case/jobs/7/retry-skipped', {
    mode: 'selected', ids: [0], group: 'size_limit', status: 'accepted', allow_large_files: true,
  }))
})

it('does not carry size selections into other skips or bypass the normal limit on ordinary retries', async () => {
  vi.mocked(api).mockImplementation(async (path) => {
    const other = path.includes('group=other')
    return { recorded: true, total: 1, counts: { size_limit: 1, other: 1, accepted: 0 },
      selection_ids: { retryable: other ? [1] : [0], acceptable: other ? [] : [0], forceable: other ? [] : [0] },
      items: other ? [{ ...skipped(1), group: 'other' }] : [large(0)] }
  })
  vi.mocked(post).mockResolvedValue({ jobs: [8], run_id: 'retry' })
  renderWithProviders(<SkippedFiles slug="case" jobId={7} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show skipped files and rules' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Size limit (1)' })).toHaveAttribute('aria-pressed', 'true'))
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select file-0.php' }))
  fireEvent.click(screen.getByRole('button', { name: 'Other skips (1)' }))
  expect(await screen.findByRole('button', { name: 'Retry selected (0)' })).toBeDisabled()
  expect(screen.queryByRole('button', { name: /Accept size skip/ })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select file-1.php' }))
  fireEvent.click(screen.getByRole('button', { name: 'Retry selected (1)' }))
  await waitFor(() => expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/case/jobs/7/retry-skipped', {
    mode: 'selected', ids: [1], group: 'other', status: 'pending', allow_large_files: false,
  }))
})
