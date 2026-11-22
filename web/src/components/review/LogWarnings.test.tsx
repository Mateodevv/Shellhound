import { fireEvent, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { api, post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { LogWarnings } from './LogWarnings'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
it('selects warnings across pages independently of retry and refreshes after a conflict', async () => {
  const ids = Array.from({ length: 101 }, (_, i) => i + 1)
  const selection_warnings = Object.fromEntries(ids.map(id => [id, { source_id: `s${id}`, warning_key: `k${id}` }]))
  vi.mocked(api).mockImplementation(async path => path.endsWith('/log-sources') ? { sources: [], formats: {} } : {
    items: ids.slice(0, 100).map(id => ({ id, path: `source ${id}`, reason: 'Review', status: 'unresolved', source_id: `s${id}`, warning_key: `k${id}` })),
    total: 101, counts: { manual_review: 101, unsupported: 0, processing_error: 0, accepted: 0 },
    selection_ids: { acceptable: ids, reopenable: [], retryable: [] }, selection_warnings,
  })
  vi.mocked(post).mockRejectedValue(new Error('Warning changed'))
  renderWithProviders(<LogWarnings slug="qa" jobId={1} />)
  fireEvent.click(screen.getByRole('button', { name: 'Show log warnings' }))
  fireEvent.click(await screen.findByRole('button', { name: 'Select all (101)' }))
  expect(screen.queryByRole('button', { name: /Retry selected/ })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Accept selected (101)' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/log-sources/review-warnings', { decision: 'accept', selections: Object.values(selection_warnings) }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Warning changed')
  await waitFor(() => expect(vi.mocked(api).mock.calls.filter(([path]) => path.includes('/skipped?')).length).toBeGreaterThan(1))
})

it('reopens accepted warnings using their current source key', async () => {
  vi.mocked(api).mockImplementation(async path => path.endsWith('/log-sources') ? { sources: [], formats: {} } : {
    items: [{ id: 1, path: 'accepted source', reason: 'Review', status: 'accepted', source_id: 's1', warning_key: 'fresh' }], total: 1,
    counts: { manual_review: 1, unsupported: 0, processing_error: 0, accepted: 1 },
    selection_ids: { acceptable: [], reopenable: [1], retryable: [] }, selection_warnings: { '1': { source_id: 's1', warning_key: 'fresh' } },
  })
  vi.mocked(post).mockResolvedValue({ updated: 1 })
  renderWithProviders(<LogWarnings slug="qa" jobId={1} initiallyOpen initialStatus="accepted" />)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select accepted source' }))
  fireEvent.click(screen.getByRole('button', { name: 'Reopen selected (1)' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/log-sources/review-warnings', { decision: 'reopen', selections: [{ source_id: 's1', warning_key: 'fresh' }] }))
})

it('exposes group controls and retries only eligible processing errors', async () => {
  vi.mocked(api).mockImplementation(async path => path.endsWith('/log-sources') ? { sources: [], formats: {} } : {
    items: [{ id: 1, path: 'failed source', reason: 'Error', status: 'unresolved', source_id: 's1', warning_key: 'fresh' }], total: 1,
    counts: { manual_review: 0, unsupported: 1, processing_error: 1, accepted: 0 },
    selection_ids: { acceptable: [1], reopenable: [], retryable: path.includes('group=processing_error') ? [1] : [] }, selection_warnings: { '1': { source_id: 's1', warning_key: 'fresh' } },
  })
  vi.mocked(post).mockResolvedValue({})
  renderWithProviders(<LogWarnings slug="qa" jobId={1} initiallyOpen />)
  fireEvent.click(await screen.findByRole('button', { name: 'Unsupported (1)' }))
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select failed source' }))
  expect(screen.queryByRole('button', { name: /Retry selected/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('link', { name: 'Open Logs' })).not.toBeInTheDocument()
  expect(screen.queryByRole('link', { name: 'Change source settings' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Processing error (1)' }))
  await waitFor(() => expect(screen.getByRole('checkbox', { name: 'Select failed source' })).toBeEnabled())
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select failed source' }))
  fireEvent.click(screen.getByRole('button', { name: 'Retry selected (1)' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/log-sources/analyze', { source_ids: ['s1'], warning_selections: [{ source_id: 's1', warning_key: 'fresh' }] }))
})

it('drops a selection when a poll returns a different warning key', async () => {
  let key = 'old'
  vi.mocked(api).mockImplementation(async path => path.endsWith('/log-sources') ? { sources: [], formats: {} } : {
    items: [{ id: 1, path: 'source', reason: 'Review', status: 'unresolved', source_id: 's1', warning_key: key }], total: 1,
    counts: { manual_review: 1, unsupported: 0, processing_error: 0, accepted: 0 },
    selection_ids: { acceptable: [1], reopenable: [], retryable: [] }, selection_warnings: { '1': { source_id: 's1', warning_key: key } },
  })
  const view = renderWithProviders(<LogWarnings slug="qa" jobId={1} initiallyOpen />)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select source' }))
  expect(screen.getByRole('button', { name: 'Accept selected (1)' })).toBeEnabled()
  key = 'new'
  await view.qc.refetchQueries({ queryKey: ['job-skips', 'qa', 1] })
  await waitFor(() => expect(screen.getByRole('checkbox', { name: 'Select source' })).not.toBeChecked())
  expect(screen.getByRole('button', { name: 'Accept selected (0)' })).toBeDisabled()
})
