import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { OpenCtiActivity } from './OpenCtiActivity'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { configured: true } : {
    jobs: [], sync: [], exports: [{ id: 'receipt', state: 'partial', updated: '2026-11-04', error: 'Import incomplete', stats: { objects: 3 } }],
    enrichments: [{ id: 'old', connector_name: 'Retired connector' }],
  })
  vi.mocked(post).mockResolvedValue({ job_id: 3 })
})

it('shows export receipts and resumes only an explicitly chosen transfer', async () => {
  renderWithProviders(<OpenCtiActivity slug="qa" allowRetry />)
  expect(await screen.findByText('Import incomplete')).toBeVisible()
  expect(screen.queryByText('Retired connector')).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Retry incomplete transfer' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/retry', { export_id: 'receipt' }))
})

it('does not offer retry without explicit permission from its parent', async () => {
  renderWithProviders(<OpenCtiActivity slug="qa" />)
  await screen.findByText('Import incomplete')
  expect(screen.queryByRole('button', { name: 'Retry incomplete transfer' })).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})

it('shows verified counts and rejects unsafe remote case links', async () => {
  vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { configured: true } : {
    jobs: [], sync: [], exports: [{ id: 'receipt', state: 'complete', updated: '', case_url: 'javascript:alert(1)', stats: { objects: 12, counts: { ips: 2, cves: 1, hashes: 1 } } }],
  })
  renderWithProviders(<OpenCtiActivity slug="qa" allowRetry />)
  expect(await screen.findByText('2 IPs, 1 CVE, 1 hash successfully transferred')).toBeVisible()
  expect(screen.queryByRole('link')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Retry incomplete transfer' })).not.toBeInTheDocument()
})
