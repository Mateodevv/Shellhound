import { beforeEach, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { api, patch, post } from '../api'
import { renderWithProviders } from '../test/setup'
import { OpenCtiSettings } from './OpenCtiSettings'

vi.mock('../api', async (original) => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), patch: vi.fn(), post: vi.fn() }))
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockResolvedValue({ configured: true, url: 'https://cti.example', ingester_id: 'ingester-a', token_hint: '…1234', sample_uploads: false, external_file_uploads: false })
  vi.mocked(patch).mockResolvedValue({})
  vi.mocked(post).mockResolvedValue({ ok: true, version: '6.8', connectors: [], warnings: [] })
})

it('never retrieves a full token or tests a connection implicitly', async () => {
  renderWithProviders(<OpenCtiSettings />)
  const token = await screen.findByLabelText(/Integration token/)
  expect(token).toHaveValue('')
  expect(screen.getByText('Stored token: …1234. Leave empty to keep it.')).toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
  fireEvent.change(screen.getByLabelText('TAXII push ingester ID'), { target: { value: 'ingester-b' } })
  expect(screen.getByRole('button', { name: 'Test saved connection' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/opencti/settings', { url: 'https://cti.example', ingester_id: 'ingester-b', sample_uploads: false }))
})

it('clears a stored token only when explicitly selected', async () => {
  renderWithProviders(<OpenCtiSettings />)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Remove stored token' }))
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/opencti/settings', expect.objectContaining({ token: '' })))
  expect(post).not.toHaveBeenCalled()
})

it('tests the saved connection on click and shows automatic connector warnings', async () => {
  vi.mocked(post).mockResolvedValue({ ok: true, version: '6.8', connectors: [{ id: 'vt', name: 'VirusTotal', scope: ['StixFile'], auto: true, active: true }], warnings: ['Set enrichment connectors to manual before transfer.'] })
  renderWithProviders(<OpenCtiSettings />)
  fireEvent.click(await screen.findByRole('button', { name: 'Test saved connection' }))
  expect(await screen.findByText('Set enrichment connectors to manual before transfer.')).toBeInTheDocument()
  expect(post).toHaveBeenCalledWith('/api/opencti/test', {})
  expect(patch).not.toHaveBeenCalled()
})
