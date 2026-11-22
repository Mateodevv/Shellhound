import { beforeEach, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { api, patch, post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { OpenCtiSettings } from './OpenCtiSettings'

vi.mock('../../api', async (original) => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), patch: vi.fn(), post: vi.fn() }))
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
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/opencti/settings', { url: 'https://cti.example', ingester_id: 'ingester-b' }))
})

it('clears a stored token only when explicitly selected', async () => {
  renderWithProviders(<OpenCtiSettings />)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Remove stored token' }))
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/opencti/settings', expect.objectContaining({ token: '' })))
  expect(post).not.toHaveBeenCalled()
})

it('tests only the saved export connection on explicit click', async () => {
  vi.mocked(post).mockResolvedValue({ ok: true, version: 'test-version' })
  renderWithProviders(<OpenCtiSettings />)
  fireEvent.click(await screen.findByRole('button', { name: 'Test saved connection' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/opencti/test', {}))
  expect(screen.queryByRole('checkbox', { name: /sample/i })).not.toBeInTheDocument()
  expect(patch).not.toHaveBeenCalled()
})


it('requires explicit activation and can turn it off without changing credentials', async () => {
  renderWithProviders(<OpenCtiSettings />)
  const option = await screen.findByRole('checkbox', { name: /Automatically send finding IPs and SHA-256 hashes to cti.example/ })
  expect(option).not.toBeChecked()
  fireEvent.click(option)
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/opencti/settings', { url: 'https://cti.example', ingester_id: 'ingester-a', auto_match: true }))
})

it('rechecks only the current case using the saved connection', async () => {
  vi.mocked(api).mockResolvedValue({ configured: true, lookup_configured: true, url: 'https://cti.example', ingester_id: 'ingester-a', token_hint: '…1234', auto_match: false })
  vi.mocked(post).mockResolvedValue({ job_id: 4 })
  renderWithProviders(<OpenCtiSettings slug="case-1" />)
  expect(await screen.findByText(/current case case-1/)).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Recheck all' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case-1/opencti/matches/recheck', { expected_url: 'https://cti.example' }))
  expect(await screen.findByText('Recheck queued.')).toBeVisible()
})

it('disables activation without credentials and omits case recheck on the start screen', async () => {
  vi.mocked(api).mockResolvedValue({ configured: false, lookup_configured: false, url: '', ingester_id: '', token_hint: '' })
  renderWithProviders(<OpenCtiSettings />)
  expect(await screen.findByRole('checkbox', { name: /Automatically send finding IPs/ })).toBeDisabled()
  expect(screen.queryByRole('button', { name: 'Recheck all' })).not.toBeInTheDocument()
})


it('requires renewed activation when changing the host and catches up the current case', async () => {
  vi.mocked(api).mockResolvedValue({ configured: true, lookup_configured: true, auto_match: true, url: 'https://old.example', ingester_id: 'ingester-a', token_hint: '…1234' })
  renderWithProviders(<OpenCtiSettings slug="case-1" />)
  const url = await screen.findByLabelText('OpenCTI URL')
  fireEvent.change(url, { target: { value: 'https://new.example' } })
  const option = screen.getByRole('checkbox', { name: /Automatically send finding IPs.*new.example/ })
  expect(option).not.toBeChecked()
  expect(option).toBeDisabled()
  fireEvent.change(screen.getByLabelText(/Integration token/), { target: { value: 'new-token' } })
  fireEvent.click(option)
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/opencti/settings', { url: 'https://new.example', ingester_id: 'ingester-a', token: 'new-token', auto_match: true, case_slug: 'case-1' }))
})


it('turns off automatic matching when removing the stored token', async () => {
  vi.mocked(api).mockResolvedValue({ configured: true, lookup_configured: true, auto_match: true, url: 'https://cti.example', ingester_id: 'ingester-a', token_hint: '…1234' })
  renderWithProviders(<OpenCtiSettings slug="case-1" />)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Remove stored token' }))
  expect(screen.getByRole('checkbox', { name: /Automatically send finding IPs/ })).not.toBeChecked()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/opencti/settings', { url: 'https://cti.example', ingester_id: 'ingester-a', token: '', auto_match: false }))
})


it('catches up the current case after rotating an active connection token', async () => {
  vi.mocked(api).mockResolvedValue({ configured: true, lookup_configured: true, auto_match: true, url: 'https://cti.example', ingester_id: 'ingester-a', token_hint: '…1234' })
  renderWithProviders(<OpenCtiSettings slug="case-1" />)
  fireEvent.change(await screen.findByLabelText(/Integration token/), { target: { value: 'rotated-token' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/opencti/settings', { url: 'https://cti.example', ingester_id: 'ingester-a', token: 'rotated-token', case_slug: 'case-1' }))
})
