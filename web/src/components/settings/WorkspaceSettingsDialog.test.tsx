import { fireEvent, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { Start } from '../../views/Start'
import { THEME_KEY } from '../../theme'
import { WorkspaceSettingsDialog } from './WorkspaceSettingsDialog'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
beforeEach(() => {
  vi.clearAllMocks()
  localStorage.setItem(THEME_KEY, 'synthwave')
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/state') return { workspace: 'Synthetic', cases: [] }
    if (path === '/api/archives') return { archives: [] }
    if (path === '/api/opencti/settings') return { configured: false, url: '', token_hint: '', ingester_id: '', sample_uploads: false }
    throw new Error(`Unexpected API: ${path}`)
  })
  vi.mocked(post).mockResolvedValue({ available: false, source: '', why: '' })
})
afterEach(() => { localStorage.removeItem(THEME_KEY); delete document.documentElement.dataset.theme })

it('groups settings, persists theme choices and retains OpenCTI drafts across tabs', async () => {
  renderWithProviders(<Start onOpen={() => {}} />)
  expect(screen.queryByRole('button', { name: 'OpenCTI settings' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Theme' })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Settings' }))
  expect(screen.getByRole('tab', { name: 'Themes' })).toHaveAttribute('aria-selected', 'true')
  fireEvent.click(screen.getByRole('radio', { name: 'Shellhound' }))
  expect(localStorage.getItem(THEME_KEY)).toBe('shellhound')
  expect(document.documentElement.dataset.theme).toBe('shellhound')
  fireEvent.click(screen.getByRole('tab', { name: 'OpenCTI' }))
  fireEvent.change(await screen.findByLabelText('OpenCTI URL'), { target: { value: 'https://draft.example' } })
  fireEvent.click(screen.getByRole('tab', { name: 'Themes' }))
  fireEvent.click(screen.getByRole('tab', { name: 'OpenCTI' }))
  expect(screen.getByLabelText('OpenCTI URL')).toHaveValue('https://draft.example')
  expect(vi.mocked(post).mock.calls.every(([path]) => path === '/api/geo')).toBe(true)
})

it('opens the existing GeoIP download flow only after an explicit click', async () => {
  renderWithProviders(<Start onOpen={() => {}} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Set up GeoIP' }))
  expect(screen.getByRole('tab', { name: 'GeoIP' })).toHaveAttribute('aria-selected', 'true')
  fireEvent.click(await screen.findByRole('button', { name: 'Fetch database…' }))
  expect(post).toHaveBeenCalledExactlyOnceWith('/api/geo', { ips: [] })
  vi.mocked(post).mockResolvedValue({ available: true, source: 'Synthetic database', size: 1, month: '2026-09' })
  fireEvent.click(screen.getByRole('button', { name: 'Fetch now' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/geo/download', {}))
  await waitFor(() => expect(screen.queryByText('GeoIP database is missing')).not.toBeInTheDocument())
})

it('persists the opt-in PHP detection mode and restores it when settings reopen', async () => {
  let enabled = false
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/settings') return { services: {}, indirect_php: enabled, enrichment_ack: false, path: '' }
    throw new Error(`Unexpected API: ${path}`)
  })
  vi.mocked(post).mockImplementation(async (_path, body) => {
    enabled = (body as { indirect_php: boolean }).indirect_php
    return { services: {}, indirect_php: enabled, enrichment_ack: false, path: '' }
  })
  const view = renderWithProviders(<WorkspaceSettingsDialog onClose={() => {}} initialTab="detection" />)
  const toggle = await screen.findByRole('checkbox', { name: 'Extended indirect PHP detection' })
  await waitFor(() => expect(toggle).toBeEnabled())
  expect(toggle).not.toBeChecked()
  fireEvent.click(toggle)
  await waitFor(() => expect(toggle).toBeChecked())
  expect(post).toHaveBeenCalledWith('/api/settings/detection', { indirect_php: true })
  view.unmount()
  renderWithProviders(<WorkspaceSettingsDialog onClose={() => {}} initialTab="detection" />)
  await waitFor(() => expect(screen.getByRole('checkbox')).toBeChecked())
  await waitFor(() => expect(screen.getByRole('checkbox')).toBeEnabled())
  fireEvent.click(screen.getByRole('checkbox'))
  await waitFor(() => expect(screen.getByRole('checkbox')).not.toBeChecked())
  expect(post).toHaveBeenCalledWith('/api/settings/detection', { indirect_php: false })
})

it('shows detection save errors without changing the saved mode', async () => {
  vi.mocked(api).mockResolvedValue({ services: {}, indirect_php: false })
  vi.mocked(post).mockRejectedValue(new Error('Synthetic save failure'))
  renderWithProviders(<WorkspaceSettingsDialog onClose={() => {}} initialTab="detection" />)
  const toggle = screen.getByRole('checkbox', { name: 'Extended indirect PHP detection' })
  await waitFor(() => expect(toggle).toBeEnabled())
  fireEvent.click(toggle)
  expect(await screen.findByText('Synthetic save failure')).toBeVisible()
  expect(toggle).not.toBeChecked()
})
