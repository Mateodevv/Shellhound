import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../api'
import { renderWithProviders } from '../test/setup'
import { EnrichmentBanners } from './SetupBanners'
import { GeoBanner } from './GeoBanner'

vi.mock('../api', () => ({ api: vi.fn(), post: vi.fn() }))
beforeEach(() => { vi.clearAllMocks(); localStorage.clear() })

it('shows missing keys before consent, hides configured services and opens settings', async () => {
  vi.mocked(api).mockResolvedValue({ enrichment_ack: false, services: {
    virustotal: { configured: false, sends: 'hash' },
    abuseipdb: { configured: true, sends: 'ip' },
  } })
  const settings = vi.fn()
  renderWithProviders(<EnrichmentBanners onOpenSettings={settings} />)
  expect(await screen.findByText('No VirusTotal key.')).toBeInTheDocument()
  expect(screen.queryByText('No AbuseIPDB key.')).not.toBeInTheDocument()
  expect(screen.getByText(/review the lookup permission/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Settings' }))
  expect(settings).toHaveBeenCalledOnce()
  fireEvent.click(screen.getByRole('button', { name: 'Dismiss No VirusTotal key.' }))
  expect(screen.queryByText('No VirusTotal key.')).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})

it('shows no reminder when all keys are configured', async () => {
  vi.mocked(api).mockResolvedValue({ enrichment_ack: true, services: {
    virustotal: { configured: true }, abuseipdb: { configured: true },
  } })
  renderWithProviders(<EnrichmentBanners />)
  await waitFor(() => expect(api).toHaveBeenCalledOnce())
  expect(screen.queryByText(/No .* key/)).not.toBeInTheDocument()
})

it('shows missing GeoIP data and disappears when refreshed after installation', async () => {
  vi.mocked(post).mockResolvedValue({ available: false, source: '', why: '' })
  const { qc } = renderWithProviders(<GeoBanner />)
  expect(await screen.findByText('No country database.')).toBeInTheDocument()
  expect(post).toHaveBeenCalledWith('/api/geo', { ips: [] })
  vi.mocked(post).mockResolvedValue({ available: true, source: 'DB-IP', why: '' })
  await qc.invalidateQueries({ queryKey: ['geo-status'] })
  await waitFor(() => expect(screen.queryByText('No country database.')).not.toBeInTheDocument())
})
