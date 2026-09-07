import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../api'
import { renderWithProviders } from '../test/setup'
import { EnrichmentBanners } from './SetupBanners'
import { GeoBanner } from './GeoBanner'

vi.mock('../api', () => ({ api: vi.fn(), post: vi.fn() }))
beforeEach(() => { vi.clearAllMocks(); localStorage.clear() })

it('shows one OpenCTI setup reminder without starting any connection or enrichment', async () => {
  vi.mocked(api).mockResolvedValue({ configured: false })
  const settings = vi.fn()
  renderWithProviders(<EnrichmentBanners onOpenSettings={settings} />)
  expect(await screen.findByText('OpenCTI is not configured.')).toBeInTheDocument()
  expect(screen.queryByText(/VirusTotal|AbuseIPDB/)).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole('button', { name: 'Settings' }))
  expect(settings).toHaveBeenCalledOnce()
  fireEvent.click(screen.getByRole('button', { name: 'Dismiss OpenCTI is not configured.' }))
  expect(screen.queryByText('OpenCTI is not configured.')).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})

it('shows no reminder when OpenCTI is configured', async () => {
  vi.mocked(api).mockResolvedValue({ configured: true })
  renderWithProviders(<EnrichmentBanners />)
  await waitFor(() => expect(api).toHaveBeenCalledOnce())
  expect(screen.queryByText('OpenCTI is not configured.')).not.toBeInTheDocument()
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
