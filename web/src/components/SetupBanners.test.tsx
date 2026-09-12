import { screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { post } from '../api'
import { renderWithProviders } from '../test/setup'
import { GeoBanner } from './GeoBanner'

vi.mock('../api', () => ({ api: vi.fn(), post: vi.fn() }))
beforeEach(() => { vi.clearAllMocks(); localStorage.clear() })

it('shows missing GeoIP data and disappears when refreshed after installation', async () => {
  vi.mocked(post).mockResolvedValue({ available: false, source: '', why: '' })
  const { qc } = renderWithProviders(<GeoBanner />)
  expect(await screen.findByText('No country database.')).toBeInTheDocument()
  expect(post).toHaveBeenCalledWith('/api/geo', { ips: [] })
  vi.mocked(post).mockResolvedValue({ available: true, source: 'DB-IP', why: '' })
  await qc.invalidateQueries({ queryKey: ['geo-status'] })
  await waitFor(() => expect(screen.queryByText('No country database.')).not.toBeInTheDocument())
})
