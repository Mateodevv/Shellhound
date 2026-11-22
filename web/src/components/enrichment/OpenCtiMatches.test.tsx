import { fireEvent, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { api, post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { OpenCtiMatches } from './OpenCtiMatches'
vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
it('reads local cache until explicitly checked and displays visible cases', async () => {
  vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { lookup_configured: true, url: 'https://cti.example' } : { result: null })
  vi.mocked(post).mockResolvedValue({ kind: 'ip', value: '192.0.2.1', known: true, checked_at: '2026-01-01', truncated: true, cases: [{ id: '1', name: 'Visible case', url: 'https://cti.example/case/1' }] })
  renderWithProviders(<OpenCtiMatches slug="qa" kind="ip" value="192.0.2.1" />)
  expect(await screen.findByText('Check this value in cti.example.')).toBeVisible()
  expect(post).not.toHaveBeenCalled()
  await waitFor(() => expect(api).toHaveBeenCalledWith('/api/cases/qa/opencti/matches?kind=ip&value=192.0.2.1'))
  fireEvent.click(screen.getByRole('button', { name: 'Check OpenCTI' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/matches', { kind: 'ip', value: '192.0.2.1', expected_url: 'https://cti.example' }))
  expect(await screen.findByRole('link', { name: 'Visible case' })).toHaveAttribute('href', 'https://cti.example/case/1')
  expect(screen.getByText(/list is truncated/)).toBeVisible()
  expect(screen.getByText('Checked: 2026-01-01')).toBeVisible()
})
