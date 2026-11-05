import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { CaseWizard } from './CaseWizard'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
let configured = true
beforeEach(() => {
  vi.clearAllMocks(); configured = true
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/opencti/settings') return { configured }
    if (path === '/api/profile/sectors') return { sectors: ['Technology', 'Healthcare'] }
    throw new Error(`Unexpected profile lookup: ${path}`)
  })
  vi.mocked(post).mockResolvedValue({ slug: 'manual', name: 'Manual case' })
})

it('saves manually entered profile values and uses only the local sector catalogue', async () => {
  renderWithProviders(<CaseWizard onClose={vi.fn()} onCreated={vi.fn()} />)
  fireEvent.change(await screen.findByLabelText('Case name *'), { target: { value: 'Manual case' } })
  fireEvent.change(screen.getByLabelText('Case ID *'), { target: { value: 'MANUAL-1' } })
  fireEvent.change(screen.getByLabelText('Incident summary *'), { target: { value: 'Manual summary' } })
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Organisation name *'), { target: { value: 'Manual organisation' } })
  fireEvent.click(screen.getByText('Main sectors (0) *'))
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Healthcare' }))
  fireEvent.change(screen.getByLabelText('Country *'), { target: { value: 'DE, AT' } })
  fireEvent.change(screen.getByLabelText('State'), { target: { value: 'Manual region' } })
  fireEvent.change(screen.getByLabelText('City'), { target: { value: 'Manual city' } })
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(post).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Create case' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases', expect.objectContaining({ profile: expect.objectContaining({ organization_name: 'Manual organisation', sectors: ['Healthcare'], countries: ['DE', 'AT'], state: 'Manual region', city: 'Manual city' }) })))
  expect(vi.mocked(api).mock.calls.every(([path]) => ['/api/opencti/settings', '/api/profile/sectors'].includes(path))).toBe(true)
})

it('also exposes manual profile fields when OpenCTI is not configured', async () => {
  configured = false
  renderWithProviders(<CaseWizard onClose={vi.fn()} onCreated={vi.fn()} />)
  fireEvent.change(await screen.findByLabelText('Case name *'), { target: { value: 'Local case' } })
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(screen.getByLabelText('Organisation name')).toBeVisible()
  fireEvent.click(screen.getByText('Main sectors (0)'))
  expect(await screen.findByRole('checkbox', { name: 'Healthcare' })).toBeVisible()
  expect(post).not.toHaveBeenCalled()
})
