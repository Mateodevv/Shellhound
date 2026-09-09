import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../api'
import { renderWithProviders } from '../test/setup'
import { Start } from '../views/Start'

vi.mock('../api', async original => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), post: vi.fn() }))
let configured: boolean
beforeEach(() => {
  vi.clearAllMocks(); configured = true
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/opencti/settings') return { configured }
    if (path === '/api/state') return { workspace: 'Synthetic workspace', cases: [] }
    if (path === '/api/archives') return { archives: [] }
    if (path === '/api/organizations') return [{ id: 'org-1', name: 'Organization-0123456789ab' }]
    throw new Error(`Unexpected API: ${path}`)
  })
  vi.mocked(post).mockResolvedValue({ slug: 'synthetic', name: 'Synthetic incident' })
})
async function open() {
  const onOpen = vi.fn()
  renderWithProviders(<Start onOpen={onOpen} />)
  fireEvent.click(screen.getByRole('button', { name: 'New case' }))
  await screen.findByRole('heading', { name: 'Case details' })
  return onOpen
}
function fillCase() {
  fireEvent.change(screen.getByLabelText('Case name *'), { target: { value: 'Synthetic incident' } })
  fireEvent.change(screen.getByLabelText('Case ID *'), { target: { value: 'PIM-5165' } })
  fireEvent.change(screen.getByLabelText('Incident summary *'), { target: { value: 'Investigation of suspicious requests' } })
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
}
async function fillAffected() {
  const org = await screen.findByRole('option', { name: 'Organization-0123456789ab' })
  fireEvent.change(org.parentElement!, { target: { value: 'org-1' } })
  fireEvent.change(screen.getByLabelText('Sectors (comma separated) *'), { target: { value: 'Technology, Manufacturing' } })
  fireEvent.change(screen.getByLabelText('Affected countries (ISO codes, comma separated) *'), { target: { value: 'DE, AT' } })
}

it('collects a granular profile, preserves back navigation and saves it in one explicit case request', async () => {
  const onOpen = await open()
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  fillCase()
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  await fillAffected()
  fireEvent.change(screen.getByLabelText('Incident start'), { target: { value: '2026-09-01' } })
  fireEvent.change(screen.getByLabelText('Incident end'), { target: { value: '2026-09-08' } })
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  const software = screen.getByRole('group', { name: 'Affected software' })
  fireEvent.click(within(software).getByRole('button', { name: 'Add' }))
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Software name'), { target: { value: 'Joomla' } })
  fireEvent.change(screen.getByLabelText('Version'), { target: { value: '5.2' } })
  const vulnerabilities = screen.getByRole('group', { name: 'Vulnerabilities' })
  fireEvent.click(within(vulnerabilities).getByRole('button', { name: 'Add' }))
  fireEvent.change(screen.getByLabelText('CVE or vulnerability name'), { target: { value: 'CVE-2026-12345' } })
  fireEvent.change(screen.getByRole('combobox', { name: 'Vulnerabilities' }), { target: { value: 'confirmed' } })
  fireEvent.change(screen.getByLabelText('Vulnerability context'), { target: { value: 'Verified by the incident response team' } })
  fireEvent.click(screen.getByRole('button', { name: 'Back' }))
  expect(screen.getByLabelText('Sectors (comma separated) *')).toHaveValue('Technology, Manufacturing')
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(screen.getByLabelText('Software name')).toHaveValue('Joomla')
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(screen.getByRole('heading', { name: 'Review' })).toBeVisible()
  expect(screen.getByText('Technology, Manufacturing')).toBeVisible()
  expect(screen.getByText('TLP:AMBER+STRICT', { selector: 'dd' })).toBeVisible()
  expect(post).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Create case' }))
  await waitFor(() => expect(onOpen).toHaveBeenCalledWith('synthetic'))
  expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases', {
    name: 'Synthetic incident', reference: 'PIM-5165', profile: {
      organization_id: 'org-1', pseudonym: 'Organization-0123456789ab', summary: 'Investigation of suspicious requests',
      sectors: ['Technology', 'Manufacturing'], countries: ['DE', 'AT'], first_seen: '2026-09-01', last_seen: '2026-09-08',
      marking: 'TLP:AMBER+STRICT', software: [{ name: 'Joomla', version: '5.2' }],
      vulnerabilities: [{ name: 'CVE-2026-12345', status: 'confirmed', description: 'Verified by the incident response team' }],
    },
  })
})

it('validates country codes and chronology and requires context for vulnerabilities without a CVE', async () => {
  await open(); fillCase(); await fillAffected()
  fireEvent.change(screen.getByLabelText('Affected countries (ISO codes, comma separated) *'), { target: { value: 'Germany' } })
  expect(screen.getByRole('alert')).toHaveTextContent('two-letter country codes')
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Affected countries (ISO codes, comma separated) *'), { target: { value: 'DE' } })
  fireEvent.change(screen.getByLabelText('Incident start'), { target: { value: '2026-09-08' } })
  fireEvent.change(screen.getByLabelText('Incident end'), { target: { value: '2026-09-01' } })
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Incident end'), { target: { value: '2026-09-09' } })
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  fireEvent.click(within(screen.getByRole('group', { name: 'Vulnerabilities' })).getByRole('button', { name: 'Add' }))
  fireEvent.change(screen.getByLabelText('CVE or vulnerability name'), { target: { value: 'Custom plugin flaw' } })
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Vulnerability context'), { target: { value: 'Unsafe file upload observed' } })
  expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled()
  expect(screen.getByRole('combobox', { name: 'Vulnerabilities' })).toHaveValue('suspected')
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
  expect(post).not.toHaveBeenCalled()
})

it('keeps local creation short when OpenCTI is not configured and retains inputs after a failed save', async () => {
  configured = false
  vi.mocked(post).mockRejectedValueOnce(new Error('Synthetic save error')).mockResolvedValueOnce({ slug: 'synthetic' })
  const onOpen = await open()
  expect(screen.queryByText('Affected organization')).not.toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Case name *'), { target: { value: 'Local case' } })
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  expect(screen.getByRole('heading', { name: 'Review' })).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Create case' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Synthetic save error')
  expect(onOpen).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Back' }))
  expect(screen.getByLabelText('Case name *')).toHaveValue('Local case')
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  fireEvent.click(screen.getByRole('button', { name: 'Create case' }))
  await waitFor(() => expect(onOpen).toHaveBeenCalledWith('synthetic'))
  expect(vi.mocked(post).mock.calls.every(([url]) => url === '/api/cases')).toBe(true)
  expect(vi.mocked(api).mock.calls.some(([url]) => url === '/api/organizations')).toBe(false)
})
