import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../api'
import { renderWithProviders } from '../test/setup'
import { Start } from '../views/Start'

vi.mock('../geo', () => ({ useGeoStatus: () => ({ data: { available: true } }) }))
vi.mock('../api', async original => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), post: vi.fn() }))
let configured: boolean
beforeEach(() => {
  vi.clearAllMocks(); configured = true
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/opencti/settings') return { configured }
    if (path === '/api/state') return { workspace: 'Synthetic workspace', cases: [] }
    if (path === '/api/archives') return { archives: [] }
    if (path === '/api/organizations') return [{ id: 'org-1', name: 'Organization-0123456789ab' }]
    if (path === '/api/profile/geography') return { countries: [{ code: 'DE', name: 'Germany' }, { code: 'AT', name: 'Austria' }], states: { DE: [{ code: 'DE-BE', name: 'Berlin' }], AT: [{ code: 'AT-9', name: 'Wien' }] } }
    if (path === '/api/opencti/sectors') return { sectors: [
      { id: 's1', name: 'Technology', parents: [], subsector: false },
      { id: 's2', name: 'Manufacturing', parents: [], subsector: false },
      { id: 's3', name: 'Software', parents: ['Technology'], subsector: true },
    ], stale: false }
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
  await screen.findByRole('option', { name: 'Technology' })
  fireEvent.change(screen.getByLabelText('Organisation name *'), { target: { value: 'Synthetic Research GmbH' } })
  fireEvent.change(screen.getByLabelText('Sectors *'), { target: { value: 'Technology' } })
  fireEvent.change(screen.getByLabelText('Sectors *'), { target: { value: 'Manufacturing' } })
  fireEvent.change(screen.getByLabelText('Subsectors'), { target: { value: JSON.stringify({ name: 'Software', sector: 'Technology' }) } })
  fireEvent.change(screen.getByLabelText('Country *'), { target: { value: 'DE' } })
  fireEvent.change(screen.getByLabelText('State'), { target: { value: 'DE-BE' } })
  fireEvent.change(screen.getByLabelText('City'), { target: { value: 'Berlin' } })
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
  expect(screen.getByText('Technology', { selector: 'span' })).toBeVisible()
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
      organization_id: '', organization_name: 'Synthetic Research GmbH', pseudonym: '', state: 'DE-BE', city: 'Berlin', subsectors: [{ name: 'Software', sector: 'Technology' }], summary: 'Investigation of suspicious requests',
      sectors: ['Technology', 'Manufacturing'], countries: ['DE'], first_seen: '2026-09-01', last_seen: '2026-09-08',
      marking: 'TLP:AMBER+STRICT', software: [{ name: 'Joomla', version: '5.2' }],
      vulnerabilities: [{ name: 'CVE-2026-12345', status: 'confirmed', description: 'Verified by the incident response team' }],
    },
  })
})

it('resets dependent locations and validates chronology and requires context for vulnerabilities without a CVE', async () => {
  await open(); fillCase(); await fillAffected()
  fireEvent.change(screen.getByLabelText('Country *'), { target: { value: '' } })
  expect(screen.getByLabelText('State')).toHaveValue('')
  expect(screen.getByLabelText('City')).toHaveValue('')
  expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Country *'), { target: { value: 'DE' } })
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


it('keeps custom sectors local until export and saves a new subsector with its parent', async () => {
  await open(); fillCase()
  await screen.findByRole('option', { name: 'Technology' })
  expect(screen.getByRole('button', { name: 'New subsector' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Organisation name *'), { target: { value: 'Synthetic organization' } })
  fireEvent.change(screen.getByLabelText('Country *'), { target: { value: 'DE' } })
  fireEvent.click(screen.getByRole('button', { name: 'New sector' }))
  expect(screen.getByRole('button', { name: 'Add to case' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Sector name'), { target: { value: '  Custom Industry  ' } })
  fireEvent.keyDown(screen.getByLabelText('Sector name'), { key: 'Enter' })
  expect(screen.getByRole('heading', { name: 'Affected organization' })).toBeVisible()
  expect(screen.getByText('Custom Industry', { selector: 'span' })).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'New subsector' }))
  expect(screen.getByLabelText('Parent sector')).toHaveValue('Custom Industry')
  fireEvent.change(screen.getByLabelText('Subsector name'), { target: { value: 'Custom specialization' } })
  fireEvent.click(screen.getByRole('button', { name: 'Add to case' }))
  expect(screen.getByText('Custom specialization', { selector: 'span' })).toBeVisible()
  expect(post).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  fireEvent.click(screen.getByRole('button', { name: 'Next' }))
  fireEvent.click(screen.getByRole('button', { name: 'Create case' }))
  await waitFor(() => expect(post).toHaveBeenCalledOnce())
  expect(post).toHaveBeenCalledWith('/api/cases', expect.objectContaining({ profile: expect.objectContaining({
    sectors: ['Custom Industry'], subsectors: [{ name: 'Custom specialization', sector: 'Custom Industry' }],
  }) }))
})

it('reuses matching names and prevents conflicting subsector identities', async () => {
  await open(); fillCase(); await fillAffected()
  fireEvent.click(screen.getByRole('button', { name: 'New sector' }))
  fireEvent.change(screen.getByLabelText('Sector name'), { target: { value: 'technology' } })
  fireEvent.click(screen.getByRole('button', { name: 'Add to case' }))
  expect(screen.getAllByRole('button', { name: 'Remove tag Technology' })).toHaveLength(1)
  fireEvent.click(screen.getByRole('button', { name: 'New subsector' }))
  expect(screen.getByLabelText('Parent sector')).toHaveValue('')
  fireEvent.change(screen.getByLabelText('Subsector name'), { target: { value: 'Technology' } })
  expect(screen.getByRole('button', { name: 'Add to case' })).toBeDisabled()
  fireEvent.change(screen.getByLabelText('Parent sector'), { target: { value: 'Manufacturing' } })
  fireEvent.click(screen.getByRole('button', { name: 'Add to case' }))
  expect(screen.getByRole('alert')).toHaveTextContent('already belongs')
  fireEvent.click(within(screen.getByRole('group', { name: 'New subsector' })).getByRole('button', { name: 'Cancel' }))
  fireEvent.click(screen.getByRole('button', { name: 'Remove tag Technology' }))
  expect(screen.queryByRole('button', { name: 'Remove tag Software' })).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})
