import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, patch, type CaseInfo } from '../../api'
import { newCaseProfile } from '../../opencti'
import { renderWithProviders } from '../../test/setup'
import { CaseProfileForm } from './CaseProfile'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), patch: vi.fn() }))

beforeEach(() => vi.clearAllMocks())

it('edits the core profile while retaining hidden software and CVE data unchanged', async () => {
  vi.mocked(api).mockResolvedValue({ sectors: ['Healthcare'] })
  vi.mocked(patch).mockResolvedValue({})
  const onClose = vi.fn()
  const profile = { ...newCaseProfile(), software: [{ name: 'Saved CMS', version: '1.2' }],
    vulnerabilities: [{ name: 'CVE-2026-12345', status: 'suspected' as const, description: 'Saved context' }] }
  const info = { name: 'Manual case', reference: 'MANUAL-1', profile_revision: 'reviewed-revision', profile } as CaseInfo
  renderWithProviders(<CaseProfileForm slug="manual" info={info} onClose={onClose} />)
  expect(screen.queryByRole('button', { name: 'Add software' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Add CVE' })).not.toBeInTheDocument()
  expect(screen.queryByLabelText('CVE identifier')).not.toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Incident summary'), { target: { value: 'Edited summary' } })
  expect(patch).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/manual', expect.objectContaining({
    expected_profile_revision: 'reviewed-revision', profile: { ...profile, summary: 'Edited summary' },
  })))
  await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
})

it('restricts new subsectors under their sector without repeating parent selectors', async () => {
  vi.mocked(api).mockResolvedValue({ sectors: ['Healthcare', 'Technology'], subsectors: { Healthcare: ['Hospitals'], Technology: ['Software'] } })
  vi.mocked(patch).mockResolvedValue({})
  const profile = { ...newCaseProfile(), sectors: ['Healthcare', 'Technology'],
    subsectors: [{ name: 'Saved clinic', sector: 'Healthcare' }] }
  const info = { name: 'Saved case', reference: 'KEEP-1', profile_revision: 'r1', profile } as CaseInfo
  renderWithProviders(<CaseProfileForm slug="saved" info={info} onClose={vi.fn()} />)
  expect(screen.queryByLabelText('Parent sector')).not.toBeInTheDocument()
  expect(screen.getByText('Main sectors (2)').closest('details')).not.toHaveAttribute('open')
  expect(within(screen.getByRole('group', { name: 'Healthcare' })).getByRole('combobox')).toHaveValue('Saved clinic')
  expect(within(screen.getByRole('group', { name: 'Healthcare' })).queryByRole('option', { name: 'Software' })).not.toBeInTheDocument()
  const add = within(screen.getByRole('group', { name: 'Technology' })).getByRole('button', { name: 'New subsector' })
  await waitFor(() => expect(add).toBeEnabled())
  fireEvent.click(add)
  fireEvent.change(screen.getByRole('combobox', { name: 'Subsector in Technology' }), { target: { value: 'Software' } })
  expect(add).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/saved', expect.objectContaining({
    profile: { ...profile, subsectors: [{ name: 'Saved clinic', sector: 'Healthcare' }, { name: 'Software', sector: 'Technology' }] },
  })))
})

it('restores and edits all company and incident fields without inferring missing outcomes', async () => {
  vi.mocked(api).mockResolvedValue({ sectors: [], subsectors: {}, context_options: {
    employee_count: ['unknown', '10-49', '50-249'], hosting_model: ['unknown', 'managed_hosting'], hosting_providers: ['Synthetic Cloud'],
    it_operating_model: ['unknown', 'external'], initial_access: ['unknown', 'software_vulnerability'],
    initial_access_status: ['unknown', 'suspected', 'confirmed'], spread: ['web_application', 'web_server', 'other_servers'],
    data_exfiltration: ['unknown', 'not_investigated', 'not_observed', 'suspected', 'confirmed'],
    attacker_encryption: ['unknown', 'not_investigated', 'not_observed', 'suspected', 'confirmed'],
    discovered_by: ['unknown', 'soc_mdr'], discovery_method: ['unknown', 'monitoring'],
  } })
  vi.mocked(patch).mockResolvedValue({})
  const profile = { ...newCaseProfile(), employee_count: '10-49', hosting_providers: ['Saved Hosting'], initial_cve: 'CVE-2025-12345' }
  const info = { name: 'Context case', reference: 'CONTEXT-1', profile_revision: 'r1', profile } as CaseInfo
  renderWithProviders(<CaseProfileForm slug="context" info={info} onClose={vi.fn()} />)
  expect(screen.getByRole('combobox', { name: 'Company size (employees)' })).toHaveValue('10-49')
  expect(screen.getByText('Saved Hosting')).toBeVisible()
  expect(screen.getByRole('combobox', { name: 'Hosting / cloud providers' })).toHaveValue('')
  expect(screen.getByRole('combobox', { name: 'Data exfiltration' })).toHaveValue('unknown')
  expect(screen.getByRole('combobox', { name: 'Encryption by attackers' })).toHaveValue('unknown')
  expect(screen.getByRole('combobox', { name: 'Initial access assessment' })).toBeDisabled()
  const initialCve = screen.getByRole('textbox', { name: 'Initial CVE' })
  expect(initialCve).toHaveValue('CVE-2025-12345')
  fireEvent.change(initialCve, { target: { value: 'cve-2026-123' } })
  expect(initialCve).toBeInvalid()
  fireEvent.change(initialCve, { target: { value: ' cve-2026-12345 ' } })
  expect(initialCve).toHaveValue('CVE-2026-12345')
  expect(initialCve).toBeValid()
  await screen.findByRole('option', { name: 'Managed hosting' })
  for (const [label, value] of [
    ['Company size (employees)', '50-249'], ['Hosting model of the affected system', 'managed_hosting'],
    ['IT operating model', 'external'], ['Initial access route', 'software_vulnerability'],
    ['Initial access assessment', 'suspected'], ['Data exfiltration', 'not_observed'],
    ['Encryption by attackers', 'not_investigated'], ['Discovering party', 'soc_mdr'], ['Discovery method', 'monitoring'],
  ]) fireEvent.change(screen.getByRole('combobox', { name: label }), { target: { value } })
  fireEvent.change(screen.getByRole('combobox', { name: 'Hosting / cloud providers' }), { target: { value: 'Synthetic Cloud' } })
  expect(screen.getByRole('option', { name: 'Synthetic Cloud' })).toBeDisabled()
  fireEvent.click(screen.getByRole('checkbox', { name: 'Web server' }))
  fireEvent.click(screen.getByRole('checkbox', { name: 'Other servers' }))
  expect(patch).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/context', expect.objectContaining({ profile: {
    ...profile, employee_count: '50-249', hosting_model: 'managed_hosting', hosting_providers: ['Saved Hosting', 'Synthetic Cloud'],
    it_operating_model: 'external', initial_access: 'software_vulnerability', initial_access_status: 'suspected', initial_cve: 'CVE-2026-12345',
    spread: ['web_server', 'other_servers'], data_exfiltration: 'not_observed', attacker_encryption: 'not_investigated',
    discovered_by: 'soc_mdr', discovery_method: 'monitoring',
  } })))
})

it('keeps legacy providers and allows a custom provider without submitting the form', async () => {
  vi.mocked(api).mockResolvedValue({ sectors: [], context_options: { hosting_providers: ['Hetzner', 'Microsoft Azure'] } })
  vi.mocked(patch).mockResolvedValue({})
  const profile = { ...newCaseProfile(), hosting_providers: ['Saved local provider'] }
  const info = { name: 'Saved case', reference: 'KEEP-1', profile_revision: 'r1', profile } as CaseInfo
  renderWithProviders(<CaseProfileForm slug="saved" info={info} onClose={vi.fn()} />)
  await screen.findByRole('option', { name: 'Hetzner' })
  const providers = screen.getByRole('combobox', { name: 'Hosting / cloud providers' })
  fireEvent.change(providers, { target: { value: 'Hetzner' } })
  expect(screen.getByText('Saved local provider')).toBeVisible()
  expect(screen.getByRole('option', { name: 'Hetzner' })).toBeDisabled()
  fireEvent.change(providers, { target: { value: '__other__' } })
  const custom = screen.getByRole('textbox', { name: 'Other hosting / cloud provider' })
  fireEvent.change(custom, { target: { value: 'Custom Hosting' } })
  fireEvent.keyDown(custom, { key: 'Enter' })
  expect(patch).not.toHaveBeenCalled()
  expect(screen.getByText('Custom Hosting')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Remove provider Hetzner' }))
  expect(screen.getByRole('option', { name: 'Hetzner' })).toBeEnabled()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/saved', expect.objectContaining({
    profile: expect.objectContaining({ hosting_providers: ['Saved local provider', 'Custom Hosting'] }),
  })))
})

it('clears the access assessment when its route is reset to unknown', async () => {
  vi.mocked(api).mockResolvedValue({ sectors: [], context_options: {} })
  vi.mocked(patch).mockResolvedValue({})
  const profile = { ...newCaseProfile(), initial_access: 'phishing', initial_access_status: 'confirmed', initial_cve: 'CVE-2026-12345' }
  const info = { name: 'Saved case', reference: 'KEEP-1', profile_revision: 'r1', profile } as CaseInfo
  renderWithProviders(<CaseProfileForm slug="saved" info={info} onClose={vi.fn()} />)
  expect(screen.getByRole('combobox', { name: 'Initial access route' })).toHaveValue('phishing')
  fireEvent.change(screen.getByRole('combobox', { name: 'Initial access route' }), { target: { value: 'unknown' } })
  expect(screen.getByRole('combobox', { name: 'Initial access assessment' })).toHaveValue('unknown')
  expect(screen.getByRole('combobox', { name: 'Initial access assessment' })).toBeDisabled()
  const initialCve = screen.getByRole('textbox', { name: 'Initial CVE' })
  expect(initialCve).toHaveValue('CVE-2026-12345')
  fireEvent.change(initialCve, { target: { value: '' } })
  expect(initialCve).toBeValid()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/saved', expect.objectContaining({
    profile: expect.objectContaining({ initial_access: 'unknown', initial_access_status: 'unknown', initial_cve: '' }),
  })))
})
