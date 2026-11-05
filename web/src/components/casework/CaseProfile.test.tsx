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
