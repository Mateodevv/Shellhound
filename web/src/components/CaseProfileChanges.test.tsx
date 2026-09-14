import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, patch, type CaseInfo } from '../api'
import { newCaseProfile, type CaseProfileChanges as Changes } from '../opencti'
import { renderWithProviders } from '../test/setup'
import { CaseProfileChanges } from './CaseProfileChanges'
import { CaseProfileForm } from './CaseProfile'

vi.mock('../api', async original => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), patch: vi.fn() }))
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/profile/geography') return { countries: [], states: {} }
    if (path === '/api/opencti/sectors') return { sectors: [] }
    if (path === '/api/organizations') return []
    return { configured: false }
  })
  vi.mocked(patch).mockResolvedValue({})
})
const changed: Changes = { status: 'changed', export_id: 'first', exported_at: '2026-09-12T10:00:00', entries: [
  { field: 'summary', before: ['Original description'], after: ['Corrected description'], included: true },
  { field: 'city', before: ['Berlin'], after: [], included: false },
] }
it('shows changed fields in before/after columns and distinguishes exclusions', () => {
  renderWithProviders(<CaseProfileChanges changes={changed} />)
  const row = screen.getByRole('row', { name: /Incident summary/ })
  expect(within(row).getByText('Original description')).toBeVisible()
  expect(within(row).getByText('Corrected description')).toBeVisible()
  expect(screen.getByText(/Excluded from this transfer/)).toBeVisible()
  expect(screen.queryByText('Not set')).not.toBeInTheDocument()
})
it.each([
  ['first_export', /First transfer to this destination/],
  ['unavailable', /did not store a comparable profile/],
  ['unchanged', /matches the last completed transfer/],
] as const)('explains the %s comparison state', (status, message) => {
  renderWithProviders(<CaseProfileChanges changes={{ ...changed, status, entries: [] }} />)
  expect(screen.getByText(message)).toBeVisible()
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
})
it('hides stale differences while a newer preview is being generated', () => {
  renderWithProviders(<CaseProfileChanges changes={changed} updating />)
  expect(screen.getByRole('status')).toBeVisible()
  expect(screen.queryByText('Original description')).not.toBeInTheDocument()
})
it('retains the editor revision across refetches and keeps a failed draft', async () => {
  const info = { slug: 'qa', name: 'Local name', reference: 'QA-1', reference_locked: true,
    profile_revision: 'revision-one', profile: newCaseProfile() } as CaseInfo
  const onClose = vi.fn()
  const view = renderWithProviders(<CaseProfileForm slug="qa" info={info} onClose={onClose} />)
  expect(screen.getByLabelText('Case ID')).toHaveAttribute('readonly')
  fireEvent.change(screen.getByLabelText('Incident summary'), { target: { value: 'Unsaved correction' } })
  view.rerender(<CaseProfileForm slug="qa" info={{ ...info, profile_revision: 'revision-two' }} onClose={onClose} />)
  vi.mocked(patch).mockRejectedValue(new Error('Profile changed in another editor'))
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/qa', expect.objectContaining({
    expected_profile_revision: 'revision-one', name: 'Local name', profile: expect.objectContaining({ summary: 'Unsaved correction' }),
  })))
  expect(await screen.findByRole('alert')).toHaveTextContent('Profile changed in another editor')
  expect(screen.getByLabelText('Incident summary')).toHaveValue('Unsaved correction')
  expect(onClose).not.toHaveBeenCalled()
})
