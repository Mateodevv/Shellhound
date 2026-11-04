import { fireEvent, screen, waitFor } from '@testing-library/react'
import { expect, it, vi } from 'vitest'
import { api, patch, type CaseInfo } from '../../api'
import { newCaseProfile } from '../../opencti'
import { renderWithProviders } from '../../test/setup'
import { CaseProfileForm } from './CaseProfile'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), patch: vi.fn() }))

it('saves manually entered software and CVE context locally with the reviewed revision', async () => {
  vi.mocked(api).mockResolvedValue({ sectors: ['Healthcare'] })
  vi.mocked(patch).mockResolvedValue({})
  const onClose = vi.fn()
  const info = { name: 'Manual case', reference: 'MANUAL-1', profile_revision: 'reviewed-revision', profile: newCaseProfile() } as CaseInfo
  renderWithProviders(<CaseProfileForm slug="manual" info={info} onClose={onClose} />)
  fireEvent.click(screen.getByRole('button', { name: 'Add software' }))
  fireEvent.change(screen.getByLabelText('Software name'), { target: { value: 'Manual CMS' } })
  fireEvent.change(screen.getByLabelText('Software version'), { target: { value: '1.2' } })
  fireEvent.click(screen.getByRole('button', { name: 'Add CVE' }))
  fireEvent.change(screen.getByLabelText('CVE identifier'), { target: { value: 'CVE-2026-12345' } })
  fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Manually recorded context' } })
  expect(patch).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/manual', expect.objectContaining({
    expected_profile_revision: 'reviewed-revision',
    profile: expect.objectContaining({ software: [{ name: 'Manual CMS', version: '1.2' }],
      vulnerabilities: [{ name: 'CVE-2026-12345', status: 'suspected', description: 'Manually recorded context' }] }),
  })))
  await waitFor(() => expect(onClose).toHaveBeenCalledOnce())
})
