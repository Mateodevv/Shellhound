import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post, type CaseInfo, type Ioc, type Job } from '../../api'
import { newCaseProfile, type OpenCtiPreview } from '../../opencti'
import { renderWithProviders } from '../../test/setup'
import { ReportTransfer } from './ReportTransfer'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
const info = { slug: 'qa', name: 'Example case', reference: 'QA-1', profile_revision: 'r1', profile: { ...newCaseProfile(), summary: 'Manual summary', organization_name: 'Manual organisation' } } as CaseInfo
const rows = [{ id: 1, type: 'ip', value: '198.51.100.4' }, { id: 2, type: 'domain', value: 'example.invalid' }] as Ioc[]
const preview: OpenCtiPreview = { preview_id: 'reviewed', case_reference: 'QA-1', fingerprint: 'fp', objects: [], iocs: [{ id: 1, type: 'ip', value: rows[0].value, selected: true, object_ids: [], tags: [], warnings: [] }], warnings: [], errors: [] }
let jobRows: Job[] = []
let configured = true
let exported = false
beforeEach(() => {
  vi.clearAllMocks(); jobRows = []; configured = true; exported = false
  vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { configured } : path === '/api/cases/qa' ? info : path.endsWith('/jobs') ? jobRows : path.endsWith('/summary') ? { artifacts: 1, findings: 1, confirmed: 1, iocs: 2, evidence: [] } : path.endsWith('/iocs') ? rows : { jobs: jobRows, exports: exported ? [{ id: 'receipt', state: 'complete', stats: { objects: 2 } }] : [], sync: [] })
  vi.mocked(post).mockImplementation(async path => {
    if (path.endsWith('/preview')) return preview
    if (path.endsWith('/export')) { exported = true; jobRows = [{ id: 9, kind: 'opencti-export', state: 'done', stats: { export_id: 'receipt' }, run_id: '', progress: 1, message: '', error: '', created: '' }] }
    return { job_id: 9, export_id: 'receipt' }
  })
})

it('transfers only allowed IOCs after review and never archives automatically', async () => {
  renderWithProviders(<ReportTransfer slug="qa" caseInfo={info} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Next' }))
  expect(await screen.findByRole('checkbox', { name: 'Select 198.51.100.4' })).toBeVisible()
  expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/preview', { ioc_ids: [1] })
  const confirm = screen.getByRole('button', { name: 'Transfer reviewed preview' })
  await waitFor(() => expect(confirm).toBeEnabled())
  fireEvent.click(confirm)
  await screen.findByText('Transfer completed')
  expect(vi.mocked(post).mock.calls.some(([path]) => path.includes('/archive'))).toBe(false)
})

it('closes locally without OpenCTI calls and rechecks active work before archiving', async () => {
  configured = false
  const { qc } = renderWithProviders(<ReportTransfer slug="qa" caseInfo={info} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Next' }))
  await screen.findByRole('heading', { name: 'Close case' })
  fireEvent.change(screen.getByRole('textbox', { name: 'Case name to confirm archiving' }), { target: { value: info.name } })
  const archive = screen.getByRole('button', { name: 'Close & archive case' })
  await waitFor(() => expect(archive).toBeEnabled())
  jobRows = [{ id: 5, kind: 'webshell', state: 'running' } as Job]
  await qc.invalidateQueries({ queryKey: ['jobs', 'qa'] })
  await waitFor(() => expect(archive).toBeDisabled())
  expect(post).not.toHaveBeenCalled()
  expect(vi.mocked(api).mock.calls.some(([path]) => path.endsWith('/opencti'))).toBe(false)
})

it('resumes an active transfer without starting another one', async () => {
  jobRows = [{ id: 9, kind: 'opencti-export', state: 'running', progress: 0.5 } as Job]
  renderWithProviders(<ReportTransfer slug="qa" caseInfo={info} />)
  expect(await screen.findByRole('heading', { name: 'Transferring to OpenCTI' })).toBeVisible()
  expect(screen.getByRole('button', { name: 'Continue with incomplete transfer' })).toBeDisabled()
  expect(post).not.toHaveBeenCalled()
})
