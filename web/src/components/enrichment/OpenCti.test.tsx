import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post, type Ioc, type CaseInfo } from '../../api'
import { newCaseProfile, type OpenCtiPreview } from '../../opencti'
import { renderWithProviders } from '../../test/setup'
import { OpenCtiToolbar } from './OpenCti'
import { OpenCtiExportDialog } from './OpenCtiExport'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
const info = { slug: 'qa', reference: 'QA-1', name: 'Manual case', profile_revision: 'r1', profile: { ...newCaseProfile(), organization_name: 'Manual organisation', sectors: ['Healthcare'] } } as CaseInfo
const preview: OpenCtiPreview = { preview_id: 'reviewed', case_reference: 'QA-1', fingerprint: 'fp', objects: [], errors: [], warnings: [],
  iocs: [{ id: 1, type: 'ip', value: '198.51.100.4', selected: true, object_ids: ['ipv4-addr--ip'], tags: ['manual-tag'], warnings: [] }] }
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { configured: true } : info)
  vi.mocked(post).mockImplementation(async path => path.endsWith('/preview') ? preview : { job_id: 7, export_id: 'receipt' })
})

it('offers only explicit transfer and filters unsupported selected types', async () => {
  const iocs = [{ id: 1, type: 'ip', value: '198.51.100.4' }, { id: 2, type: 'domain', value: 'example.invalid' }] as Ioc[]
  renderWithProviders(<OpenCtiToolbar slug="qa" iocs={iocs} selectedIds={[1, 2]} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Transfer to OpenCTI' }))
  expect(await screen.findByRole('dialog')).toBeVisible()
  expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/preview', { ioc_ids: [1] })
  expect(screen.queryByRole('button', { name: /Check in OpenCTI|Enrich via OpenCTI/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('checkbox', { name: /Indicator|sample/ })).not.toBeInTheDocument()
  expect(screen.getByText('manual-tag')).toBeVisible()
  expect(vi.mocked(post).mock.calls.every(([path]) => path.endsWith('/preview'))).toBe(true)
  const confirm = screen.getByRole('button', { name: 'Transfer reviewed preview' })
  await waitFor(() => expect(confirm).toBeEnabled())
  fireEvent.click(confirm)
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/export', { preview_id: 'reviewed' }))
})

it('allows profile-only transfers and blocks previews containing errors', async () => {
  const onQueued = vi.fn()
  const { unmount } = renderWithProviders(<OpenCtiExportDialog slug="qa" caseInfo={info} initial={{ ...preview, iocs: [] }} initialOptions={{ ioc_ids: [] }} onClose={vi.fn()} onQueued={onQueued} />)
  const confirm = await screen.findByRole('button', { name: 'Transfer reviewed preview' })
  await waitFor(() => expect(confirm).toBeEnabled())
  fireEvent.click(confirm)
  await waitFor(() => expect(onQueued).toHaveBeenCalledWith({ job_id: 7, export_id: 'receipt' }))
  unmount()
  renderWithProviders(<OpenCtiExportDialog slug="qa" caseInfo={info} initial={{ ...preview, errors: ['Review required'] }} initialOptions={{ ioc_ids: [1] }} onClose={vi.fn()} onQueued={onQueued} />)
  expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeDisabled()
  expect(screen.getByRole('alert')).toHaveTextContent('Review required')
})
