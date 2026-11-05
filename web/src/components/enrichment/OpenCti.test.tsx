import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post, type Ioc, type CaseInfo } from '../../api'
import { newCaseProfile, type OpenCtiPreview } from '../../opencti'
import { renderWithProviders } from '../../test/setup'
import { OpenCtiToolbar } from './OpenCti'
import { OpenCtiExportDialog } from './OpenCtiExport'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
const info = { slug: 'qa', reference: 'QA-1', name: 'Manual case', profile_revision: 'r1', profile: { ...newCaseProfile(), organization_name: 'Manual organisation', sectors: ['Healthcare'] } } as CaseInfo
const preview: OpenCtiPreview = { preview_id: 'reviewed', case_reference: 'QA-1', fingerprint: 'fp', objects: [], errors: [], warnings: [],
  profile: { ...newCaseProfile(), ...info.profile }, target: { url: 'https://cti.example.test', ingester_id: 'collection' }, counts: { ips: 1, cves: 0, hashes: 0 }, redacted: false, already_exported: null,
  iocs: [{ id: 1, type: 'ip', value: '198.51.100.4', selected: true, object_ids: ['ipv4-addr--ip'], tags: ['manual-tag'], warnings: [] }] }
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { configured: true } : info)
  vi.mocked(post).mockImplementation(async path => path.endsWith('/preview') ? preview : { job_id: 7, export_id: 'receipt' })
})

it('shows the sanitized reviewed profile, destination and TLP without exposing raw profile text', async () => {
  renderWithProviders(<OpenCtiExportDialog slug="qa" caseInfo={info} initial={{ ...preview, profile: { ...preview.profile, organization_name: '[local path]', summary: 'password=[redacted]' }, redacted: true }} initialOptions={{ ioc_ids: [1] }} onClose={vi.fn()} onQueued={vi.fn()} />)
  expect(await screen.findByText('password=[redacted]')).toBeVisible()
  expect(screen.queryByText('Manual organisation')).not.toBeInTheDocument()
  expect(screen.getByText(/Destination: https:\/\/cti.example.test/)).toHaveTextContent('TLP:AMBER+STRICT')
  expect(screen.getByText(/Local paths and credentials were removed/)).toBeVisible()
})

it('blocks an unchanged completed export while allowing a fresh selection', async () => {
  renderWithProviders(<OpenCtiExportDialog slug="qa" caseInfo={info} initial={{ ...preview, already_exported: { id: 'previous', updated: '', case_url: 'https://cti.example.test/dashboard/id/case' } }} initialOptions={{ ioc_ids: [1] }} onClose={vi.fn()} onQueued={vi.fn()} />)
  expect(await screen.findByText(/Already transferred successfully/)).toBeVisible()
  const confirm = screen.getByRole('button', { name: 'Transfer reviewed preview' })
  expect(confirm).toBeDisabled()
  expect(screen.getByRole('link', { name: 'Open case in OpenCTI' })).toHaveAttribute('href', 'https://cti.example.test/dashboard/id/case')
  expect(post).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select 198.51.100.4' }))
  await waitFor(() => expect(confirm).toBeEnabled())
  expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/preview', { ioc_ids: [] })
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

it('groups IPs, CVEs and hash-only files while retaining every selection', async () => {
  const iocs = [
    { ...preview.iocs[0], id: 4, type: 'file', value: 'b'.repeat(64) },
    { ...preview.iocs[0], id: 2, type: 'vulnerability', value: 'CVE-2026-12345' },
    { ...preview.iocs[0], id: 3, type: 'hash', value: 'a'.repeat(64) },
    preview.iocs[0],
  ]
  renderWithProviders(<OpenCtiExportDialog slug="qa" caseInfo={info} initial={{ ...preview, iocs, profile: { ...preview.profile, summary: 'Reviewed incident summary' } }} initialOptions={{ ioc_ids: [1, 2, 3, 4] }} onClose={vi.fn()} onQueued={vi.fn()} />)
  expect(await screen.findByRole('heading', { level: 2, name: 'Manual organisation' })).toBeVisible()
  expect(screen.getByRole('heading', { name: 'Incident summary' })).toBeVisible()
  expect(screen.getByText('Reviewed incident summary')).toBeVisible()
  const groups = screen.getAllByRole('rowgroup').filter(group => group.hasAttribute('aria-label'))
  expect(groups.map(group => group.getAttribute('aria-label'))).toEqual(['IP addresses', 'CVEs', 'Hashes'])
  expect(within(groups[0]).getByRole('checkbox', { name: 'Select 198.51.100.4' })).toBeChecked()
  expect(within(groups[1]).getByRole('checkbox', { name: 'Select CVE-2026-12345' })).toBeChecked()
  expect(within(groups[2]).getAllByRole('checkbox')).toHaveLength(2)
  expect(screen.queryByRole('columnheader', { name: 'Type' })).not.toBeInTheDocument()
  fireEvent.click(within(groups[2]).getByRole('checkbox', { name: `Select ${'b'.repeat(64)}` }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/preview', { ioc_ids: [1, 2, 3] }))
})
