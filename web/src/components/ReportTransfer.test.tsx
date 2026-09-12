import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post, type CaseInfo, type Ioc, type Job } from '../api'
import { initialExportOptions, newCaseProfile, type OpenCtiPreview } from '../opencti'
import { renderWithProviders } from '../test/setup'
import { ReportTransfer } from './ReportTransfer'
import { OpenCtiExportDialog } from './OpenCtiExport'

vi.mock('../api', async original => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), post: vi.fn() }))
const info = { slug: 'qa', name: 'Example case', reference: 'QA-1', profile: { ...newCaseProfile(), summary: 'Investigated incident', organization_name: 'Example organization' } } as CaseInfo
const rows = [{ id: 1, type: 'file', value: 'sample.txt' }, { id: 2, type: 'hash', value: 'a'.repeat(64), file_ids: [1] }, { id: 3, type: 'ip', value: '198.51.100.4' }] as Ioc[]
const preview: OpenCtiPreview = { preview_id: 'first', case_reference: 'QA-1', fingerprint: 'fingerprint', objects: [{ id: 'file--sample', type: 'file' }, { id: 'indicator--sample', type: 'indicator' }],
 iocs: rows.map(row => ({ id: row.id, value: row.value, type: row.type, selected: true, object_ids: row.id < 3 ? ['file--sample'] : ['ipv4-addr--ip'], indicator_supported: true, indicator_suggested: row.id < 3, indicator_default: row.id < 3, warnings: [], tags: [] })),
 relationships: [{ id: 1, src_id: 1, dst_id: 3, kind: 'related-to', note: '', selected: true }],
 samples: [{ id: 'sample', display_path: 'sample.txt', sha256: 'a'.repeat(64), size: 12, selected: false, available: true, reason: '', file_id: 'file--sample' }], warnings: [], errors: [] }
let jobRows: Job[] = []
let configured = true
let exported = false
beforeEach(() => {
 vi.clearAllMocks(); jobRows = []; configured = true; exported = false
 vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { configured } : path.endsWith('/jobs') ? jobRows : path.endsWith('/summary') ? { artifacts: 2, findings: 3, confirmed: 2, iocs: 3, evidence: [] } : path.endsWith('/iocs') ? rows : { jobs: jobRows, exports: exported ? [{ id: 'export', state: 'complete', stats: { objects: 2 } }] : [], enrichments: [], sync: [], lookups: [] })
 vi.mocked(post).mockImplementation(async path => {
   if (path.endsWith('/preview')) return { ...preview, preview_id: 'latest' }
   if (path.endsWith('/export')) { exported = true; jobRows = [{ id: 9, kind: 'opencti-export', state: 'done', stats: { export_id: 'export' }, run_id: '', progress: 1, message: '', error: '', created: '2026-09-11' }] }
   return { job_id: 9, export_id: 'export' }
 })
})
const next = () => fireEvent.click(screen.getByRole('button', { name: 'Next' }))
it('runs selection, transfer result and closure in one wizard without dialogs or automatic archiving', async () => {
 const onClosed = vi.fn()
 renderWithProviders(<ReportTransfer slug="qa" caseInfo={info} onClosed={onClosed} />)
 expect(await screen.findByRole('navigation', { name: 'Transfer and close steps' })).toBeVisible()
 expect(screen.getByText('Example organization')).toBeVisible()
 expect(post).not.toHaveBeenCalled()
 next()
 await screen.findByRole('checkbox', { name: 'Create Indicator: sample.txt' })
 expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/preview', initialExportOptions([1, 2, 3]))
 expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
 expect(screen.queryByRole('button', { name: 'Transfer reviewed preview' })).not.toBeInTheDocument()
 expect(screen.getByRole('checkbox', { name: 'Create Indicator: sample.txt' })).toBeChecked()
 expect(screen.getByRole('checkbox', { name: `Create Indicator: ${rows[1].value}` })).not.toBeChecked()
 expect(screen.getByRole('checkbox', { name: 'Include evidence excerpts' })).toBeChecked()
 fireEvent.click(screen.getByRole('tab', { name: /^IPs/ }))
 fireEvent.click(screen.getByRole('checkbox', { name: 'Select 198.51.100.4' }))
 next()
 expect(screen.getByRole('checkbox', { name: 'Upload original sample: sample.txt' })).not.toBeChecked()
 fireEvent.click(screen.getByRole('button', { name: 'Back' }))
 expect(screen.getByRole('checkbox', { name: 'Select 198.51.100.4' })).not.toBeChecked()
 fireEvent.click(screen.getByRole('checkbox', { name: 'Create Indicator: sample.txt' }))
 next(); next()
 expect(screen.getByRole('region', { name: 'Review & transfer' })).toBeVisible()
 expect(vi.mocked(post).mock.calls.every(([path]) => path.endsWith('/preview'))).toBe(true)
 const transfer = screen.getByRole('button', { name: 'Transfer reviewed preview' })
 await waitFor(() => expect(transfer).toBeEnabled())
 expect(post).toHaveBeenLastCalledWith('/api/cases/qa/opencti/preview', expect.objectContaining({ ioc_ids: [1, 2], indicator_ids: [], sample_ids: [], exclude_relationship_ids: [] }))
 fireEvent.click(transfer)
 await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/export', { preview_id: 'latest' }))
 expect(await screen.findByRole('heading', { name: 'Transfer completed' })).toBeVisible()
 expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
 expect(vi.mocked(post).mock.calls.filter(([path]) => path.endsWith('/export'))).toHaveLength(1)
 expect(vi.mocked(post).mock.calls.some(([path]) => path.includes('/archive'))).toBe(false)
 next()
 const close = await screen.findByRole('button', { name: 'Close & archive case' })
 expect(close).toBeDisabled()
 fireEvent.change(screen.getByRole('textbox', { name: 'Case name to confirm archiving' }), { target: { value: info.name } })
 await waitFor(() => expect(close).toBeEnabled())
 fireEvent.click(close)
 await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/archive?require_idle=true', {}))
 expect(onClosed).toHaveBeenCalledOnce()
})
it('invalidates a reviewed preview when the case context changes', async () => {
 const options = { ...initialExportOptions([1, 2, 3]), indicator_ids: [1] }
 const props = { wizard: true, slug: 'qa', caseInfo: info, initial: preview, initialOptions: options, onClose: vi.fn(), onQueued: vi.fn() }
 const { rerender } = renderWithProviders(<OpenCtiExportDialog {...props} />)
 next(); next(); next()
 expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeEnabled()
 let resolve: (value: OpenCtiPreview) => void = () => {}
 vi.mocked(post).mockImplementation(() => new Promise(done => { resolve = done }))
 rerender(<OpenCtiExportDialog {...props} caseInfo={{ ...info, profile: { ...info.profile!, summary: 'Revised summary' } }} />)
 expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeDisabled()
 await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/preview', options))
 resolve({ ...preview, preview_id: 'revised-context' })
 await waitFor(() => expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeEnabled())
})
it('uses the same wizard for local closure when OpenCTI is not configured', async () => {
 configured = false
 const onExit = vi.fn()
 renderWithProviders(<ReportTransfer slug="qa" caseInfo={info} onExit={onExit} />)
 await screen.findByRole('navigation', { name: 'Transfer and close steps' })
 expect(screen.queryByRole('checkbox', { name: /Transfer to OpenCTI/ })).not.toBeInTheDocument()
 next()
 expect(await screen.findByRole('heading', { name: 'Close case' })).toBeVisible()
 fireEvent.click(screen.getByRole('button', { name: 'Finish and keep case open' }))
 expect(onExit).toHaveBeenCalledOnce()
 expect(post).not.toHaveBeenCalled()
 expect(vi.mocked(api).mock.calls.some(([path]) => path.endsWith('/opencti'))).toBe(false)
})
it('can skip transfer while retaining selection when returning to earlier steps', async () => {
 renderWithProviders(<ReportTransfer slug="qa" caseInfo={info} />)
 await screen.findByRole('navigation', { name: 'Transfer and close steps' }); next()
 await screen.findByRole('checkbox', { name: 'Create Indicator: sample.txt' })
 fireEvent.click(screen.getByRole('checkbox', { name: 'Select 198.51.100.4' }))
 fireEvent.click(screen.getByRole('button', { name: 'Skip transfer' }))
 expect(screen.getByRole('heading', { name: 'Close case' })).toBeVisible()
 fireEvent.click(screen.getByRole('button', { name: 'Back' }))
 fireEvent.click(screen.getByRole('button', { name: 'Back' }))
 fireEvent.click(screen.getByRole('button', { name: 'Back' }))
 expect(screen.getByRole('checkbox', { name: 'Select 198.51.100.4' })).not.toBeChecked()
 expect(vi.mocked(post).mock.calls.every(([path]) => path.endsWith('/preview'))).toBe(true)
})
it('resumes an active transfer and does not allow closure before its terminal result', async () => {
 jobRows = [{ id: 4, kind: 'opencti-export', state: 'running', progress: 0.5 } as Job]
 const { qc } = renderWithProviders(<ReportTransfer slug="qa" caseInfo={info} />)
 expect(await screen.findByRole('heading', { name: 'Transferring to OpenCTI' })).toBeVisible()
 expect(screen.getByRole('button', { name: 'Continue with incomplete transfer' })).toBeDisabled()
 expect(post).not.toHaveBeenCalled()
 jobRows = [{ ...jobRows[0], state: 'failed', error: 'Synthetic transfer failure' }]
 await qc.invalidateQueries({ queryKey: ['jobs', 'qa'] })
 expect(await screen.findByRole('heading', { name: 'Transfer incomplete' })).toBeVisible()
 expect(screen.getByText('Synthetic transfer failure')).toBeVisible()
 fireEvent.click(screen.getByRole('button', { name: 'Continue with incomplete transfer' }))
 expect(screen.getByRole('heading', { name: 'Close case' })).toBeVisible()
 expect(post).not.toHaveBeenCalled()
})
it('blocks archiving when a job starts after the closing screen was prepared', async () => {
 renderWithProviders(<ReportTransfer slug="qa" caseInfo={info} />)
 fireEvent.click(await screen.findByRole('checkbox', { name: /Transfer to OpenCTI before closing/ }))
 next()
 fireEvent.change(screen.getByRole('textbox', { name: 'Case name to confirm archiving' }), { target: { value: info.name } })
 const close = screen.getByRole('button', { name: 'Close & archive case' })
 await waitFor(() => expect(close).toBeEnabled())
 jobRows = [{ id: 6, kind: 'index_logs', state: 'running' } as Job]
 fireEvent.click(close)
 expect((await screen.findAllByText('Work is still running. Wait for it to finish before archiving the case.')).length).toBeGreaterThan(0)
 expect(post).not.toHaveBeenCalled()
})
it('blocks the final transfer on preview errors and keeps original file uploads opt-in', async () => {
 const options = { ...initialExportOptions([1, 2, 3]), indicator_ids: [1] }
 renderWithProviders(<OpenCtiExportDialog wizard slug="qa" initial={{ ...preview, errors: ['Review required'] }} initialOptions={options} caseInfo={info} onClose={() => {}} onQueued={() => {}} />)
 next(); next()
 expect(screen.getByRole('checkbox', { name: 'Upload original sample: sample.txt' })).not.toBeChecked()
 next()
 expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeDisabled()
 expect(within(screen.getByRole('alert')).getByText('Review required')).toBeVisible()
 expect(post).not.toHaveBeenCalled()
})
