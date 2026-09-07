import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { api, post, patch, type CaseInfo, type Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { IocBox } from '../views/IocBox'
import { OpenCtiDetails, OpenCtiToolbar } from './OpenCti'
import { OpenCtiExportDialog } from './OpenCtiExport'
import { CaseProfileForm } from './CaseProfile'
import { initialExportOptions, type OpenCtiPreview } from '../opencti'

vi.mock('../api', async (original) => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), post: vi.fn(), patch: vi.fn() }))
const file: Ioc = { id: 1, type: 'path', value: 'web/shell.php', note: '', tags: [], origin: '', added: '', first_seen: null, last_seen: null, links: [{ id: 2, kind: 'hash-of', type: 'hash', value: 'a'.repeat(64), label: 'has the SHA-256', note: '' }] }
const hash: Ioc = { ...file, id: 2, type: 'hash', value: 'a'.repeat(64), links: [{ id: 1, kind: 'hash-of', type: 'path', value: file.value, label: 'is the SHA-256 of', note: '' }] }
const preview: OpenCtiPreview = { preview_id: 'preview-1', case_reference: 'PIM-5165', fingerprint: 'fp', objects: [{ id: 'file--a', type: 'file', name: 'shell.php' }], iocs: [{ id: 1, value: file.value, type: 'path', selected: true, object_ids: ['file--a'], indicator_supported: false, indicator_suggested: false, warnings: [] }, { id: 2, value: hash.value, type: 'hash', selected: true, object_ids: ['file--a'], indicator_supported: true, indicator_suggested: true, warnings: [] }], relationships: [{ id: 4, src_id: 2, dst_id: 1, kind: 'hash-of', note: '', selected: true }], samples: [{ id: 'sample-1', display_path: 'web/shell.php', sha256: hash.value, size: 20, selected: false, available: true, reason: '', file_id: 'file--a' }], warnings: [], errors: [] }
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/opencti/settings') return { configured: true, url: 'https://cti.example', ingester_id: 'ingester' } as never
    if (path.endsWith('/iocs/cross-case')) return { entries: [], matched_iocs: 0, cases_skipped: 0 } as never
    if (path.endsWith('/iocs')) return [file, hash] as never
    if (path === '/api/organizations') return [{ id: 'org-1', name: 'Organization-abc123' }] as never
    return { lookups: [], exports: [], sync: [], jobs: [] } as never
  })
  vi.mocked(post).mockResolvedValue({ job_id: 1 })
})

describe('OpenCTI user intent', () => {
  it('checks the complete IOC selection, including collapsed hashes, only after a click', async () => {
    renderWithProviders(<IocBox slug="case" gotoView={() => {}} />)
    const check = await screen.findByRole('button', { name: 'Check in OpenCTI' })
    await waitFor(() => expect(check).toBeEnabled())
    expect(screen.queryByRole('checkbox', { name: `Select ${hash.value} for OpenCTI` })).not.toBeInTheDocument()
    expect(screen.getByText(/2 IoCs selected, including collapsed/)).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(check)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/lookup', { ioc_ids: [1, 2] }))
  })
  it('can clear then select an individual IOC without silently adding descendants', async () => {
    renderWithProviders(<IocBox slug="case" gotoView={() => {}} />)
    await screen.findByRole('checkbox', { name: `Select ${file.value} for OpenCTI` })
    fireEvent.click(screen.getByRole('button', { name: 'Clear selection' }))
    expect(screen.getByRole('button', { name: 'Check in OpenCTI' })).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox', { name: `Select ${file.value} for OpenCTI` }))
    fireEvent.click(screen.getByRole('button', { name: 'Check in OpenCTI' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/lookup', { ioc_ids: [1] }))
  })
  it('requires explicit connector choice and missing-observable creation before enrichment', async () => {
    vi.mocked(post).mockImplementation(async (path) => path.endsWith('/enrichment/preview') ? {
      entities: [{ ioc_id: 2, id: null, value: hash.value, type: 'hash', requires_creation: true }],
      connectors: [{ id: 'vt', name: 'VirusTotal', scope: ['File'], active: true, auto: false }], warnings: [],
    } as never : { job_id: 1 } as never)
    renderWithProviders(<OpenCtiToolbar slug="case" iocs={[hash]} selectedIds={[2]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    const enrich = screen.getByRole('button', { name: 'Enrich via OpenCTI' })
    await waitFor(() => expect(enrich).toBeEnabled())
    fireEvent.click(enrich)
    const run = await screen.findByRole('button', { name: 'Run selected connectors' })
    expect(run).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox', { name: /VirusTotal/ }))
    expect(run).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox', { name: /Create the listed missing observables/ }))
    fireEvent.click(run)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/enrich', { ioc_ids: [2], connector_ids: ['vt'], create_missing: true }))
  })
  it('refreshes persisted connector work only on demand, even when work is still pending', async () => {
    vi.mocked(api).mockImplementation(async (path) => path === '/api/opencti/settings' ? { configured: true } as never : {
      lookups: [], exports: [], sync: [], jobs: [], enrichments: [{ id: 'request-1', ioc_id: 2, connector_id: 'connector-1', work_id: 'work-1', state: 'pending', updated: '2026-09-07' }],
    } as never)
    renderWithProviders(<OpenCtiToolbar slug="case" iocs={[hash]} selectedIds={[2]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    const refresh = await screen.findByRole('button', { name: 'Refresh enrichment status' })
    expect(screen.getByText('pending')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(refresh)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/enrichment/status', {}))
  })
})

describe('reviewed transfer', () => {
  it('shows batch outcomes and existing work IDs for a partial transfer', async () => {
    vi.mocked(api).mockImplementation(async (path) => path === '/api/opencti/settings' ? { configured: true } as never : {
      lookups: [], sync: [], jobs: [], exports: [{ id: 'export-partial', state: 'partial', created: '2026-09-07', updated: '2026-09-07', stats: {
        batches: [{ state: 'failed', ids: ['file--1', 'note--2'], work_id: 'existing-work-42', status: { success_count: 1, failure_count: 1, pending_count: 0 } }],
        descriptions: [{ source_id: 'ip-1', state: 'complete' }, { source_id: 'old-artifact', state: 'unavailable', error: 'Previous artifact no longer visible; no reupload.' }],
      } }],
    } as never)
    renderWithProviders(<OpenCtiToolbar slug="case" iocs={[hash]} selectedIds={[2]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    fireEvent.click(await screen.findByText('Transfer history'))
    fireEvent.click(screen.getByText('Transfer details'))
    expect(screen.getByText('1 imported · 1 failed · 0 pending')).toBeInTheDocument()
    expect(screen.getByText('existing-work-42')).toBeInTheDocument()
    expect(screen.getByText('Observable descriptions: 1 of 2 updated')).toBeInTheDocument()
    expect(screen.getByText('Previous artifact no longer visible; no reupload.')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })
  it.each(['pending', 'paused'])('can resume an existing %s transfer without creating another preview', async (state) => {
    vi.mocked(api).mockImplementation(async (path) => path === '/api/opencti/settings' ? { configured: true } as never : {
      lookups: [], sync: [], jobs: [], exports: [{ id: 'export-1', state, created: '2026-09-07', updated: '2026-09-07', stats: {} }],
    } as never)
    renderWithProviders(<OpenCtiToolbar slug="case" iocs={[hash]} selectedIds={[2]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    await screen.findByText('Transfer history')
    fireEvent.click(screen.getByText('Transfer history'))
    fireEvent.click(screen.getByRole('button', { name: 'Retry incomplete transfer' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/retry', { export_id: 'export-1' }))
    expect(post).toHaveBeenCalledTimes(1)
  })
  it('can exclude case notes while retaining individually selected IOC notes', async () => {
    vi.mocked(post).mockResolvedValue(preview)
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={preview} initialOptions={initialExportOptions([1, 2])} onClose={() => {}} onQueued={() => {}} />)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Include analyst notes' }))
    fireEvent.click(screen.getByText('Included case context'))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Case notes (when analyst notes are included)' }))
    fireEvent.click(screen.getByRole('button', { name: 'Update preview' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/preview', expect.objectContaining({ include_notes: true, exclude_profile_fields: ['case_notes'], exclude_note_ioc_ids: [] })))
  })
  it('keeps samples and Indicators unselected and requires updated preview after a change', async () => {
    vi.mocked(post).mockResolvedValue({ ...preview, preview_id: 'preview-2' })
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={preview} initialOptions={initialExportOptions([1, 2])} onClose={() => {}} onQueued={() => {}} />)
    const submit = screen.getByRole('button', { name: 'Transfer reviewed preview' })
    expect(screen.getByRole('checkbox', { name: /Create Indicator/ })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: /web\/shell.php ·/ })).not.toBeChecked()
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('checkbox', { name: /Create Indicator/ }))
    expect(submit).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Update preview' }))
    await waitFor(() => expect(submit).toBeEnabled())
    expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/preview', expect.objectContaining({ indicator_ids: [2], sample_ids: [], include_notes: false, include_evidence: false }))
    fireEvent.click(submit)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/export', { preview_id: 'preview-2' }))
  })
  it('blocks transfer for missing Case ID or unresolved preview errors', () => {
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={{ ...preview, case_reference: '', errors: ['Case ID required'] }} initialOptions={initialExportOptions([1, 2])} onClose={() => {}} onQueued={() => {}} />)
    expect(screen.getByRole('alert')).toHaveTextContent('Case ID required')
    expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeDisabled()
    expect(post).not.toHaveBeenCalled()
  })
  it('shows stored provenance and stale/own-only status without implying a clean verdict', () => {
    renderWithProviders(<OpenCtiDetails lookup={{ ioc_id: 2, status: 'own', checked_at: '2026-09-01', stale: true, entities: [{ id: 'file', type: 'File', name: hash.value, url: 'javascript:alert(1)', labels: [], sources: [{ name: 'Shellhound PIM-5165' }], reports: [{ name: 'PIM-5165' }], malware: [], relationships: [] }] }} />)
    expect(screen.getByText('Own exports only')).toBeInTheDocument()
    expect(screen.getByText('Stale result')).toBeInTheDocument()
    expect(screen.getByText('Shellhound PIM-5165')).toBeInTheDocument()
    expect(screen.getByText(/No match does not mean harmless/)).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open in OpenCTI' })).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })
})

it('uses generated or existing pseudonyms and validates incident dates', async () => {
  const info = { slug: 'case', reference: '', name: 'local', notes: '', dir: '', created: '' } as CaseInfo
  renderWithProviders(<CaseProfileForm slug="case" info={info} onClose={() => {}} />)
  expect(await screen.findByRole('option', { name: 'Organization-abc123' })).toBeInTheDocument()
  expect(screen.queryByRole('textbox', { name: /customer name/i })).not.toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Incident start'), { target: { value: '2026-09-07' } })
  fireEvent.change(screen.getByLabelText('Incident end'), { target: { value: '2026-09-01' } })
  expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  expect(patch).not.toHaveBeenCalled()
  fireEvent.change(screen.getByLabelText('Incident end'), { target: { value: '2026-09-08' } })
  fireEvent.change(screen.getByLabelText(/Affected organization pseudonym/), { target: { value: 'org-1' } })
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/case', expect.objectContaining({ profile: expect.objectContaining({ organization_id: 'org-1', marking: 'TLP:AMBER+STRICT' }) })))
})
