import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { api, post, patch, type CaseInfo, type Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { IocBox } from '../views/IocBox'
import { OpenCtiDetails, OpenCtiToolbar } from './OpenCti'
import { OpenCtiActivity } from './OpenCtiActivity'
import { OpenCtiExportDialog } from './OpenCtiExport'
import { CaseProfileForm } from './CaseProfile'
import { initialExportOptions, type OpenCtiPreview } from '../opencti'

vi.mock('../api', async (original) => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), post: vi.fn(), patch: vi.fn() }))
vi.mock('../geo', () => ({ useGeo: () => null }))
const file: Ioc = { id: 1, type: 'path', value: 'web/shell.php', note: '', tags: [], origin: '', added: '', first_seen: null, last_seen: null, links: [{ id: 2, kind: 'hash-of', type: 'hash', value: 'a'.repeat(64), label: 'has the SHA-256', note: '' }] }
const hash: Ioc = { ...file, id: 2, type: 'hash', value: 'a'.repeat(64), links: [{ id: 1, kind: 'hash-of', type: 'path', value: file.value, label: 'is the SHA-256 of', note: '' }] }
const preview: OpenCtiPreview = { preview_id: 'preview-1', case_reference: 'PIM-5165', fingerprint: 'fp', objects: [{ id: 'file--a', type: 'file', name: 'shell.php' }], iocs: [{ id: 1, value: file.value, type: 'path', selected: true, object_ids: ['file--a'], indicator_supported: false, indicator_suggested: false, warnings: [] }, { id: 2, value: hash.value, type: 'hash', selected: true, object_ids: ['file--a'], indicator_supported: true, indicator_suggested: true, warnings: [] }], relationships: [{ id: 4, src_id: 2, dst_id: 1, kind: 'hash-of', note: '', selected: true }], samples: [{ id: 'sample-1', display_path: 'web/shell.php', sha256: hash.value, size: 20, selected: false, available: true, reason: '', file_id: 'file--a' }], warnings: [], errors: [] }
beforeEach(() => {
  vi.clearAllMocks()
  sessionStorage.clear()
  history.replaceState(null, '', '/')
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/opencti/settings') return { configured: true, url: 'https://cti.example', ingester_id: 'ingester' } as never
    if (path.endsWith('/iocs/cross-case')) return { entries: [], matched_iocs: 0, cases_skipped: 0 } as never
    if (path.endsWith('/iocs')) return [file, hash] as never
    if (path === '/api/organizations') return [{ id: 'org-1', name: 'Organization-abc123' }] as never
    if (path === '/api/opencti/sectors') return { sectors: [], stale: false } as never
    if (path === '/api/profile/geography') return { countries: [], states: {} } as never
    return { lookups: [], exports: [], sync: [], jobs: [] } as never
  })
  vi.mocked(post).mockResolvedValue({ job_id: 1 })
})

describe('OpenCTI user intent', () => {
  it('preselects one indicator per confirmed webshell and preserves an opt-out through preview updates', async () => {
    const initial = { ...preview, iocs: [
      ...preview.iocs.map(row => ({ ...row, indicator_supported: true, indicator_default: true })),
      { ...preview.iocs[1], id: 3, type: 'file', value: 'confirmed-file', indicator_default: true },
      { ...preview.iocs[1], id: 4, value: 'other-hash', object_ids: ['file--b'], indicator_default: false },
    ] }
    vi.mocked(post).mockImplementation(async path => path.endsWith('/preview') ? { ...initial, preview_id: 'updated' } : { job_id: 1 })
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={initial} initialOptions={initialExportOptions([1, 2, 3, 4])} onClose={() => {}} onQueued={() => {}} />)
    const checkbox = screen.getByRole('checkbox', { name: 'Create Indicator: confirmed-file' })
    expect(checkbox).toBeChecked()
    expect(screen.getByRole('checkbox', { name: `Create Indicator: ${hash.value}` })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Create Indicator: other-hash' })).not.toBeChecked()
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/preview', expect.objectContaining({ indicator_ids: [3], sample_ids: [] })))
    fireEvent.click(checkbox)
    await waitFor(() => expect(post).toHaveBeenLastCalledWith('/api/cases/case/opencti/preview', expect.objectContaining({ indicator_ids: [] })))
    expect(checkbox).not.toBeChecked()
    expect(vi.mocked(post).mock.calls.every(([url]) => url.endsWith('/preview'))).toBe(true)
  })
  it('enriches an unknown CVE only after creation approval and connector selection', async () => {
    const cve = { ...file, type: 'vulnerability', value: 'CVE-2026-12345' }
    vi.mocked(post).mockImplementation(async path => path.endsWith('/enrichment/preview') ? {
      entities: [{ ioc_id: 1, id: null, value: cve.value, type: 'vulnerability', requires_creation: true, requires_transfer: false }],
      connectors: [{ id: 'epss', name: 'FIRST EPSS', scope: ['vulnerability'], active: true, auto: false }], warnings: [],
    } : { job_id: 1 })
    renderWithProviders(<OpenCtiToolbar slug="case" iocs={[cve]} selectedIds={[1]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    const enrich = await screen.findByRole('button', { name: 'Enrich via OpenCTI' })
    await waitFor(() => expect(enrich).toBeEnabled())
    fireEvent.click(enrich)
    fireEvent.click(await screen.findByRole('tab', { name: /^CVEs/ }))
    expect(screen.getByText(cve.value)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Run selected connectors' })).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox', { name: /Create the listed missing objects/ }))
    expect(screen.getByRole('button', { name: 'Run selected connectors' })).toBeDisabled()
    expect(screen.queryByRole('tab', { name: 'Compatible connectors' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Choose connectors' })).toBeVisible()
    expect(screen.getByRole('checkbox', { name: 'FIRST EPSS' })).toBeVisible()
    fireEvent.click(screen.getByRole('checkbox', { name: 'FIRST EPSS' }))
    fireEvent.click(screen.getByRole('button', { name: 'Run selected connectors' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/enrich', { ioc_ids: [1], connector_ids: ['epss'], create_missing: true }))
  })

  it('uses category selection and the connector select-all for enrichment', async () => {
    vi.mocked(post).mockImplementation(async path => path.endsWith('/enrichment/preview') ? {
      entities: [{ ioc_id: 1, id: 'ip', value: '198.51.100.1', type: 'ip', requires_creation: false },
        { ioc_id: 2, id: null, value: hash.value, type: 'hash', requires_creation: true }],
      connectors: [{ id: 'one', name: 'First connector', scope: ['IPv4-Addr'], active: true, auto: false },
        { id: 'two', name: 'Second connector', scope: ['StixFile'], active: true, auto: false }], warnings: [],
    } : { job_id: 1 })
    renderWithProviders(<OpenCtiToolbar slug="case" iocs={[file, hash]} selectedIds={[1, 2]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    const enrich = await screen.findByRole('button', { name: 'Enrich via OpenCTI' })
    await waitFor(() => expect(enrich).toBeEnabled())
    fireEvent.click(enrich)
    fireEvent.click(await screen.findByRole('tab', { name: /^Hashes/ }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all: IoCs' }))
    expect(screen.queryByRole('checkbox', { name: /Create the listed/ })).not.toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'First connector' })).toBeVisible()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all: Compatible connectors' }))
    expect(screen.getByRole('checkbox', { name: 'First connector' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: 'Second connector' })).toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Run selected connectors' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/enrich', { ioc_ids: [1], connector_ids: ['one', 'two'], create_missing: false }))
  })

  it('checks the entire case despite pagination, filters, selection and folded file hashes', async () => {
    const caseIocs: Ioc[] = [
      { ...file, type: 'file', value: 'sample.php' }, { ...hash, file_ids: [1] },
      ...Array.from({ length: 55 }, (_, n) => ({ ...file, id: n + 3, type: 'ip', value: `198.51.100.${n + 1}` })),
    ]
    const original = vi.mocked(api).getMockImplementation()!
    vi.mocked(api).mockImplementation(async path => path.endsWith('/iocs') ? caseIocs as never : original(path))
    renderWithProviders(<IocBox slug="case" gotoView={() => {}} />)
    const menu = await screen.findByRole('button', { name: 'OpenCTI actions' })
    expect(screen.queryByRole('button', { name: 'Check all' })).not.toBeInTheDocument()
    await screen.findByRole('checkbox', { name: 'Select 198.51.100.55' })
    expect(within(screen.getByRole('list', { name: 'Object list' })).getAllByRole('listitem')).toHaveLength(50)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select 198.51.100.55' }))
    fireEvent.click(screen.getByRole('button', { name: /^IPs/ }))
    fireEvent.change(screen.getByPlaceholderText('Search objects…'), { target: { value: '198.51.100.1' } })
    expect(screen.queryByRole('button', { name: 'Open sample.php' })).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(menu)
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Check all' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/lookup', { ioc_ids: caseIocs.map(ioc => ioc.id) }))
    expect(menu).toHaveAttribute('aria-expanded', 'false')
    expect(post).toHaveBeenCalledTimes(1)
    expect(await screen.findByRole('status')).toHaveTextContent('Follow progress in Activity')
  })

  it.each(['Enrich all'])('%s opens a preview for all case entries without executing it', async label => {
    vi.mocked(post).mockResolvedValue(label === 'Transfer all' ? preview : { entities: [], connectors: [], warnings: [] })
    renderWithProviders(<OpenCtiToolbar mode="inline" grouped actionScope="case" slug="case" iocs={[file, hash]} selectedIds={[1]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    fireEvent.click(await screen.findByRole('button', { name: 'OpenCTI actions' }))
    const action = await screen.findByRole('button', { name: label })
    await waitFor(() => expect(action).toBeEnabled())
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(action)
    await screen.findByRole('dialog')
    expect(post).toHaveBeenCalledTimes(1)
    expect(post).toHaveBeenCalledWith(`/api/cases/case/opencti/${label === 'Transfer all' ? 'preview' : 'enrichment/preview'}`,
      label === 'Transfer all' ? initialExportOptions([1, 2]) : { ioc_ids: [1, 2] })
    if (label === 'Transfer all') {
      expect(screen.getByRole('checkbox', { name: /^Create Indicator:/ })).not.toBeChecked()
      fireEvent.click(screen.getByRole('tab', { name: /^Original samples \(optional\)/ }))
      expect(screen.getByRole('checkbox', { name: 'Upload original sample: web/shell.php' })).not.toBeChecked()
    } else {
      expect(screen.getByRole('button', { name: 'Run selected connectors' })).toBeDisabled()
    }
  })

  it('disables all case actions when the case has no IOC entries', async () => {
    renderWithProviders(<OpenCtiToolbar mode="inline" actionScope="case" slug="case" iocs={[]} selectedIds={[1]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    for (const label of ['Check all', 'Enrich all']) expect(await screen.findByRole('button', { name: label })).toBeDisabled()
    expect(post).not.toHaveBeenCalled()
  })

  it('shows inline action failures and makes the action available for a retry', async () => {
    vi.mocked(post).mockRejectedValue(new Error('Synthetic OpenCTI connection failure'))
    renderWithProviders(<OpenCtiToolbar mode="inline" actionScope="case" slug="case" iocs={[file]} selectedIds={[]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    const check = await screen.findByRole('button', { name: 'Check all' })
    await waitFor(() => expect(check).toBeEnabled())
    fireEvent.click(check)
    expect(await screen.findByRole('alert')).toHaveTextContent('Synthetic OpenCTI connection failure')
    expect(check).toBeEnabled()
    expect(post).toHaveBeenCalledTimes(1)
  })

  it('checks the complete IOC selection, including collapsed hashes, only after a click', async () => {
    renderWithProviders(<IocBox slug="case" gotoView={() => {}} />)
    await screen.findByRole('checkbox', { name: `Select ${file.value}` })
    fireEvent.click(screen.getByRole('button', { name: 'Select all filtered' }))
    const check = await screen.findByRole('button', { name: 'Check in OpenCTI' })
    await waitFor(() => expect(check).toBeEnabled())
    expect(screen.queryByRole('checkbox', { name: `Select ${hash.value} for OpenCTI` })).not.toBeInTheDocument()
    expect(screen.getByText('2 objects selected')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(check)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/lookup', { ioc_ids: expect.arrayContaining([1, 2]) }))
  })
  it('can clear then select an individual IOC without silently adding descendants', async () => {
    renderWithProviders(<IocBox slug="case" gotoView={() => {}} />)
    await screen.findByRole('checkbox', { name: `Select ${file.value}` })
    expect(screen.queryByRole('button', { name: 'Check in OpenCTI' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: `Select ${file.value}` }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Check in OpenCTI' })).toBeEnabled())
    fireEvent.click(screen.getByRole('button', { name: 'Check in OpenCTI' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/lookup', { ioc_ids: [1] }))
  })
  it('requires explicit connector choice and missing-observable creation before enrichment', async () => {
    vi.mocked(post).mockImplementation(async (path) => path.endsWith('/enrichment/preview') ? {
      entities: [{ ioc_id: 2, id: null, value: hash.value, type: 'hash', requires_creation: true }],
      connectors: [{ id: 'vt', name: 'VirusTotal', scope: ['File'], active: true, auto: false }], warnings: [],
    } as never : { job_id: 1 } as never)
    renderWithProviders(<OpenCtiToolbar slug="case" iocs={[hash]} selectedIds={[2]} onSelectAll={() => {}} onClear={() => {}} onSettings={() => {}} />)
    const enrich = await screen.findByRole('button', { name: 'Enrich via OpenCTI' })
    await waitFor(() => expect(enrich).toBeEnabled())
    fireEvent.click(enrich)
    const run = await screen.findByRole('button', { name: 'Run selected connectors' })
    expect(run).toBeDisabled()
    expect(screen.getByText('Select at least one connector to start enrichment.')).toBeVisible()
    fireEvent.click(screen.getByRole('checkbox', { name: /VirusTotal/ }))
    fireEvent.click(screen.getByRole('tab', { name: /^All/ }))
    expect(screen.getByText('Will be created with your approval')).toBeVisible()
    expect(screen.getByRole('checkbox', { name: /VirusTotal/ })).toBeVisible()
    expect(screen.getByRole('checkbox', { name: /VirusTotal/ })).toBeChecked()
    expect(run).toBeDisabled()
    fireEvent.click(screen.getByRole('checkbox', { name: /Create the listed missing objects/ }))
    fireEvent.click(run)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/enrich', { ioc_ids: [2], connector_ids: ['vt'], create_missing: true }))
  })
  it('refreshes persisted connector work only on demand, even when work is still pending', async () => {
    vi.mocked(api).mockImplementation(async (path) => path === '/api/opencti/settings' ? { configured: true } as never : {
      lookups: [], exports: [], sync: [], jobs: [], enrichments: [{ id: 'request-1', ioc_id: 2, connector_id: 'connector-1', work_id: 'work-1', state: 'pending', updated: '2026-09-07' }],
    } as never)
    renderWithProviders(<OpenCtiActivity slug="case" iocs={[hash]} allowRetry />)
    const refresh = await screen.findByRole('button', { name: 'Refresh enrichment status' })
    fireEvent.click(screen.getByRole('tab', { name: /Enrichment requests/ }))
    expect(await screen.findByText('Pending')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(refresh)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/enrichment/status', {}))
  })
})

describe('reviewed transfer', () => {
  it('ignores a late preview response after a newer selection has been prepared', async () => {
    let finishOld!: (value: OpenCtiPreview) => void
    vi.mocked(post).mockImplementationOnce(() => new Promise(resolve => { finishOld = resolve }))
      .mockResolvedValue({ ...preview, preview_id: 'latest-preview' })
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={preview} initialOptions={initialExportOptions([1, 2])} onClose={() => {}} onQueued={() => {}} />)
    expect(screen.queryByRole('button', { name: 'Update preview' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Include analyst notes' }))
    const transfer = screen.getByRole('button', { name: 'Transfer reviewed preview' })
    expect(transfer).toBeDisabled()
    await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Include evidence excerpts' }))
    await waitFor(() => expect(post).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(transfer).toBeEnabled())
    await act(async () => { finishOld({ ...preview, preview_id: 'outdated-preview' }) })
    fireEvent.click(transfer)
    await waitFor(() => expect(post).toHaveBeenLastCalledWith('/api/cases/case/opencti/export', { preview_id: 'latest-preview' }))
  })

  it('blocks transfer on a failed automatic refresh and permits an explicit retry', async () => {
    vi.mocked(post).mockRejectedValueOnce(new Error('Preview temporarily unavailable')).mockResolvedValue(preview)
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={preview} initialOptions={initialExportOptions([1, 2])} onClose={() => {}} onQueued={() => {}} />)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Include analyst notes' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Preview temporarily unavailable')
    expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeEnabled())
    expect(post).toHaveBeenCalledTimes(2)
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })

  it.each([
    ['Include analyst notes', 'Includes analyst notes attached to the selected IoCs'],
    ['Include evidence excerpts', 'Includes evidence excerpts from findings and recorded observations'],
  ])('explains %s on keyboard focus', async (name, description) => {
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={preview} initialOptions={initialExportOptions([1, 2])} onClose={() => {}} onQueued={() => {}} />)
    fireEvent.focus(screen.getByRole('checkbox', { name }).closest('label')!.nextElementSibling!)
    expect(await screen.findByRole('tooltip')).toHaveTextContent(description)
    expect(post).not.toHaveBeenCalled()
  })
  it('limits bulk column changes to the category and eligible rows, retaining other choices', async () => {
    const mixedPreview = { ...preview, iocs: [...preview.iocs,
      { ...preview.iocs[1], id: 3, type: 'ip', value: '198.51.100.3', indicator_supported: true },
      { ...preview.iocs[1], id: 4, type: 'ip', value: '198.51.100.4', indicator_supported: false },
    ] }
    vi.mocked(post).mockResolvedValue(mixedPreview)
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={mixedPreview} initialOptions={initialExportOptions([1, 2, 3, 4])} onClose={() => {}} onQueued={() => {}} />)
    fireEvent.click(screen.getByRole('tab', { name: /^IPs/ }))
    const selectAll = screen.getByRole('checkbox', { name: 'Select all: IoCs' })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select 198.51.100.4' }))
    expect(selectAll).toBePartiallyChecked()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all: Create Indicator' }))
    expect(screen.getByRole('checkbox', { name: 'Create Indicator: 198.51.100.3' })).toBeChecked()
    fireEvent.click(selectAll)
    expect(selectAll).toBeChecked()
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/preview', expect.objectContaining({ indicator_ids: [3], ioc_ids: [1, 2, 3, 4] })))
    fireEvent.click(screen.getByRole('tab', { name: /^Hashes/ }))
    expect(screen.getByRole('checkbox', { name: /^Create Indicator:/ })).not.toBeChecked()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all: IoCs' }))
    expect(screen.getByRole('checkbox', { name: 'Select all: Create Indicator' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeDisabled()
  })

  it('bulk-selects optional notes, excerpts and available samples only after explicit input', async () => {
    const samples = { ...preview, samples: [...preview.samples, { ...preview.samples[0], id: 'unavailable', display_path: 'missing.php', available: false }] }
    vi.mocked(post).mockResolvedValue(samples)
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={samples} initialOptions={initialExportOptions([1, 2])} onClose={() => {}} onQueued={() => {}} />)
    fireEvent.click(screen.getByRole('checkbox', { name: 'Include analyst notes' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all: Note' }))
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all: Evidence' }))
    fireEvent.click(screen.getByRole('tab', { name: /^Original samples \(optional\)/ }))
    expect(screen.getByRole('checkbox', { name: 'Select all: Original samples (optional)' })).not.toBeChecked()
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select all: Original samples (optional)' }))
    expect(screen.getByRole('checkbox', { name: /missing.php/ })).toBeDisabled()
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/preview', expect.objectContaining({ exclude_note_ioc_ids: [1, 2], exclude_evidence_ioc_ids: [1, 2], sample_ids: ['sample-1'] })))
  })

  it('shows batch outcomes and existing work IDs for a partial transfer', async () => {
    vi.mocked(api).mockImplementation(async (path) => path === '/api/opencti/settings' ? { configured: true } as never : {
      lookups: [], sync: [], jobs: [], exports: [{ id: 'export-partial', state: 'partial', created: '2026-09-07', updated: '2026-09-07', stats: {
        batches: [{ state: 'failed', ids: ['file--1', 'note--2'], work_id: 'existing-work-42', status: { success_count: 1, failure_count: 1, pending_count: 0 } }],
        descriptions: [{ source_id: 'ip-1', state: 'complete' }, { source_id: 'old-artifact', state: 'unavailable', error: 'Previous artifact no longer visible; no reupload.' }],
      } }],
    } as never)
    renderWithProviders(<OpenCtiActivity slug="case" iocs={[hash]} allowRetry />)
    fireEvent.click(await screen.findByText('Transfer history'))
    fireEvent.click(await screen.findByText('Transfer details'))
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
    renderWithProviders(<OpenCtiActivity slug="case" iocs={[hash]} allowRetry />)
    await screen.findByText('Transfer history')
    fireEvent.click(screen.getByText('Transfer history'))
    fireEvent.click(await screen.findByRole('button', { name: 'Retry incomplete transfer' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/retry', { export_id: 'export-1' }))
    expect(post).toHaveBeenCalledTimes(1)
  })
  it('always includes selected relationships and removes the three obsolete tabs', async () => {
    vi.mocked(post).mockResolvedValue(preview)
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={preview} initialOptions={{ ...initialExportOptions([1, 2]), exclude_relationship_ids: [4] }} onClose={() => {}} onQueued={() => {}} />)
    for (const name of ['Included case context', 'Relationships', 'Exact generated objects']) expect(screen.queryByRole('tab', { name })).not.toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /^Original samples/ })).toBeVisible()
    expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeDisabled()
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/preview', expect.objectContaining({ exclude_relationship_ids: [], sample_ids: [] })))
    await waitFor(() => expect(screen.getByRole('button', { name: 'Transfer reviewed preview' })).toBeEnabled())
  })
  it('keeps samples and Indicators unselected and automatically updates the preview after a change', async () => {
    vi.mocked(post).mockResolvedValue({ ...preview, preview_id: 'preview-2' })
    renderWithProviders(<OpenCtiExportDialog slug="case" initial={preview} initialOptions={initialExportOptions([1, 2])} onClose={() => {}} onQueued={() => {}} />)
    const submit = screen.getByRole('button', { name: 'Transfer reviewed preview' })
    expect(screen.getByRole('checkbox', { name: 'Include evidence excerpts' })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /^Create Indicator:/ })).not.toBeChecked()
    fireEvent.click(screen.getByRole('tab', { name: /^Original samples \(optional\)/ }))
    expect(screen.getByRole('checkbox', { name: 'Upload original sample: web/shell.php' })).not.toBeChecked()
    fireEvent.click(screen.getByRole('tab', { name: /^All/ }))
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('checkbox', { name: /^Create Indicator:/ }))
    expect(submit).toBeDisabled()
    await waitFor(() => expect(submit).toBeEnabled())
    expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/preview', expect.objectContaining({ indicator_ids: [2], sample_ids: [], include_notes: false, include_evidence: true }))
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
    expect(screen.queryByText('Benign')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open in OpenCTI' })).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })
})

it.each([
  { name: 'Organization-abc123', organizationId: 'org-1' },
  { name: 'Synthetic Research GmbH', organizationId: '' },
])('saves the chosen organisation name $name and validates incident dates', async ({ name, organizationId }) => {
  const info = { slug: 'case', reference: '', name: 'local', notes: '', dir: '', created: '' } as CaseInfo
  renderWithProviders(<CaseProfileForm slug="case" info={info} onClose={() => {}} />)
  await waitFor(() => expect(document.querySelector('datalist option[value="Organization-abc123"]')).toBeInTheDocument())
  expect(screen.queryByRole('button', { name: /Generate pseudonym/i })).not.toBeInTheDocument()
  fireEvent.change(screen.getByLabelText('Incident start'), { target: { value: '2026-09-07' } })
  fireEvent.change(screen.getByLabelText('Incident end'), { target: { value: '2026-09-01' } })
  expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  expect(patch).not.toHaveBeenCalled()
  fireEvent.change(screen.getByLabelText('Incident end'), { target: { value: '2026-09-08' } })
  fireEvent.change(screen.getByLabelText('Organisation name'), { target: { value: name } })
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(patch).toHaveBeenCalledWith('/api/cases/case', expect.objectContaining({ profile: expect.objectContaining({ organization_id: organizationId, organization_name: name, pseudonym: '', marking: 'TLP:AMBER+STRICT' }) })))
})
