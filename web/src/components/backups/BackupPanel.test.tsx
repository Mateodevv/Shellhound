import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, patch, post, type EvidenceItem } from '../../api'
import type { BackupHistoryData, BackupOverview, BackupSnapshot } from '../../backupApi'
import { renderWithProviders } from '../../test/setup'
import { BackupPanel } from './BackupPanel'

vi.mock('../../api', async original => ({
  ...(await original<typeof import('../../api')>()),
  api: vi.fn(), post: vi.fn(), patch: vi.fn(),
}))

const evidence: EvidenceItem[] = [
  { id: 31, kind: 'webroot', path: 'C:/Synthetic/Week one', label: 'First evidence copy',
    added: '', scanned_at: '', stats: {}, source_timezone: 'UTC', exists: true },
  { id: 32, kind: 'webroot', path: 'D:/Synthetic/Week two', label: 'Second evidence copy',
    added: '', scanned_at: '', stats: {}, source_timezone: 'UTC', exists: true },
]

function snapshot(id: number, index: number): BackupSnapshot {
  return { id, site_id: 7, evidence_id: evidence[index].id, root: evidence[index].path,
    label: index ? 'Later copy' : 'Earlier copy', captured_at: `2026-09-${index ? '17' : '10'}T12:00:00Z`,
    captured_epoch: null, timezone: 'UTC', completeness: 'complete', generation: `generation-${id}`,
    state: 'ready', available: true, stats: { files: 1, prepared: '2026-09-18T12:00:00Z' } }
}

let overview: BackupOverview
let historyData: BackupHistoryData
let failDiff = false

beforeEach(() => {
  window.history.replaceState(null, '', '/?case=backup-case&view=evidence')
  vi.resetAllMocks()
  failDiff = false
  overview = { sites: [{ id: 7, label: 'Example website', timezone: 'UTC' }],
    snapshots: [snapshot(11, 0), snapshot(22, 1)] }
  historyData = { site_id: 7, path: 'nested/example.txt', entries: overview.snapshots.map((copy, index) => ({
    snapshot: copy, status: 'present', available: true, stale: false, scan_state: 'not_analyzed',
    file: { relative_path: 'nested/example.txt', artifact: `${evidence[index].path}/nested/example.txt`,
      sha256: (index ? 'b' : 'a').repeat(64), size: 20, state: 'ready' },
  })) }
  vi.mocked(api).mockImplementation(async path => {
    const url = new URL(path, 'http://localhost')
    if (url.pathname === '/api/timezones') return { zones: ['UTC', 'Europe/Berlin', 'Asia/Tokyo'] }
    if (url.pathname === '/api/cases/backup-case/backups') return overview
    if (url.pathname.endsWith('/backups/compare')) return {
      snapshots: overview.snapshots, rows: [{ ...historyData, changed: true, suspicious: true }],
      prepared: true, total: 1,
    }
    if (url.pathname.endsWith('/backups/history')) return historyData
    if (url.pathname.endsWith('/backups/diff')) {
      if (failDiff) throw new Error('File content changed; refresh this backup before viewing the difference')
      return { sides: overview.snapshots.map(copy => ({ label: copy.label })), lines: [], truncated: false }
    }
    throw new Error(`Unexpected API call: ${path}`)
  })
  vi.mocked(post).mockImplementation(async path => {
    if (path.endsWith('/backups/preview-root')) return { paths: ['nested/example.txt'], more: false, warning: false }
    return { id: 33 }
  })
  vi.mocked(patch).mockResolvedValue({ id: 11 })
})

async function openHistory() {
  fireEvent.click(await screen.findByRole('button', { name: 'Compare backups' }))
  fireEvent.click(await screen.findByRole('button', { name: /nested\/example\.txt/ }))
  const dialog = await screen.findByRole('dialog', { name: 'Backup history' })
  await within(dialog).findByRole('combobox', { name: 'First backup' })
  return dialog
}

describe('website backup workflow', () => {
  it('previews relative paths and registers the chosen root, date, named zone and coverage', async () => {
    renderWithProviders(<BackupPanel slug="backup-case" evidence={evidence} />)
    const add = await screen.findByRole('button', { name: 'Add backup' })
    await waitFor(() => expect(add).toBeEnabled())
    fireEvent.click(add)
    const dialog = screen.getByRole('dialog', { name: 'Add backup' })
    fireEvent.change(within(dialog).getByRole('combobox', { name: 'Evidence source' }), { target: { value: '32' } })
    const root = within(dialog).getByRole('textbox', { name: 'Website root inside this evidence' })
    expect(root).toHaveValue('D:/Synthetic/Week two')
    fireEvent.change(root, { target: { value: 'D:/Synthetic/Week two/site' } })
    fireEvent.change(within(dialog).getByRole('textbox', { name: 'Backup name' }), { target: { value: 'Week two website' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Preview relative paths' }))
    expect(await within(dialog).findByText('nested/example.txt')).toBeInTheDocument()
    expect(post).toHaveBeenCalledWith('/api/cases/backup-case/backups/preview-root', {
      evidence_id: 32, root: 'D:/Synthetic/Week two/site',
    })
    expect(vi.mocked(post).mock.calls.some(([path]) => path.endsWith('/snapshots'))).toBe(false)
    fireEvent.change(within(dialog).getByRole('textbox', { name: 'Backup name' }), { target: { value: 'Week two website' } })
    fireEvent.change(within(dialog).getByRole('textbox', { name: 'Backup date (optional)' }), { target: { value: '2026-09-17T12:00:00' } })
    fireEvent.change(within(dialog).getByRole('combobox', { name: 'Backup coverage' }), { target: { value: 'partial' } })
    fireEvent.change(within(dialog).getByRole('combobox', { name: 'Website / backup time zone' }), { target: { value: 'custom' } })
    fireEvent.change(within(dialog).getByRole('combobox', { name: 'Choose time zone…' }), { target: { value: 'Asia/Tokyo' } })
    expect(within(dialog).getByText(/Recorded filesystem timestamps keep their original instant/)).toBeInTheDocument()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/backup-case/backups/snapshots', {
      site_id: 7, evidence_id: 32, root: 'D:/Synthetic/Week two/site', label: 'Week two website',
      captured_at: '2026-09-17T12:00:00', timezone: 'Asia/Tokyo', completeness: 'partial',
    }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Add backup' })).not.toBeInTheDocument())
  })

  it('keeps the selected history and backup pair in the URL and restores them on remount', async () => {
    const view = renderWithProviders(<BackupPanel slug="backup-case" evidence={evidence} />)
    const dialog = await openHistory()
    fireEvent.change(within(dialog).getByRole('combobox', { name: 'First backup' }), { target: { value: '22' } })
    fireEvent.change(within(dialog).getByRole('combobox', { name: 'Second backup' }), { target: { value: '11' } })
    await waitFor(() => {
      const params = new URLSearchParams(location.search)
      expect(params.get('backup_site')).toBe('7')
      expect(params.get('backup_path')).toBe('nested/example.txt')
      expect(params.get('backup_left')).toBe('22')
      expect(params.get('backup_right')).toBe('11')
      expect(params.get('case')).toBe('backup-case')
    })
    view.unmount()
    renderWithProviders(<BackupPanel slug="backup-case" evidence={evidence} />)
    const reopened = await screen.findByRole('dialog', { name: 'Backup history' })
    expect(await within(reopened).findByRole('combobox', { name: 'First backup' })).toHaveValue('22')
    expect(within(reopened).getByRole('combobox', { name: 'Second backup' })).toHaveValue('11')
    expect(within(reopened).getByText('nested/example.txt')).toBeInTheDocument()
  })

  it('shows a failed diff without claiming the content is identical', async () => {
    failDiff = true
    renderWithProviders(<BackupPanel slug="backup-case" evidence={evidence} />)
    const dialog = await openHistory()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare selected versions' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('File content changed')
    expect(within(dialog).queryByText('Identical content — no text changes')).not.toBeInTheDocument()
  })

  it('withdraws a cached identical result when its source can no longer be verified', async () => {
    const { qc } = renderWithProviders(<BackupPanel slug="backup-case" evidence={evidence} />)
    const dialog = await openHistory()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Compare selected versions' }))
    expect(await within(dialog).findByText('Identical content — no text changes')).toBeInTheDocument()
    failDiff = true
    await act(async () => { await qc.invalidateQueries({ queryKey: ['backup-diff', 'backup-case'] }) })
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('File content changed')
    expect(within(dialog).queryByText('Identical content — no text changes')).not.toBeInTheDocument()
  })

  it('adds the selected backup occurrence for review without confirming it', async () => {
    renderWithProviders(<BackupPanel slug="backup-case" evidence={evidence} />)
    const dialog = await openHistory()
    fireEvent.change(within(dialog).getByRole('textbox', { name: 'Note for selected evidence (optional)' }), {
      target: { value: 'Inspect the change in this copy' },
    })
    fireEvent.click(within(dialog).getAllByRole('button', { name: 'Add to Findings' })[1])
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/backup-case/backups/findings', {
      snapshot_id: 22, path: 'nested/example.txt', note: 'Inspect the change in this copy',
    }))
    expect(await within(dialog).findByText('Added for review')).toBeInTheDocument()
    expect(post).not.toHaveBeenCalledWith(expect.stringContaining('/triage'), expect.anything())
  })

  it('disables file and evidence actions for unavailable or stale copies', async () => {
    historyData.entries[0].available = false
    historyData.entries[0].file!.state = 'unavailable'
    historyData.entries[1].stale = true
    renderWithProviders(<BackupPanel slug="backup-case" evidence={evidence} />)
    const dialog = await openHistory()
    expect(within(dialog).getByText('Unavailable')).toBeInTheDocument()
    expect(within(dialog).getByText('Historical / refresh needed')).toBeInTheDocument()
    for (const button of within(dialog).getAllByRole('button', { name: /^(Open file|Add to Findings)$/ })) {
      expect(button).toBeDisabled()
      fireEvent.click(button)
    }
    expect(post).not.toHaveBeenCalled()
  })
})
