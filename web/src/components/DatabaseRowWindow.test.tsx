import { beforeEach, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { api, type ArtifactContext, type DatabaseRow, type Finding } from '../api'
import { renderWithProviders } from '../test/setup'
import { ArtifactWindow } from './ArtifactWindow'
import { DatabaseRowWindow } from './DatabaseRowWindow'

vi.mock('../api', async (orig) => ({ ...(await orig<typeof import('../api')>()), api: vi.fn(), post: vi.fn() }))

const finding: Finding = {
  id: 12, fingerprint: 'synthetic-row', source: 'sqldb', severity: 1, rule: 'Synthetic observation',
  artifact_kind: 'table', artifact: 'sample_modules', line: 2, evidence: 'Harmless marker',
  created: '', last_seen: '', triage: 'new', triage_note: '', retired: 0,
}
const sources = [{ dump_id: 4, dump_path: '/export one/data.sql' }, { dump_id: 7, dump_path: '/export two/data.sql' }]
const row: DatabaseRow = { ...sources[1], table: finding.artifact, row: 2, truncated: false,
  columns: [{ name: 'title', value: '<b>Harmless marker</b>', truncated: false }, { name: 'optional', value: null, truncated: false }] }

beforeEach(() => vi.clearAllMocks())

it('requires an explicit export choice and renders database values as inert text', async () => {
  vi.mocked(api).mockResolvedValue(row)
  renderWithProviders(<DatabaseRowWindow slug="case" finding={finding} sources={sources} onClose={() => {}} />)
  expect(api).not.toHaveBeenCalled()
  await userEvent.setup().selectOptions(screen.getByRole('combobox', { name: 'Database export' }), '7')
  expect(await screen.findByText('<b>Harmless marker</b>')).toBeVisible()
  expect(screen.getByText('NULL')).toBeVisible()
  expect(api).toHaveBeenCalledWith('/api/cases/case/database/row?finding_id=12&dump_id=7')
  expect(document.querySelector('dd b')).toBeNull()
})

it('opens the only available export and explains read failures', async () => {
  vi.mocked(api).mockRejectedValue(new Error('The evidence file is unavailable.'))
  renderWithProviders(<DatabaseRowWindow slug="case" finding={finding} sources={[sources[0]]} onClose={() => {}} />)
  expect(await screen.findByRole('alert')).toHaveTextContent('The evidence file is unavailable.')
  expect(api).toHaveBeenCalledWith('/api/cases/case/database/row?finding_id=12&dump_id=4')
})

it('explains missing indexed exports without making a file request', () => {
  renderWithProviders(<DatabaseRowWindow slug="case" finding={finding} sources={[]} onClose={() => {}} />)
  expect(screen.getByRole('status')).toHaveTextContent('No indexed export')
  expect(api).not.toHaveBeenCalled()
})

it('routes table row links through the row viewer and preserves the unsaved analyst note', async () => {
  const context: ArtifactContext = { artifact: finding.artifact, kind: 'table', findings: [finding],
    triage: 'new', triage_note: 'Existing note', triaged_at: '', worst: 1, sources: ['sqldb'], related_ips: [], table_sources: sources }
  vi.mocked(api).mockImplementation(async (url) => url.includes('/database/row?') ? row as never : context as never)
  const onView = vi.fn()
  renderWithProviders(<ArtifactWindow slug="case" artifact={{ artifact: finding.artifact, artifact_kind: 'table',
    worst: 1, triage: 'new', triage_note: '' }} roots={[]} collected={[]} onClose={() => {}}
    onSave={vi.fn()} onView={onView} onTrace={() => {}} />)
  const note = await screen.findByPlaceholderText(/Reasoning/)
  await waitFor(() => expect(note).toHaveValue('Existing note'))
  const user = userEvent.setup()
  await user.type(note, ' and draft')
  await user.click(await screen.findByRole('button', { name: 'Row 2' }))
  expect(screen.getByRole('combobox', { name: 'Database export' })).toBeVisible()
  expect(onView).not.toHaveBeenCalled()
  await user.keyboard('{Escape}')
  expect(note).toHaveValue('Existing note and draft')
})

it('does not offer file actions when existing evidence is no longer registered', async () => {
  const path = '/removed evidence/note.txt'
  const context: ArtifactContext = { artifact: path, kind: 'file', findings: [{ ...finding, artifact: path,
    artifact_kind: 'file', source: 'webshell' }], triage: 'new', triage_note: '', triaged_at: '', worst: 1,
    sources: ['webshell'], related_ips: [], file: { exists: true, available: false, unavailable_reason: 'Outside registered evidence.' } }
  vi.mocked(api).mockResolvedValue(context)
  renderWithProviders(<ArtifactWindow slug="case" artifact={{ artifact: path, artifact_kind: 'file', worst: 1,
    triage: 'new', triage_note: '' }} roots={[]} collected={[]} onClose={() => {}}
    onSave={vi.fn()} onView={vi.fn()} onTrace={() => {}} />)
  expect(await screen.findByText('Outside registered evidence.')).toBeVisible()
  expect(screen.queryByRole('button', { name: 'Expand file' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Line 2' })).not.toBeInTheDocument()
})
