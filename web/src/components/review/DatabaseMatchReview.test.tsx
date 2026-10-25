import { beforeEach, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { api, post, ApiError, type DatabaseRow, type DatabaseFieldPage, type Finding } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { TableRecord } from './ReviewEvidence'
import { DatabaseRowWindow } from './DatabaseRowWindow'

vi.mock('../../api', async orig => ({ ...(await orig<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
const finding: Finding = { id: 12, fingerprint: 'safe', source: 'sqldb', severity: 1, rule: 'Synthetic observation', artifact_kind: 'table', artifact: 'items', line: 2, evidence: 'old excerpt', triage: 'new', triage_note: '', retired: 0, created: '', last_seen: '' }
const sources = [{ dump_id: 4, dump_path: '/one.sql', table_id: 10, rows: 4 }, { dump_id: 7, dump_path: '/two.sql', table_id: 20, rows: 4 }]
const match = { column_index: 1, column_name: 'body', start: 12000, end: 12006, before: 'before ', text: '<b>safe</b>', after: ' after' }
const row: DatabaseRow = { ...sources[1], table: 'items', row: 2, record_version: 'version-1', truncated: true, columns: [{ index: 0, name: 'title', value: 'short title', truncated: false }, { index: 1, name: 'body', value: 'preview without hit', truncated: true }], finding_match: { state: 'recorded', matches: [match] } }
const page: DatabaseFieldPage = { ...sources[1], table: 'items', row: 2, column_index: 1, column_name: 'body', value: 'visible <b>safe</b> text', offset: 11488, next_offset: 19680, total_characters: 30000, record_version: 'version-1', highlight: { before: 'visible ', text: '<b>safe</b>', after: ' text' } }
beforeEach(() => { vi.mocked(post).mockResolvedValue({}); vi.mocked(api).mockResolvedValue(row) })
function viewer(f: Finding = finding) { return <TableRecord slug="case" tableName="items" finding={f} sources={[sources[1]]} /> }

it('shows a verified late match before the collapsed remaining fields and keeps markup inert', async () => {
  renderWithProviders(viewer())
  expect(await screen.findByText('<b>safe</b>')).toBeVisible()
  expect(screen.getByText('short title')).not.toBeVisible()
  expect(document.querySelector('mark')!.compareDocumentPosition(screen.getByRole('combobox', { name: 'Database export' })) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  expect(screen.queryByText('preview without hit')).not.toBeInTheDocument()
  expect(document.querySelector('mark b')).toBeNull()
  expect(document.querySelector('mark')).toHaveClass('bg-[var(--review-soft)]')
  expect(screen.getByText('Recorded match')).toHaveAttribute('title', expect.stringContaining('verified'))
  await userEvent.click(screen.getByText('Record details'))
  expect(screen.getByText('short title')).toBeVisible()
})

it('switches matching fields without showing unrelated row previews', async () => {
  vi.mocked(api).mockResolvedValue({ ...row, finding_match: { state: 'current', matches: [match, { ...match, column_index: 2, column_name: 'footer', text: 'second marker' }] } })
  renderWithProviders(viewer())
  await userEvent.selectOptions(await screen.findByRole('combobox', { name: 'Matching field' }), '1')
  expect(screen.getByText('second marker')).toBeVisible()
  expect(screen.queryByText('<b>safe</b>')).not.toBeInTheDocument()
  expect(screen.getByText('Current match')).toHaveAttribute('title', expect.stringContaining('current rule'))
})

it.each(['confirmed', 'dismissed'] as const)('styles %s matches with the existing triage palette', async triage => {
  renderWithProviders(viewer({ ...finding, triage }))
  await screen.findByText('<b>safe</b>')
  expect(document.querySelector('mark')).toHaveClass(triage === 'confirmed' ? 'bg-[var(--danger-soft)]' : 'line-through')
})

it.each(['changed', 'not_found', 'not_observed', 'rule_unavailable'] as const)('shows the actual %s state without guessing highlights from previews', async state => {
  vi.mocked(api).mockResolvedValue({ ...row, finding_match: { state, matches: [] } })
  renderWithProviders(viewer())
  expect(await screen.findByText('preview without hit')).toBeVisible()
  expect(document.querySelector('mark')).toBeNull()
  expect(screen.getByText('old excerpt')).toBeVisible()
  expect(api).toHaveBeenCalledTimes(1)
})

it('opens a field near the hit and uses bounded server page positions for navigation', async () => {
  vi.mocked(api).mockImplementation(async url => {
    if (!url.includes('/database/field?')) return row as never
    const offset = Number(new URL(url, 'http://localhost').searchParams.get('offset'))
    return { ...page, offset, next_offset: offset + 8192 < 30000 ? offset + 8192 : null } as never
  })
  renderWithProviders(viewer())
  await userEvent.click((await screen.findAllByRole('button', { name: 'Expand field' }))[0])
  const dialog = await screen.findByRole('dialog')
  expect(await within(dialog).findByText('Characters 11489–19680 of 30000')).toBeVisible()
  expect(api).toHaveBeenLastCalledWith(expect.stringContaining('column_index=1&offset=11488&record_version=version-1&finding_id=12'))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Next page' }))
  await waitFor(() => expect(api).toHaveBeenLastCalledWith(expect.stringContaining('offset=19680&')))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Previous page' }))
  await waitFor(() => expect(api).toHaveBeenLastCalledWith(expect.stringContaining('offset=11488&')))
  await userEvent.click(within(dialog).getByRole('button', { name: 'Last page' }))
  expect(await within(dialog).findByText('Characters 21809–30000 of 30000')).toBeVisible()
  expect(within(dialog).getByRole('button', { name: 'Next page' })).toBeDisabled()
  await userEvent.click(within(dialog).getByRole('button', { name: 'First page' }))
  expect(await within(dialog).findByText('Characters 1–8192 of 30000')).toBeVisible()
  expect(within(dialog).getByRole('button', { name: 'Previous page' })).toBeDisabled()
  expect(within(dialog).getByRole('button', { name: 'Copy visible text' })).toBeVisible()
})

it('clears an expanded field on finding change while retaining the selected export', async () => {
  vi.mocked(api).mockImplementation(async url => (url.includes('/database/field?') ? page : row) as never)
  const view = renderWithProviders(<TableRecord slug="case" tableName="items" finding={finding} sources={sources} />)
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Database export' }), '7')
  await userEvent.click((await screen.findAllByRole('button', { name: 'Expand field' }))[0])
  expect(await screen.findByRole('dialog')).toBeVisible()
  view.rerender(<TableRecord slug="case" tableName="items" finding={{ ...finding, id: 13, line: 3 }} sources={sources} />)
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(screen.getByRole('combobox', { name: 'Database export' })).toHaveValue('7')
  await waitFor(() => expect(api).toHaveBeenCalledWith('/api/cases/case/database/table-row?table_id=20&row=3&expected_dump_path=%2Ftwo.sql&expected_table=items&finding_id=13'))
})

it('shows a stale record error without keeping an old page or retrying unversioned data', async () => {
  vi.mocked(api).mockImplementation(async url => { if (url.includes('/database/field?')) throw new ApiError(409, 'The export changed. Reopen the record.'); return row as never })
  renderWithProviders(viewer())
  await userEvent.click((await screen.findAllByRole('button', { name: 'Expand field' }))[0])
  expect(await screen.findByRole('alert')).toHaveTextContent('The export changed. Reopen the record.')
  expect(screen.queryByText('visible <b>safe</b> text')).not.toBeInTheDocument()
  expect(api).toHaveBeenCalledTimes(2)
})

it('reveals only the explicitly selected export', async () => {
  renderWithProviders(<TableRecord slug="case" tableName="items" finding={finding} sources={sources} />)
  expect(screen.getByRole('button', { name: 'Show in file manager' })).toBeDisabled()
  expect(api).not.toHaveBeenCalled()
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Database export' }), '7')
  expect(screen.getByRole('combobox', { name: 'Database export' })).toHaveDisplayValue('/two.sql')
  await userEvent.click(screen.getByRole('button', { name: 'Show in file manager' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/reveal-file', { path: '/two.sql' }))
})

it('keeps legacy response previews usable without fetching unsupported full fields', async () => {
  vi.mocked(api).mockResolvedValue({ ...row, table_id: undefined, record_version: undefined, finding_match: undefined })
  renderWithProviders(<DatabaseRowWindow slug="case" finding={finding} sources={[{ dump_id: 7, dump_path: '/two.sql' }]} onClose={() => {}} />)
  expect(await screen.findByText('preview without hit')).toBeVisible()
  expect(screen.getAllByRole('button', { name: 'Expand field' }).every(button => (button as HTMLButtonElement).disabled)).toBe(true)
  expect(screen.getByText(/Full field reading is unavailable/)).toBeVisible()
  expect(api).toHaveBeenCalledWith('/api/cases/case/database/row?finding_id=12&dump_id=7&expected_dump_path=%2Ftwo.sql')
  expect(api).toHaveBeenCalledTimes(1)
})

it('shows a generic intelligence row immediately without a finding', async () => {
  vi.mocked(api).mockResolvedValue({ ...row, finding_match: undefined })
  renderWithProviders(<DatabaseRowWindow slug="case" tableName="items" initialRow={3} sources={[sources[1]]} onClose={() => {}} />)
  expect(await screen.findByText('short title')).toBeVisible()
  expect(api).toHaveBeenCalledWith('/api/cases/case/database/table-row?table_id=20&row=3&expected_dump_path=%2Ftwo.sql&expected_table=items')
})

it('copies exactly the visible field page and leaves the complete field unread', async () => {
  const user = userEvent.setup()
  const clipboard = vi.spyOn(navigator.clipboard, 'writeText')
  vi.mocked(api).mockImplementation(async url => (url.includes('/database/field?') ? page : row) as never)
  renderWithProviders(viewer())
  await user.click((await screen.findAllByRole('button', { name: 'Expand field' }))[0])
  const dialog = await screen.findByRole('dialog')
  await within(dialog).findByText('Characters 11489–19680 of 30000')
  await user.click(within(dialog).getByRole('button', { name: 'Copy visible text' }))
  await waitFor(() => expect(clipboard).toHaveBeenCalledWith(page.value))
  expect(api).toHaveBeenCalledTimes(2)
})

it('browses adjacent rows and their fields without applying the selected finding to another row', async () => {
  vi.mocked(api).mockImplementation(async url => {
    if (url.includes('/database/field?')) return { ...page, row: 3 } as never
    return url.includes('row=3') ? { ...row, row: 3, finding_match: undefined } as never : row as never
  })
  renderWithProviders(viewer())
  await screen.findByText('<b>safe</b>')
  await userEvent.click(screen.getByRole('button', { name: 'Next row' }))
  expect(await screen.findByText('preview without hit')).toBeVisible()
  expect(api).toHaveBeenLastCalledWith('/api/cases/case/database/table-row?table_id=20&row=3&expected_dump_path=%2Ftwo.sql&expected_table=items')
  await userEvent.click((await screen.findAllByRole('button', { name: 'Expand field' }))[0])
  await waitFor(() => expect(api).toHaveBeenLastCalledWith(expect.stringMatching(/database\/field\?table_id=20&row=3&column_index=0&offset=0&record_version=version-1$/)))
})

it('resets the selected export and field when moving to a different case', async () => {
  vi.mocked(api).mockImplementation(async url => (url.includes('/database/field?') ? page : row) as never)
  const view = renderWithProviders(<TableRecord slug="case" tableName="items" finding={finding} sources={sources} />)
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Database export' }), '7')
  await userEvent.click((await screen.findAllByRole('button', { name: 'Expand field' }))[0])
  expect(await screen.findByRole('dialog')).toBeVisible()
  view.rerender(<TableRecord slug="other" tableName="items" finding={finding} sources={sources} />)
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  expect(screen.getByRole('combobox', { name: 'Database export' })).toHaveValue('')
  expect(screen.getByRole('button', { name: 'Show in file manager' })).toBeDisabled()
  expect(vi.mocked(api).mock.calls.some(([url]) => url.startsWith('/api/cases/other/'))).toBe(false)
})

it('keeps the selected full path when export IDs are recreated and never follows a reused ID', async () => {
  const view = renderWithProviders(<TableRecord slug="case" tableName="items" finding={finding} sources={sources} />)
  await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Database export' }), '7')
  await screen.findByText('<b>safe</b>')
  vi.mocked(api).mockClear()
  const recreated = [{ ...sources[1], dump_path: '/different.sql' }, { ...sources[1], dump_id: 9, table_id: 30 }]
  view.rerender(<TableRecord slug="case" tableName="items" finding={finding} sources={recreated} />)
  expect(screen.getByRole('combobox', { name: 'Database export' })).toHaveValue('9')
  await waitFor(() => expect(api).toHaveBeenCalledWith('/api/cases/case/database/table-row?table_id=30&row=2&expected_dump_path=%2Ftwo.sql&expected_table=items&finding_id=12'))
  view.rerender(<TableRecord slug="case" tableName="items" finding={finding} sources={[recreated[0]]} />)
  expect(screen.getByRole('combobox', { name: 'Database export' })).toHaveValue('')
  expect(screen.getByRole('button', { name: 'Show in file manager' })).toBeDisabled()
})

it('does not display a cached row when a source ID is reused for another full path', async () => {
  vi.mocked(api).mockResolvedValue({ ...row, finding_match: undefined, columns: [{ name: 'title', value: 'old export value', truncated: false }] })
  const view = renderWithProviders(<TableRecord slug="case" tableName="items" sourceId={7} sources={[sources[1]]} />)
  view.qc.setDefaultOptions({ queries: { staleTime: 5000, retry: false } })
  expect(await screen.findByText('old export value')).toBeVisible()
  vi.mocked(api).mockImplementation(() => new Promise(() => {}))
  view.rerender(<TableRecord slug="case" tableName="items" sourceId={7} sources={[{ ...sources[1], dump_path: '/reindexed.sql' }]} />)
  expect(screen.queryByText('old export value')).not.toBeInTheDocument()
  await waitFor(() => expect(api).toHaveBeenLastCalledWith('/api/cases/case/database/table-row?table_id=20&row=1&expected_dump_path=%2Freindexed.sql&expected_table=items'))
  view.rerender(<TableRecord slug="case" tableName="other" sourceId={7} sources={[sources[1]]} />)
  expect(screen.queryByText('old export value')).not.toBeInTheDocument()
  await waitFor(() => expect(api).toHaveBeenLastCalledWith('/api/cases/case/database/table-row?table_id=20&row=1&expected_dump_path=%2Ftwo.sql&expected_table=other'))
})
