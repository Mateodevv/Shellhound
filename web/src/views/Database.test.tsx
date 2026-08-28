import { fireEvent, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api'
import { renderWithProviders } from '../test/setup'
import { DatabaseView } from './Database'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
}))

const source = {
  source_table: 'wp_options', source_row: 1, dump_id: 1,
  dump_name: 'cms.sql', signals: [] as string[], review: false,
}

const DATA = {
  dumps: [{ id: 1, path: 'C:/evidence/cms.sql', meta: {}, statements: 4,
    size: 800, cms: 'Joomla, WordPress', kind: 'export' }],
  schema_files: [], tables: [], schema_tables: 0, accounts: [], findings: [], reference: '',
  intelligence: {
    cms: ['Joomla', 'WordPress'], truncated: {}, configuration: [], access: [], content: [],
    extensions: [
      { ...source, cms: 'WordPress', key: 'missing/missing.php', name: 'missing',
        type: 'plugin', enabled: true, version: '', signals: ['active_missing_files'], review: true,
        filesystem: { status: 'missing', path: '', version: '', type: '', findings: [] } },
      { ...source, cms: 'Joomla', key: 'extension:8', name: 'System - Example',
        element: 'example', type: 'plugin', enabled: true, version: '2.0',
        filesystem: { status: 'present', path: 'C:/web/plugins/system/example',
          version: '2.0', type: 'Plugin (system)', findings: [] } },
    ],
    persistence: [{ ...source, cms: 'Joomla', key: 'task:3', kind: 'scheduled_task',
      label: 'Remote request', schedule: '*/5 * * * *', domains: ['tasks.example'],
      signals: ['external_target'], review: true }],
    review_queue: [{ ...source, category: 'extensions', cms: 'WordPress',
      key: 'missing/missing.php', name: 'missing', signals: ['active_missing_files'], review: true }],
    summary: { needs_review: 2, active_extensions: 2, access_records: 0,
      persistence_records: 1, content_signals: 0 },
  },
}

beforeEach(() => {
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/cases/test/database') return DATA
    if (path === '/api/cases/test') return { evidence_items: [] }
    throw new Error(`unexpected API call: ${path}`)
  })
})

describe('Database CMS intelligence workspace', () => {
  it('shows a review queue and keeps WordPress and Joomla in one extension lens', async () => {
    renderWithProviders(<DatabaseView slug="test" gotoView={() => {}} />)
    expect(await screen.findByRole('heading', { name: 'Review queue' })).toBeInTheDocument()
    expect(screen.getByText('Active, files missing')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('tab', { name: /Extensions/ }))
    expect(await screen.findByText('System - Example')).toBeInTheDocument()
    expect(screen.getAllByText('missing').length).toBeGreaterThan(0)
    expect(screen.getByText('present')).toBeInTheDocument()
  })

  it('shows Joomla Scheduler targets in the persistence lens', async () => {
    renderWithProviders(<DatabaseView slug="test" gotoView={() => {}} />)
    await screen.findByRole('heading', { name: 'Review queue' })
    fireEvent.click(screen.getByRole('tab', { name: /Persistence/ }))
    expect(await screen.findByText('Remote request')).toBeInTheDocument()
    expect(screen.getByText('tasks.example')).toBeInTheDocument()
  })
})
