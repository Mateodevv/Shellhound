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
  schema_files: [], tables: [], schema_tables: 0, findings: [], reference: '',
  accounts: [{ id: 7, dump_id: 1, cms: 'WordPress', tbl: 'wp_users', user_id: '7',
    login: 'synthetic-admin', email: 'admin@example.test', registered: '2026-05-01',
    hash_type: 'phpass', admin: 1, last_login: '', blocked: 0, sessions: 1,
    signals: [{ id: 'admin', label: 'Administrator', why: 'Privileged account' }],
    rank: 1, in_box: false }],
  intelligence: {
    cms: ['Joomla', 'WordPress'], truncated: {}, configuration: [],
    access: [{ ...source, cms: 'WordPress', key: 'user:7:capabilities', kind: 'capabilities',
      user_id: '7', account_login: 'synthetic-admin', roles: ['administrator'] }],
    content: [{ ...source, source_table: 'wp_posts', cms: 'WordPress', key: 'post:9',
      title: 'Synthetic post', type: 'post', modified: '2026-05-02',
      content: '<script>synthetic()</script>', content_truncated: false,
      signals: ['script'], review: true }],
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
  it('opens on accounts and shows database-derived permissions', async () => {
    renderWithProviders(<DatabaseView slug="test" gotoView={() => {}} />)
    expect(await screen.findByRole('heading', { name: 'Accounts and permissions' })).toBeInTheDocument()
    expect(screen.getByText('synthetic-admin')).toBeInTheDocument()
    expect(screen.getByText('administrator')).toBeInTheDocument()
  })

  it('keeps WordPress and Joomla in one extension lens', async () => {
    renderWithProviders(<DatabaseView slug="test" gotoView={() => {}} />)
    await screen.findByText('synthetic-admin')
    fireEvent.click(screen.getByRole('tab', { name: /Extensions/ }))
    expect(await screen.findByText('System - Example')).toBeInTheDocument()
    expect(screen.getAllByText('missing').length).toBeGreaterThan(0)
    expect(screen.getByText('present')).toBeInTheDocument()
  })

  it('shows post content as inert text on demand', async () => {
    renderWithProviders(<DatabaseView slug="test" gotoView={() => {}} />)
    await screen.findByText('synthetic-admin')
    fireEvent.click(screen.getByRole('tab', { name: /Posts & articles/ }))
    const post = await screen.findByRole('button', { name: /Synthetic post/ })
    fireEvent.click(post)
    const sourceText = await screen.findByText('<script>synthetic()</script>')
    expect(sourceText.tagName).toBe('PRE')
    expect(sourceText.querySelector('script')).toBeNull()
  })
})
