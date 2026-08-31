import { fireEvent, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  api, type BrowseFile, type BrowseResponse, type CaseDetail, type FileContent,
} from '../api'
import { renderWithProviders } from '../test/setup'
import { Files } from './Files'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
}))

const ROOT = 'C:\\Synthetic\\Evidence'
const FIRST_PATH = `${ROOT}\\index.php`
const SECOND_PATH = `${ROOT}\\readme.txt`

const FIRST: BrowseFile = {
  name: 'index.php', path: FIRST_PATH, relative: 'index.php', size: 42,
  created_at: '2026-08-20T07:10:00Z',
  modified_at: '2026-08-21T08:11:12Z',
  accessed_at: '2026-08-22T09:12:13Z', changed_at: null,
  in_box: false, flagged: 0, worst: null, triage: null, review: null,
}

const SECOND: BrowseFile = {
  ...FIRST, name: 'readme.txt', path: SECOND_PATH, relative: 'readme.txt',
  size: 18, modified_at: '2026-08-19T06:00:00Z',
}

const DIRECTORY_RESPONSE: BrowseResponse = {
  path: ROOT, parent: null, roots: [], dirs: [], files: [FIRST, SECOND],
  truncated: false,
}

const PREVIEW: FileContent = {
  path: FIRST_PATH, size: 42, offset: 0, length: 42, eof: true,
  mode: 'raw', window: 65_536, binary: false,
  created_at: FIRST.created_at, modified_at: FIRST.modified_at,
  accessed_at: FIRST.accessed_at, changed_at: FIRST.changed_at,
  hashes: {
    md5: '1'.repeat(32), sha1: '2'.repeat(40), sha256: '3'.repeat(64),
  },
  hashes_limited: false,
  from_line: 1, lines: ['<?php', 'echo "synthetic";', ''],
}

const CASE = {
  evidence_items: [{
    id: 1, kind: 'webroot', path: ROOT, label: 'Synthetic site',
    added: '2026-08-20T07:00:00Z', scanned_at: '', stats: {},
  }],
} as unknown as CaseDetail

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/cases/case-1') return CASE
    if (path.includes('/browse?path=')) return DIRECTORY_RESPONSE
    if (path.includes('/file?path=')) return PREVIEW
    throw new Error(`unexpected API call: ${path}`)
  })
})

describe('manual file review workspace', () => {
  it('shows copyable forensic facts and no analyst-decision form', async () => {
    renderWithProviders(<Files slug="case-1" gotoView={vi.fn()} />)

    await screen.findByText('Manual file review')
    expect(await screen.findByRole('button', { name: /Review index\.php/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Synthetic site/ })).not.toBeInTheDocument()
    fireEvent.click(await screen.findByRole('button', { name: /Review index\.php/ }))

    expect(await screen.findByText('Filesystem metadata')).toBeInTheDocument()
    expect(screen.getByText('Created')).toBeInTheDocument()
    expect(screen.getByText('Modified')).toBeInTheDocument()
    expect(screen.getByText('Accessed')).toBeInTheDocument()
    expect(screen.getAllByText(/UTC/).length).toBeGreaterThanOrEqual(3)
    expect(screen.getByText('File hashes')).toBeInTheDocument()
    expect(await screen.findByText('1'.repeat(32))).toBeInTheDocument()
    expect(screen.getByText('2'.repeat(40))).toBeInTheDocument()
    expect(screen.getByText('3'.repeat(64))).toBeInTheDocument()
    expect(await screen.findByText('echo "synthetic";')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy file name' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy path' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy file content' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy Created' })).toBeInTheDocument()
    expect(screen.queryByText('Analyst decision')).not.toBeInTheDocument()
  })
})
