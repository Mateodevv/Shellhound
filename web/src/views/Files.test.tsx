import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  api, post, type BrowseFile, type BrowseResponse, type CaseDetail, type FileContent, type FileReviewResult,
} from '../api'
import { renderWithProviders, testQueryClient } from '../test/setup'
import { Files } from './Files'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
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

const REVIEW_RESULT: FileReviewResult = {
  updated: 1, artifacts: 1, collected: [], linked: [], suggested: [], retained_iocs: [],
  review: { state: 'confirmed', classification: 'malware', note: 'Evidence reviewed', at: '2026-09-07T10:00:00Z' },
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(post).mockResolvedValue(REVIEW_RESULT)
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/cases/case-1') return CASE
    if (path.includes('/browse?path=')) return DIRECTORY_RESPONSE
    if (path.includes('/file?path=')) return PREVIEW
    throw new Error(`unexpected API call: ${path}`)
  })
})

describe('manual file review workspace', () => {
  it('shows forensic facts and keeps classifications explicit and reason-gated', async () => {
    renderWithProviders(<Files slug="case-1" gotoView={vi.fn()} />)

    await screen.findByText('Manual file review')
    expect(await screen.findByRole('button', { name: /Review index\.php/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Synthetic site/ })).not.toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: 'Evidence path' })).toHaveTextContent('Synthetic site')
    expect(screen.getByRole('button', { name: 'Copy current folder path' })).toBeInTheDocument()
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
    expect(screen.getByRole('button', { name: 'Mark as webshell' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Mark as malware' })).toBeDisabled()
    fireEvent.change(screen.getByRole('textbox', { name: /Reason and supporting evidence/ }), { target: { value: '   ' } })
    expect(screen.getByRole('button', { name: 'Mark as malware' })).toBeDisabled()
    expect(post).not.toHaveBeenCalled()
  })

  it.each(['webshell', 'malware'] as const)('records only the explicitly chosen %s classification through the audit endpoint', async (classification) => {
    vi.mocked(post).mockResolvedValue({ ...REVIEW_RESULT, review: { ...REVIEW_RESULT.review, classification } })
    const qc = testQueryClient()
    qc.setQueryData(['opencti', 'case-1'], { cached: true })
    renderWithProviders(<Files slug="case-1" gotoView={vi.fn()} />, qc)
    fireEvent.click(await screen.findByRole('button', { name: /Review index\.php/ }))
    await screen.findByText('3'.repeat(64))
    fireEvent.change(screen.getByRole('textbox', { name: /Reason and supporting evidence/ }),
      { target: { value: '  Explicit evidence from the inspected content  ' } })
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: `Mark as ${classification}` }))
    await screen.findByText('Classification saved in the case.')
    expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/case-1/files/review', {
      path: FIRST_PATH, state: 'confirmed', classification, note: 'Explicit evidence from the inspected content',
    })
    expect(screen.getByText(classification === 'malware' ? 'Malware' : 'Webshell')).toBeInTheDocument()
    expect(qc.getQueryState(['opencti', 'case-1'])?.isInvalidated).toBe(true)
  })

  it('retains the reason after a save failure and clears it when selecting a different file', async () => {
    vi.mocked(post).mockRejectedValue(new Error('The file has changed; review it again.'))
    renderWithProviders(<Files slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Review index\.php/ }))
    await screen.findByText('3'.repeat(64))
    fireEvent.change(screen.getByRole('textbox', { name: /Reason and supporting evidence/ }),
      { target: { value: 'Do not lose this reasoning' } })
    fireEvent.click(screen.getByRole('button', { name: 'Mark as malware' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('The file has changed; review it again.')
    expect(screen.getByRole('textbox', { name: /Reason and supporting evidence/ })).toHaveValue('Do not lose this reasoning')
    expect(screen.queryByText('Classification saved in the case.')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Review readme\.txt/ }))
    expect(screen.getByRole('textbox', { name: /Reason and supporting evidence/ })).toHaveValue('')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('blocks conflicting actions while the explicit classification is being saved', async () => {
    let resolve!: (value: FileReviewResult) => void
    vi.mocked(post).mockReturnValue(new Promise<FileReviewResult>((done) => { resolve = done }))
    renderWithProviders(<Files slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', { name: /Review index\.php/ }))
    await screen.findByText('3'.repeat(64))
    fireEvent.change(screen.getByRole('textbox', { name: /Reason and supporting evidence/ }), { target: { value: 'Inspected content' } })
    fireEvent.click(screen.getByRole('button', { name: 'Mark as malware' }))
    await screen.findByText('Saving classification…')
    expect(screen.getByRole('button', { name: 'Mark as malware' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Mark as webshell' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Mark as webshell' }))
    expect(post).toHaveBeenCalledTimes(1)
    resolve(REVIEW_RESULT)
    await waitFor(() => expect(screen.getByRole('button', { name: 'Mark as webshell' })).toBeEnabled())
  })
})
