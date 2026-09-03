import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, del, post, type CaseDetail, type PickPath } from '../api'
import { renderWithProviders } from '../test/setup'
import { Evidence } from './Evidence'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
  del: vi.fn(),
  patch: vi.fn(),
}))

const CASE = {
  slug: 'case-1', name: 'Synthetic case', evidence_items: [], log_index: null,
} as unknown as CaseDetail

const EMPTY_FOLDER: PickPath = {
  path: '', parent: null, dirs: [], files: [], truncated: false,
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async (path) => {
    if (path === '/api/cases/case-1') return CASE
    if (path === '/api/cases/case-1/jobs') return []
    if (path.startsWith('/api/pickpath?path=')) return EMPTY_FOLDER
    throw new Error(`unexpected API call: ${path}`)
  })
  vi.mocked(post).mockResolvedValue({})
})

describe('evidence registration', () => {
  it('allows analysis of a single source without requiring the other types', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path.endsWith('/jobs')) return []
      return { ...CASE, evidence_items: [{
        id: 1, kind: 'webroot', path: 'C:/Synthetic/site', added: '', scanned_at: '',
        stats: {}, label: '', exists: true,
      }] }
    })
    renderWithProviders(<Evidence slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByText('Evidence ready')).toBeInTheDocument()
    expect(screen.getAllByText('Not provided (optional)')).toHaveLength(2)
    expect(screen.queryByText('Required evidence')).not.toBeInTheDocument()
    const analyze = screen.getByRole('button', { name: 'Run analysis' })
    expect(analyze).toBeEnabled()
    fireEvent.click(analyze)
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case-1/analyze', { mode: 'all' }))
  })
  it('reuses the last browsed path and no longer offers reference copies', async () => {
    renderWithProviders(<Evidence slug="case-1" gotoView={vi.fn()} />)

    expect(await screen.findByRole('button', { name: 'Add Webroot' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Reference copy/ })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Add Webroot' }))
    const path = screen.getByPlaceholderText('or type a path directly')
    fireEvent.change(path, { target: { value: 'C:\\Synthetic\\Evidence' } })
    fireEvent.click(screen.getByRole('button', { name: 'Use this folder' }))

    await waitFor(() => expect(post).toHaveBeenCalledWith(
      '/api/cases/case-1/evidence',
      { kind: 'webroot', path: 'C:\\Synthetic\\Evidence' },
    ))

    fireEvent.click(screen.getByRole('button', { name: 'Add Access logs' }))
    expect(screen.getByPlaceholderText('or type a path directly')).toHaveValue(
      'C:\\Synthetic\\Evidence')
  })

  it('confirms removal and states that disk evidence remains', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/cases/case-1') return {
        ...CASE,
        evidence_items: [{ id: 7, kind: 'webroot', path: 'C:\\Evidence\\Site', added: '',
          scanned_at: '', stats: {}, label: 'Site copy', exists: true }],
      }
      if (path === '/api/cases/case-1/jobs') return []
      throw new Error(`unexpected API call: ${path}`)
    })
    vi.mocked(del).mockResolvedValue({})

    renderWithProviders(<Evidence slug="case-1" gotoView={vi.fn()} />)
    fireEvent.click(await screen.findByRole('button', {
      name: 'Remove from the case (the evidence stays on disk)',
    }))

    expect(await screen.findByRole('dialog', { name: 'Remove this evidence registration?' }))
      .toHaveTextContent('original evidence on disk is not changed')
    expect(del).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Remove registration' }))
    await waitFor(() => expect(del).toHaveBeenCalledWith('/api/cases/case-1/evidence/7'))
  })

  it('separates new evidence, opens management, and sends an incremental run', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/cases/case-1') return {
        ...CASE,
        evidence_items: ['webroot', 'access_logs', 'sql_dump'].map((kind, index) => ({
          id: index + 1, kind, path: `C:\\Synthetic\\${kind}`,
          added: `2026-09-0${index + 1}T10:00:00Z`,
          scanned_at: index === 0 ? '2026-09-01T12:00:00Z' : '',
          stats: {}, exists: true,
        })),
      }
      if (path === '/api/cases/case-1/jobs') return [{
        id: 1, run_id: 'run-1', kind: 'analysis', state: 'done', progress: 1,
        message: '', error: '', created: '2026-09-02T10:00:00Z', stats: {},
      }]
      throw new Error(`unexpected API call: ${path}`)
    })

    renderWithProviders(<Evidence slug="case-1" gotoView={vi.fn()} />)

    expect(await screen.findByText('Evidence ready')).toBeInTheDocument()
    expect(screen.getByText('Manage evidence').closest('details')).toHaveAttribute('open')
    expect(screen.getByText('New evidence — not analyzed')).toBeInTheDocument()
    expect(screen.getByText('Analyzed evidence')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Analyze new evidence (2)' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith(
      '/api/cases/case-1/analyze', { mode: 'new' }))
  })

  it('disables the default action when nothing is pending and confirms full reanalysis', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/cases/case-1') return {
        ...CASE,
        evidence_items: ['webroot', 'access_logs', 'sql_dump'].map((kind, index) => ({
          id: index + 1, kind, path: `C:\\Synthetic\\${kind}`, added: '',
          scanned_at: '2026-09-01T12:00:00Z', stats: {}, exists: true,
        })),
      }
      if (path === '/api/cases/case-1/jobs') return [{
        id: 1, run_id: 'run-1', kind: 'analysis', state: 'done', progress: 1,
        message: '', error: '', created: '2026-09-02T10:00:00Z', stats: {},
      }]
      throw new Error(`unexpected API call: ${path}`)
    })

    renderWithProviders(<Evidence slug="case-1" gotoView={vi.fn()} />)
    expect(await screen.findByRole('button', { name: 'No new evidence' })).toBeDisabled()
    expect(screen.getByText('Manage evidence').closest('details')).not.toHaveAttribute('open')

    fireEvent.click(screen.getByRole('button', { name: 'More analysis options' }))
    fireEvent.click(screen.getByRole('button', { name: 'Reanalyze all evidence…' }))
    expect(await screen.findByRole('dialog', { name: 'Reanalyze the complete case?' }))
      .toHaveTextContent('existing analyst decisions and notes are preserved')
    fireEvent.click(screen.getByRole('button', { name: 'Reanalyze all evidence' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith(
      '/api/cases/case-1/analyze', { mode: 'all' }))
  })
})
