import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, post, type CaseDetail, type PickPath } from '../api'
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
})
