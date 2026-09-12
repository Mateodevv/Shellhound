import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { api, post, type Enrichment } from '../api'
import { renderWithProviders } from '../test/setup'
import { EnrichPanel } from './Enrich'

vi.mock('../api', async (orig) => ({ ...(await orig<typeof import('../api')>()), api: vi.fn(), post: vi.fn() }))
const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)
function verdict(value: string, score: number): Enrichment {
  return { service: 'virustotal', value, kind: 'hash', fetched: '2026-09-01T10:00:00Z', result: { known: true, score, of: 72 } }
}
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api).mockImplementation(async (path) => {
    if (path.endsWith('/enrichment')) return { entries: [verdict(HASH_A, 17), verdict(HASH_B, 42)] } as never
    if (path.endsWith('/iocs')) return [] as never
    return { lookups: [], exports: [], sync: [], jobs: [] } as never
  })
})
describe('historical enrichment', () => {
  it('loads stored results without any external action or obsolete provider buttons', async () => {
    renderWithProviders(<EnrichPanel slug="case" kind="hash" value={HASH_A} />)
    expect(await screen.findByText('17')).toBeInTheDocument()
    expect(screen.queryByText('42')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Ask/ })).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    expect(screen.getByRole('link', { name: 'Open IOC Box' })).toHaveAttribute('href', expect.stringContaining('view=iocbox'))
  })
  it('changes displayed verdict when the subject changes and clears it for another kind', async () => {
    const { rerender } = renderWithProviders(<EnrichPanel slug="case" kind="hash" value={HASH_A} />)
    await screen.findByText('17')
    rerender(<EnrichPanel slug="case" kind="hash" value={HASH_B} />)
    expect(await screen.findByText('42')).toBeInTheDocument()
    expect(screen.queryByText('17')).not.toBeInTheDocument()
    rerender(<EnrichPanel slug="case" kind="ip" value="192.0.2.1" />)
    expect(screen.queryByText('42')).not.toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })
  it('does not display another case history while a new case request is pending', async () => {
    const { rerender } = renderWithProviders(<EnrichPanel slug="case" kind="hash" value={HASH_A} />)
    await screen.findByText('17')
    vi.mocked(api).mockImplementation(() => new Promise(() => {}))
    rerender(<EnrichPanel slug="other" kind="hash" value={HASH_A} />)
    await waitFor(() => expect(screen.queryByText('17')).not.toBeInTheDocument())
  })
  it('keeps the IOC route available when local history cannot be loaded', async () => {
    vi.mocked(api).mockRejectedValue(new Error('History unavailable'))
    renderWithProviders(<EnrichPanel slug="case" kind="hash" value={HASH_A} />)
    expect(await screen.findByRole('alert')).toHaveTextContent('History unavailable')
    expect(screen.getByRole('link', { name: 'Open IOC Box' })).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
  })
})
