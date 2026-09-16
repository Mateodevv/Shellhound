import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post, type Enrichment } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { FileReputation } from './FileReputation'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
const HASH = 'a'.repeat(64)
const OTHER = 'b'.repeat(64)
let entries: Enrichment[] = []
let configured = false
let keyAvailable = true
const report = (result: Enrichment['result'], hash = HASH): Enrichment => ({
  service: 'virustotal', kind: 'hash', value: hash, fetched: '2026-09-16T12:00:00Z', result,
})
const panel = (hash = HASH, slug = 'demo') => <FileReputation slug={slug} sha256={hash} boxUrl={`/?case=${slug}&view=iocbox`} />

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(post).mockReset()
  entries = []; configured = false; keyAvailable = true
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/settings') return { services: { virustotal: { configured: keyAvailable } } } as never
    if (path === '/api/opencti/settings') return { configured } as never
    if (path.endsWith('/enrichment')) return { entries: path.includes('/demo/') ? entries : [] } as never
    throw new Error('Unexpected request')
  })
})

it('looks up only the displayed hash on an explicit click, without requiring or collecting IOCs', async () => {
  let finish!: (result: Enrichment) => void
  vi.mocked(post).mockImplementation(() => new Promise(resolve => { finish = resolve as typeof finish }))
  renderWithProviders(panel())
  const button = await screen.findByRole('button', { name: 'Ask VirusTotal' })
  await waitFor(() => expect(button).toBeEnabled())
  expect(post).not.toHaveBeenCalled()
  expect(vi.mocked(api).mock.calls.some(([path]) => path.endsWith('/iocs'))).toBe(false)
  fireEvent.click(button)
  await waitFor(() => expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/demo/enrich', {
    service: 'virustotal', kind: 'hash', value: HASH, refresh: false,
  }))
  expect(screen.getByRole('button', { name: 'Looking up…' })).toBeDisabled()
  fireEvent.click(button)
  expect(post).toHaveBeenCalledTimes(1)
  await act(async () => finish(report({ known: true, score: 0, of: 72 })))
  expect(await screen.findByText('0 / 72')).toBeVisible()
})

it.each([
  [{ known: true, score: 0, of: 72 }, '0 / 72', 'var(--ok)'],
  [{ known: true, score: 7, of: 72 }, '7 / 72', 'var(--danger-text)'],
  [{ known: false, score: 0 }, 'No existing VirusTotal report for this hash.', 'var(--muted)'],
  [{ known: true }, 'Report available; detection count unavailable.', 'var(--muted)'],
] as const)('distinguishes report verdicts without presenting unknown data as zero: %j', async (result, text, color) => {
  entries = [report(result)]
  renderWithProviders(panel())
  const value = await screen.findByText(text)
  expect(value.closest('[role="status"]')).toHaveStyle({ color })
  expect(post).not.toHaveBeenCalled()
})

it('keeps the dated saved result visible when a refresh fails, then accepts a successful retry', async () => {
  entries = [report({ known: true, score: 7, of: 72, permalink: `https://www.virustotal.com/gui/file/${HASH}` })]
  vi.mocked(post).mockRejectedValueOnce(new Error('Provider rate limit reached')).mockResolvedValueOnce(report({ known: true, score: 0, of: 72 }))
  renderWithProviders(panel())
  fireEvent.click(await screen.findByRole('button', { name: 'Refresh VirusTotal' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Provider rate limit reached')
  expect(screen.getByText('7 / 72')).toBeVisible()
  expect(screen.getByText(/2026-09-16/)).toBeVisible()
  expect(screen.getByRole('link', { name: 'Open provider report' })).toHaveAttribute('href', `https://www.virustotal.com/gui/file/${HASH}`)
  expect(post).toHaveBeenCalledWith('/api/cases/demo/enrich', expect.objectContaining({ refresh: true }))
  fireEvent.click(screen.getByRole('button', { name: 'Refresh VirusTotal' }))
  expect(await screen.findByText('0 / 72')).toBeVisible()
  expect(screen.queryByRole('alert')).not.toBeInTheDocument()
})

it('isolates late lookup responses and saved reports when switching files or cases', async () => {
  let finish!: (result: Enrichment) => void
  vi.mocked(post).mockImplementation(() => new Promise(resolve => { finish = resolve as typeof finish }))
  const view = renderWithProviders(panel())
  const button = await screen.findByRole('button', { name: 'Ask VirusTotal' })
  await waitFor(() => expect(button).toBeEnabled())
  fireEvent.click(button)
  await waitFor(() => expect(post).toHaveBeenCalledTimes(1))
  view.rerender(panel(OTHER))
  entries = [report({ known: true, score: 31, of: 72 })]
  await act(async () => finish(entries[0]))
  expect(screen.queryByText('31 / 72')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Refresh VirusTotal' })).not.toBeInTheDocument()
  view.rerender(panel(HASH))
  expect(await screen.findByText('31 / 72')).toBeVisible()
  view.rerender(panel(HASH, 'other-case'))
  expect(screen.queryByText('31 / 72')).not.toBeInTheDocument()
  expect(post).toHaveBeenCalledTimes(1)
})

it('keeps OpenCTI routing and cached reports without offering a direct lookup', async () => {
  configured = true
  entries = [report({ known: true, score: 7, of: 72 })]
  renderWithProviders(panel())
  expect(await screen.findByRole('link', { name: 'Open IOC Box' })).toHaveAttribute('href', '/?case=demo&view=iocbox')
  expect(screen.queryByRole('button', { name: /VirusTotal/ })).not.toBeInTheDocument()
  expect(screen.getByText('7 / 72')).toBeVisible()
  expect(post).not.toHaveBeenCalled()
})

it('explains a missing key while keeping a saved report readable', async () => {
  keyAvailable = false
  entries = [report({ known: true, score: 0, of: 72 })]
  renderWithProviders(panel())
  expect(await screen.findByText(/Add a VirusTotal API key/)).toBeVisible()
  expect(screen.getByRole('button', { name: 'Refresh VirusTotal' })).toBeDisabled()
  expect(screen.getByText('0 / 72')).toBeVisible()
})

it('keeps loading and configuration errors separate from empty reports', async () => {
  vi.mocked(api).mockRejectedValue(new Error('Unavailable'))
  renderWithProviders(panel())
  expect(await screen.findByText('Lookup settings could not be loaded.')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Ask VirusTotal' })).toBeDisabled()
  expect(screen.queryByText('0 / 72')).not.toBeInTheDocument()
  expect(screen.queryByText('No existing VirusTotal report for this hash.')).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})
