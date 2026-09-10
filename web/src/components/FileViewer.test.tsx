import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, type FileContent } from '../api'
import { renderWithProviders } from '../test/setup'
import { FileContentPane } from './FileViewer'

vi.mock('../api', async (original) => ({
  ...(await original<typeof import('../api')>()), api: vi.fn(),
}))

const SOURCE = 'C:\\Evidence folder\\sample notes.txt'
const INITIAL = { slug: 'sample', path: SOURCE, focusLine: 5000 }
const RAW_WINDOW = 256 * 1024

function page(overrides: Partial<FileContent> = {}): FileContent {
  return {
    path: SOURCE, size: 1_000_000, offset: 430_000, length: RAW_WINDOW - 3,
    window: RAW_WINDOW, eof: false, mode: 'raw', binary: false,
    created_at: null, modified_at: null, accessed_at: null, changed_at: null,
    hashes: {}, hashes_limited: false, from_line: 5000, starts_mid_line: false,
    requested_line: 5000, focus_found: true,
    lines: ['Selected harmless marker', 'Following source line'],
    ...overrides,
  }
}

function requests() {
  return vi.mocked(api).mock.calls.map(([url]) => new URL(url, 'http://localhost'))
}

function lastRequest() {
  const request = requests().at(-1)
  expect(request).toBeDefined()
  return request!
}

beforeEach(() => { vi.mocked(api).mockReset() })

describe('source file line navigation', () => {
  it('requests a distant source line and displays the returned byte range and line numbers', async () => {
    vi.mocked(api).mockResolvedValue(page())
    renderWithProviders(<FileContentPane {...INITIAL} />)

    const selected = await screen.findByText('Selected harmless marker')
    expect(lastRequest().pathname).toBe('/api/cases/sample/file')
    expect(lastRequest().searchParams.get('path')).toBe(SOURCE)
    expect(lastRequest().searchParams.get('line')).toBe('5000')
    expect(lastRequest().searchParams.get('offset')).toBe('0')
    expect(within(selected.parentElement!).getByText('5000')).toBeInTheDocument()
    expect(within(screen.getByText('Following source line').parentElement!)
      .getByText('5001')).toBeInTheDocument()
    expect(screen.getByText(/Byte 430,000–692,141 of 1,000,000/)).toBeInTheDocument()
  })

  it('pages from actual returned offsets and lengths and can return to the referenced line', async () => {
    vi.mocked(api).mockImplementation(async (url) => {
      const query = new URL(url, 'http://localhost').searchParams
      if (query.has('line')) return page()
      const offset = Number(query.get('offset'))
      return page({ offset, from_line: 8100, starts_mid_line: true,
        requested_line: undefined, focus_found: undefined,
        lines: [`Loaded byte ${offset}`] })
    })
    renderWithProviders(<FileContentPane {...INITIAL} />)
    await screen.findByText('Selected harmless marker')

    fireEvent.click(screen.getByRole('button', { name: 'Next part of file' }))
    await screen.findByText('Loaded byte 692141')
    expect(lastRequest().searchParams.get('offset')).toBe('692141')
    expect(lastRequest().searchParams.has('line')).toBe(false)
    expect(screen.getByText(/first displayed line is a continuation/)).toBeInTheDocument()
    expect(within(screen.getByText('Loaded byte 692141').parentElement!)
      .getByText('8100')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Previous part of file' }))
    await screen.findByText('Loaded byte 429997')
    expect(lastRequest().searchParams.get('offset')).toBe('429997')
    expect(lastRequest().searchParams.has('line')).toBe(false)

    fireEvent.click(screen.getByRole('button', { name: 'Back to line 5000' }))
    await screen.findByText('Selected harmless marker')
    await waitFor(() => expect(lastRequest().searchParams.get('line')).toBe('5000'))
    expect(lastRequest().searchParams.get('offset')).toBe('0')
  })

  it('can inspect earlier context when a targeted line is within a small file', async () => {
    vi.mocked(api).mockImplementation(async (url) => {
      const target = new URL(url, 'http://localhost').searchParams.has('line')
      return page({ size: 1000, offset: target ? 600 : 0, length: target ? 400 : 1000,
        eof: true, from_line: target ? 12 : 1,
        lines: [target ? 'Selected small-file marker' : 'Beginning of small file'] })
    })
    renderWithProviders(<FileContentPane {...INITIAL} focusLine={12} />)
    await screen.findByText('Selected small-file marker')
    expect(screen.getByRole('button', { name: 'Next part of file' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Previous part of file' }))
    await screen.findByText('Beginning of small file')
    expect(lastRequest().searchParams.get('offset')).toBe('0')
    expect(lastRequest().searchParams.has('line')).toBe(false)
  })

  it('explains an unavailable line while showing the beginning with its actual line numbers', async () => {
    vi.mocked(api).mockResolvedValue(page({ offset: 0, from_line: 1,
      focus_found: false, lines: ['Beginning after source changed'] }))
    renderWithProviders(<FileContentPane {...INITIAL} />)
    const warning = await screen.findByText(/Line 5000 is no longer present/)
    expect(warning).toHaveAttribute('role', 'status')
    expect(warning).toHaveTextContent('Showing the beginning')
    expect(within(screen.getByText('Beginning after source changed').parentElement!)
      .getByText('1')).toBeInTheDocument()
    expect(screen.queryByText('5000')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Previous part of file' })).toBeDisabled()
  })

  it('uses byte offsets in hex mode and restores the requested source line in raw mode', async () => {
    vi.mocked(api).mockImplementation(async (url) => {
      const query = new URL(url, 'http://localhost').searchParams
      if (query.get('mode') === 'raw') return page()
      const offset = Number(query.get('offset'))
      return page({ mode: 'hex', offset, window: 16 * 1024, length: 16 * 1024,
        lines: undefined, from_line: undefined, requested_line: undefined,
        focus_found: undefined, rows: [{ offset, hex: '41 42', ascii: `AB at ${offset}` }] })
    })
    renderWithProviders(<FileContentPane {...INITIAL} />)
    await screen.findByText('Selected harmless marker')
    fireEvent.click(screen.getByRole('button', { name: 'hex' }))
    await screen.findByText('AB at 0')
    expect(lastRequest().searchParams.get('mode')).toBe('hex')
    expect(lastRequest().searchParams.has('line')).toBe(false)
    expect(lastRequest().searchParams.get('offset')).toBe('0')

    fireEvent.click(screen.getByRole('button', { name: 'Next part of file' }))
    await screen.findByText('AB at 16384')
    expect(lastRequest().searchParams.get('offset')).toBe('16384')

    fireEvent.click(screen.getByRole('button', { name: 'raw' }))
    await screen.findByText('Selected harmless marker')
    await waitFor(() => expect(lastRequest().searchParams.get('mode')).toBe('raw'))
    expect(lastRequest().searchParams.get('line')).toBe('5000')
    expect(lastRequest().searchParams.get('offset')).toBe('0')
  })

  it.each([
    ['case', { slug: 'another-case' }],
    ['file', { path: 'D:\\Other evidence\\different note.txt' }],
    ['line', { focusLine: 7000 }],
  ])('resets mode and page when the selected %s changes', async (_kind, changed) => {
    vi.mocked(api).mockImplementation(async (url) => {
      const request = new URL(url, 'http://localhost')
      const query = request.searchParams
      const mode = query.get('mode') as 'raw' | 'hex'
      const label = `${request.pathname} ${query.get('path')} ${query.get('line')} ${mode}`
      return page({ mode, lines: mode === 'raw' ? [label] : undefined,
        rows: mode === 'hex' ? [{ offset: 0, hex: '41', ascii: 'Hex source marker' }] : undefined })
    })
    const view = renderWithProviders(<FileContentPane {...INITIAL} />)
    const oldLabel = `/api/cases/sample/file ${SOURCE} 5000 raw`
    await screen.findByText(oldLabel)
    fireEvent.click(screen.getByRole('button', { name: 'hex' }))
    await screen.findByText('Hex source marker')

    const next = { ...INITIAL, ...changed }
    view.rerender(<FileContentPane {...next} />)
    await screen.findByText(`/api/cases/${next.slug}/file ${next.path} ${next.focusLine} raw`)
    expect(lastRequest().pathname).toBe(`/api/cases/${next.slug}/file`)
    expect(lastRequest().searchParams.get('path')).toBe(next.path)
    expect(lastRequest().searchParams.get('mode')).toBe('raw')
    expect(lastRequest().searchParams.get('offset')).toBe('0')
    expect(lastRequest().searchParams.get('line')).toBe(String(next.focusLine))
    expect(screen.queryByText('Hex source marker')).not.toBeInTheDocument()
    expect(screen.queryByText(oldLabel)).not.toBeInTheDocument()
  })
})
