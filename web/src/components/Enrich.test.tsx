// Enrich.test.tsx -- a third party's verdict, and which indicator it belongs
// to.
//
// THE PANEL STAYS MOUNTED WHILE ITS SUBJECT CHANGES. It sits inside the
// artifact window, and that window is re-rendered with the next hash or the
// next address rather than torn down. Everything the panel remembers about
// one lookup -- the answer, an error, an in-flight request -- therefore has
// to be tied to the value it was about, or the analyst reads VirusTotal's
// opinion of the previous file under the name of the current one. That is
// not a cosmetic slip: a foreign verdict against the wrong artifact is the
// exact mistake the whole component is written to prevent.
import { describe, expect, it, vi } from 'vitest'
import { act, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { api, post, type Enrichment, type SettingsInfo } from '../api'
import { renderWithProviders, testQueryClient } from '../test/setup'
import { EnrichPanel } from './Enrich'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
}))

const HASH_A = 'a'.repeat(64)
const HASH_B = 'b'.repeat(64)

const CONFIGURED: SettingsInfo = {
  enrichment_ack: true,
  path: '/workspace',
  services: {
    virustotal: { configured: true, hint: '', sends: 'hash', url: '' },
    abuseipdb: { configured: true, hint: '', sends: 'ip', url: '' },
  },
}

function verdict(value: string, score: number): Enrichment {
  return {
    service: 'virustotal', value, kind: 'hash',
    fetched: new Date().toISOString(),
    result: { known: true, score, of: 72 },
  }
}

function mount(kind: string, value: string) {
  return renderWithProviders(
    <EnrichPanel slug="case" kind={kind} value={value} />, testQueryClient())
}

const askButton = () => screen.getByRole('button', { name: /Ask VirusTotal/i })

describe('the verdict on screen', () => {
  it('offers no lookup until the workspace has allowed one', async () => {
    // Nothing may leave the machine before the analyst has said so. The
    // panel says this quietly rather than with a banner, but it must say it
    // instead of offering a button that would fail.
    vi.mocked(api).mockResolvedValue({
      ...CONFIGURED, enrichment_ack: false,
    } satisfies SettingsInfo)
    mount('hash', HASH_A)

    await waitFor(() => expect(screen.getByText('no lookup')).toBeInTheDocument())
    expect(screen.queryByRole('button', { name: /Ask/i })).toBeNull()
  })

  it('sends nothing until the button is clicked', async () => {
    // No lookup on mount, no sweep, no background refresh: the request
    // leaves when the analyst asks for it. Opening an artifact window must
    // not tell VirusTotal which hashes this case is looking at.
    vi.mocked(api).mockResolvedValue(CONFIGURED)
    mount('hash', HASH_A)

    await waitFor(() => expect(askButton()).toBeInTheDocument())
    expect(post).not.toHaveBeenCalled()
  })

  it('shows the answer for the value that was asked about', async () => {
    vi.mocked(api).mockResolvedValue(CONFIGURED)
    vi.mocked(post).mockResolvedValue(verdict(HASH_A, 41))
    mount('hash', HASH_A)

    await userEvent.click(await screen.findByRole('button', { name: /Ask VirusTotal/i }))
    await waitFor(() => expect(screen.getByText('41')).toBeInTheDocument())
    expect(post).toHaveBeenCalledWith('/api/cases/case/enrich',
      { service: 'virustotal', value: HASH_A, refresh: false })
  })

  it('clears the verdict when the panel is handed a different value', async () => {
    // The bug in one assertion: the artifact window is re-rendered with the
    // next file's hash, and 41 detections stayed on screen next to it.
    vi.mocked(api).mockResolvedValue(CONFIGURED)
    vi.mocked(post).mockResolvedValue(verdict(HASH_A, 41))
    const { rerender } = mount('hash', HASH_A)

    await userEvent.click(await screen.findByRole('button', { name: /Ask VirusTotal/i }))
    await waitFor(() => expect(screen.getByText('41')).toBeInTheDocument())

    rerender(<EnrichPanel slug="case" kind="hash" value={HASH_B} />)
    expect(screen.queryByText('41')).toBeNull()
  })

  it('clears the verdict when the kind of indicator changes', async () => {
    // The same panel is used for hashes and for addresses, and the two are
    // answered by different services. A VirusTotal score left standing under
    // an AbuseIPDB heading is a number nobody can interpret.
    vi.mocked(api).mockResolvedValue(CONFIGURED)
    vi.mocked(post).mockResolvedValue(verdict(HASH_A, 41))
    const { rerender } = mount('hash', HASH_A)

    await userEvent.click(await screen.findByRole('button', { name: /Ask VirusTotal/i }))
    await waitFor(() => expect(screen.getByText('41')).toBeInTheDocument())

    rerender(<EnrichPanel slug="case" kind="ip" value="203.0.113.7" />)
    expect(screen.queryByText('41')).toBeNull()
    expect(await screen.findByRole('button', { name: /Ask AbuseIPDB/i }))
      .toBeInTheDocument()
  })

  it('offers no lookup for a kind no service answers for', async () => {
    vi.mocked(api).mockResolvedValue(CONFIGURED)
    const { container } = mount('login', 'admin')
    expect(container).toBeEmptyDOMElement()
  })

  it('clears a failed lookup when the value changes', async () => {
    vi.mocked(api).mockResolvedValue(CONFIGURED)
    vi.mocked(post).mockRejectedValue(new Error('quota exceeded'))
    const { rerender } = mount('hash', HASH_A)

    await userEvent.click(await screen.findByRole('button', { name: /Ask VirusTotal/i }))
    await waitFor(() => expect(screen.getByText('quota exceeded')).toBeInTheDocument())

    rerender(<EnrichPanel slug="case" kind="hash" value={HASH_B} />)
    expect(screen.queryByText('quota exceeded')).toBeNull()
  })

  it('drops an in-flight answer that is no longer about the value shown', async () => {
    vi.mocked(api).mockResolvedValue(CONFIGURED)
    let release: ((e: Enrichment) => void) | null = null
    vi.mocked(post).mockReturnValue(
      new Promise<Enrichment>((res) => { release = res }) as Promise<unknown>)
    const { rerender } = mount('hash', HASH_A)

    await userEvent.click(await screen.findByRole('button', { name: /Ask VirusTotal/i }))
    rerender(<EnrichPanel slug="case" kind="hash" value={HASH_B} />)

    await act(async () => { release?.(verdict(HASH_A, 41)) })
    expect(screen.queryByText('41')).toBeNull()
  })
})
