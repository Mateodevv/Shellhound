import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { api, post, put, type OpenCtiDraft, type SettingsInfo } from '../api'
import { renderWithProviders } from '../test/setup'
import {
  AddToOpenCtiButton, OpenCtiContextPanel, OpenCtiPackageButton,
} from './OpenCti'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  api: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
}))

const unavailable = {
  services: {}, enrichment_ack: false, path: '',
  opencti: { configured: false, verified: false },
} as SettingsInfo

const available = {
  services: {}, enrichment_ack: false, path: '',
  opencti: { configured: true, verified: true, url: 'https://opencti.test',
    author_id: 'author', author_name: 'IR', default_marking_id: 'marking',
    default_marking_name: 'TLP:AMBER', taxii_collection_url: 'https://opencti.test/taxii',
    token_hint: '…abcd', verified_at: '2026-09-01T10:00:00Z', version: '7.260817.0',
    capabilities: [], markings: [{ id: 'marking', standard_id: 'marking--1',
      name: 'TLP:AMBER' }], authors: [{ id: 'author', standard_id: 'identity--1',
      name: 'IR' }] },
} as SettingsInfo

const draft: OpenCtiDraft = { items: [], summary: '', marking_id: '' }

describe('OpenCTI feature gate', () => {
  it('does not expose actions until settings were successfully verified', async () => {
    vi.mocked(api).mockResolvedValue(unavailable)
    const { container } = renderWithProviders(<AddToOpenCtiButton slug="case" item={{
      kind: 'actor', value: '192.0.2.8', indicator: false,
    }} />)

    await waitFor(() => expect(api).toHaveBeenCalledWith('/api/settings'))
    expect(container).toBeEmptyDOMElement()
  })

  it('persists an explicit package selection without creating an indicator', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/settings') return available
      if (path.endsWith('/draft')) return draft
      throw new Error(`unexpected API call: ${path}`)
    })
    vi.mocked(put).mockImplementation(async (_path, body) => body as OpenCtiDraft)
    renderWithProviders(<AddToOpenCtiButton slug="case" item={{
      kind: 'actor', value: '192.0.2.8', indicator: false,
    }} />)

    fireEvent.click(await screen.findByRole('button', { name: 'Add to OpenCTI package' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      '/api/cases/case/opencti/draft',
      expect.objectContaining({ items: [{
        kind: 'actor', value: '192.0.2.8', indicator: false,
      }] }),
    ))
  })
})

describe('OpenCTI context remains foreign until confirmed', () => {
  it('promotes a related observable only after the analyst clicks it', async () => {
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/settings') return available
      if (path.includes('/context?')) return { entries: [{
        id: 17, target_kind: 'ip', target_key: '192.0.2.8',
        fetched_at: '2026-09-01T10:00:00Z',
        result: { matched: true, matches: [], related: [{
          id: 'domain-name--remote', type: 'Domain-Name', relationship: 'resolves-to',
          value: 'related.example', ioc_type: 'domain', promotable: true,
        }] },
      }] }
      throw new Error(`unexpected API call: ${path}`)
    })
    vi.mocked(post).mockResolvedValue({ ok: true, ioc_id: 3 })
    renderWithProviders(<OpenCtiContextPanel
      slug="case" kind="ip" value="192.0.2.8" />)

    expect((await screen.findByRole('button', { name: 'Add to IOC box' })).parentElement)
      .toHaveTextContent('related.example')
    expect(post).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'Add to IOC box' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith(
      '/api/cases/case/opencti/context/promote', {
        snapshot_id: 17,
        external_id: 'domain-name--remote',
        value: 'related.example',
        type: 'domain',
      },
    ))
  })
})

describe('OpenCTI package preview', () => {
  it('shows the exact file metadata and keeps Indicator an explicit opt-in', async () => {
    const selected: OpenCtiDraft = {
      items: [{ kind: 'file', path: 'evidence/harmless.txt', indicator: false }],
      summary: 'Release context', marking_id: 'marking',
    }
    vi.mocked(api).mockImplementation(async (path) => {
      if (path === '/api/settings') return available
      if (path.endsWith('/draft')) return selected
      if (path.endsWith('/publications')) return { entries: [] }
      throw new Error(`unexpected API call: ${path}`)
    })
    vi.mocked(put).mockImplementation(async (_path, body) => body as OpenCtiDraft)
    vi.mocked(post).mockImplementation(async (path) => {
      if (path.endsWith('/preview')) return {
        publication_id: '00000000-0000-4000-8000-000000000001',
        fingerprint: 'f'.repeat(64), report_id: 'report--1', object_count: 3,
        objects: [{ type: 'file', id: 'file--1', name: 'harmless.txt', size: 42 }],
        summary: 'Release context',
        marking: { id: 'marking', standard_id: 'marking--1', name: 'TLP:AMBER' },
        author: { id: 'author', standard_id: 'identity--1', name: 'IR' },
        files: [{ relative_path: 'evidence/harmless.txt', name: 'harmless.txt',
          size: 42, hashes: { 'SHA-256': 'a'.repeat(64) }, mime_type: 'text/plain',
          artifact_stix_id: 'artifact--1' }],
      }
      throw new Error(`unexpected POST: ${path}`)
    })
    renderWithProviders(<OpenCtiPackageButton slug="case" />)

    fireEvent.click(await screen.findByRole('button', { name: /OpenCTI package/ }))
    const indicator = await screen.findByRole('checkbox', {
      name: 'Also a detection Indicator',
    })
    expect(indicator).not.toBeChecked()
    fireEvent.click(indicator)
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      '/api/cases/case/opencti/draft',
      expect.objectContaining({ items: [expect.objectContaining({ indicator: true })] }),
    ))

    fireEvent.click(screen.getByRole('button', { name: 'Review transmission' }))
    expect(await screen.findByText('evidence/harmless.txt')).toBeInTheDocument()
    expect(screen.getByText('file · file--1')).toBeInTheDocument()
    expect(screen.getByText(/42 B · text\/plain · SHA-256 aaaaaaaaaaaa/))
      .toBeInTheDocument()
    expect(screen.getByText('The binary content will be uploaded.')).toBeInTheDocument()
  })
})
