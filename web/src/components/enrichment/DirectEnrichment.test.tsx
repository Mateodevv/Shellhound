import { beforeEach, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { api, post, type Enrichment } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { DirectEnrichment } from './DirectEnrichment'
import { DirectEnrichmentSettings } from '../settings/DirectEnrichmentSettings'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
let configured = false
let entries: Enrichment[] = []
let kind = 'ip'
let value = '1.1.1.1'
beforeEach(() => {
  vi.clearAllMocks(); configured = false; entries = []; kind = 'ip'; value = '1.1.1.1'
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/opencti/settings') return { configured } as never
    if (path === '/api/settings') return { services: { virustotal: { configured: true, hint: '…1234' }, abuseipdb: { configured: true, hint: '…5678' } } } as never
    if (path.endsWith('/iocs')) return [{ id: 1, type: kind, value }] as never
    if (path.endsWith('/enrichment')) return { entries } as never
    return {} as never
  })
  vi.mocked(post).mockResolvedValue({})
})
it('uses both compatible providers for IPs without automatic requests', async () => {
  renderWithProviders(<DirectEnrichment slug="demo" ids={[1]} />)
  expect(await screen.findByText('AbuseIPDB')).toBeVisible()
  expect(screen.getByText('VirusTotal')).toBeVisible()
  expect(screen.getAllByRole('button', { name: 'Lookup' })).toHaveLength(2)
  expect(post).not.toHaveBeenCalled()
  fireEvent.click(screen.getAllByRole('button', { name: 'Lookup' })[1])
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/demo/enrich', { service: 'abuseipdb', kind: 'ip', value, refresh: false }))
})
it('files use only VirusTotal and send the digest, never content', async () => {
  kind = 'file'; value = 'a'.repeat(64)
  renderWithProviders(<DirectEnrichment slug="demo" ids={[1]} />)
  fireEvent.click(await screen.findByRole('button', { name: 'Lookup' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/demo/enrich', { service: 'virustotal', kind: 'file', value, refresh: false }))
  expect(screen.queryByText('AbuseIPDB')).not.toBeInTheDocument()
})
it('keeps scores separated and cached results visible on a failed refresh', async () => {
  entries = [{ service: 'abuseipdb', value, kind, fetched: '2026-09-15T00:00:00Z', result: { known: true, score: 0, of: 100, reports: 0, distinct_reporters: 0 } }]
  vi.mocked(post).mockRejectedValue(new Error('Provider rate limit reached'))
  renderWithProviders(<DirectEnrichment slug="demo" ids={[1]} />)
  expect(await screen.findByText('0 / 100')).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
  expect(await screen.findByRole('alert')).toHaveTextContent('Provider rate limit reached')
  expect(screen.getByText('0 / 100')).toBeVisible()
  expect(post).toHaveBeenCalledWith('/api/cases/demo/enrich', expect.objectContaining({ refresh: true }))
})
it('does not substitute another URL report differing only in path case', async () => {
  kind = 'url'; value = 'https://example.test/Report'
  entries = [{ service: 'virustotal', value: 'https://example.test/report', kind, fetched: '2026-09-15', result: { known: true, score: 99, of: 100 } }]
  renderWithProviders(<DirectEnrichment slug="demo" ids={[1]} />)
  expect(await screen.findByRole('button', { name: 'Lookup' })).toBeVisible()
  expect(screen.queryByText('99 / 100')).not.toBeInTheDocument()
})
it('does not offer direct actions when OpenCTI is configured', async () => {
  configured = true
  renderWithProviders(<DirectEnrichment slug="demo" ids={[1]} />)
  await waitFor(() => expect(api).toHaveBeenCalledWith('/api/opencti/settings'))
  expect(screen.queryByRole('button', { name: 'Lookup' })).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})
it('saves and removes keys explicitly while leaving inputs empty on read', async () => {
  renderWithProviders(<DirectEnrichmentSettings />)
  const key = await screen.findByLabelText('VirusTotal API key')
  expect(key).toHaveValue('')
  expect(await screen.findByText('…1234')).toBeVisible()
  fireEvent.change(key, { target: { value: 'new-provider-key' } })
  fireEvent.click(screen.getAllByRole('button', { name: 'Save' })[0])
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/settings/key', { service: 'virustotal', key: 'new-provider-key' }))
  await waitFor(() => expect(key).toHaveValue(''))
  fireEvent.click(screen.getAllByRole('button', { name: 'Remove key' })[0])
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/settings/key', { service: 'virustotal', key: '' }))
})
