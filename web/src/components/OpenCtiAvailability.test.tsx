import { act, fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, patch, post, type Ioc } from '../api'
import { renderWithProviders, testQueryClient } from '../test/setup'
import { Start } from '../views/Start'
import { IocBox } from '../views/IocBox'
import { IocDetails } from './IocDetails'

vi.mock('../api', async original => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), patch: vi.fn(), post: vi.fn() }))
vi.mock('../geo', () => ({ useGeo: () => null }))
const ip: Ioc = { id: 1, type: 'ip', value: '198.51.100.1', note: '', origin: 'Manual', tags: ['reviewed'], added: '', first_seen: null, last_seen: null, links: [], assessment: 'malicious' }
const cached = { lookups: [{ ioc_id: 1, status: 'known', entities: [{ id: 'remote', name: ip.value, score: 58, url: 'https://cti.example/observable/remote' }] }], sync: [{ ioc_id: 1, status: 'error' }], jobs: [] }
let settings: { configured: boolean; url: string; ingester_id: string; token_hint: string; sample_uploads: boolean }
beforeEach(() => {
  vi.clearAllMocks(); sessionStorage.clear(); history.replaceState(null, '', '/')
  settings = { configured: false, url: '', ingester_id: '', token_hint: '', sample_uploads: false }
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/opencti/settings') return { ...settings }
    if (path === '/api/state') return { workspace: 'Synthetic workspace', cases: [] }
    if (path === '/api/archives') return { archives: [] }
    if (path.endsWith('/cross-case')) return { entries: [] }
    if (path.endsWith('/iocs')) return [ip]
    if (path.endsWith('/detail')) return { object: ip, observations: [], sources: [], findings: [], assessments: [], relationships: [] }
    if (path.endsWith('/opencti')) return cached
    throw new Error(`Unexpected API: ${path}`)
  })
  vi.mocked(patch).mockImplementation(async (_path, body) => {
    const input = body as { url: string; ingester_id: string; token?: string }
    settings = { ...settings, ...input, token_hint: input.token ? '…test' : '', configured: Boolean(input.url && input.ingester_id && input.token) }
    return { ...settings }
  })
})

it('configures OpenCTI from the case picker and activates actions without a reload', async () => {
  const { qc, rerender } = renderWithProviders(<Start onOpen={() => {}} />)
  fireEvent.click(screen.getByRole('button', { name: 'OpenCTI settings' }))
  fireEvent.change(await screen.findByLabelText('OpenCTI URL'), { target: { value: 'https://cti.example' } })
  fireEvent.change(screen.getByLabelText('TAXII push ingester ID'), { target: { value: 'synthetic-ingester' } })
  fireEvent.change(screen.getByLabelText(/Integration token/), { target: { value: 'synthetic-token' } })
  expect(screen.getByRole('button', { name: 'Test saved connection' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Save' }))
  await waitFor(() => expect(qc.getQueryData(['opencti-settings'])).toMatchObject({ configured: true }))
  expect(patch).toHaveBeenCalledWith('/api/opencti/settings', expect.objectContaining({ token: 'synthetic-token', sample_uploads: false }))
  expect(post).not.toHaveBeenCalled()
  expect(screen.getByLabelText(/Integration token/)).toHaveValue('')
  rerender(<IocBox slug="synthetic" gotoView={() => {}} />)
  await waitFor(() => expect(screen.getByRole('button', { name: 'Check all' })).toBeEnabled())
  expect(screen.getByRole('button', { name: 'Transfer all' })).toBeEnabled()
  expect(screen.getByRole('button', { name: 'Enrich all' })).toBeEnabled()
  expect(post).not.toHaveBeenCalled()
})

it('ignores a remembered CTI filter and hides cached statuses while local IOC controls stay available', async () => {
  sessionStorage.setItem('ioc-workspace:synthetic', JSON.stringify({ status: 'sync:exported' }))
  const qc = testQueryClient()
  qc.setQueryData(['opencti', 'synthetic'], cached)
  renderWithProviders(<IocBox slug="synthetic" gotoView={() => {}} />, qc)
  expect(await screen.findByRole('button', { name: `Open ${ip.value}` })).toBeVisible()
  fireEvent.click(screen.getByRole('button', { name: 'Filters' }))
  expect(screen.queryByLabelText('OpenCTI filter')).not.toBeInTheDocument()
  expect(screen.queryByText('Transfer error')).not.toBeInTheDocument()
  expect(screen.queryByText('Not checked')).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Check all' })).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Add IOC' })).toBeVisible()
  expect(vi.mocked(api).mock.calls.some(([path]) => path.endsWith('/opencti'))).toBe(false)
})

it('hides cached score, links and actions immediately on removal, retaining assessment, tags and Trace', async () => {
  settings.configured = true
  const { qc } = renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip]} onClose={() => {}} embedded />)
  expect(await screen.findByText('58 / 100')).toBeVisible()
  expect(screen.getByRole('link', { name: 'Open in OpenCTI' })).toBeVisible()
  await act(async () => { qc.setQueryData(['opencti-settings'], { ...settings, configured: false }) })
  await waitFor(() => expect(screen.queryByText('Score')).not.toBeInTheDocument())
  expect(screen.queryByRole('link', { name: 'Open in OpenCTI' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Check in OpenCTI' })).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Change assessment' })).toBeVisible()
  expect(screen.getByRole('button', { name: 'Add tag' })).toBeVisible()
  expect(screen.getByRole('tab', { name: 'Trace' })).toBeVisible()
  expect(screen.getByText('reviewed')).toBeVisible()
})

it('keeps configured actions available when OpenCTI data cannot be loaded', async () => {
  settings.configured = true
  const original = vi.mocked(api).getMockImplementation()!
  vi.mocked(api).mockImplementation(async path => {
    if (path.endsWith('/opencti')) throw new Error('Synthetic outage')
    return original(path)
  })
  renderWithProviders(<IocBox slug="synthetic" gotoView={() => {}} />)
  await waitFor(() => expect(screen.getByRole('button', { name: 'Check all' })).toBeEnabled())
  expect(await screen.findByRole('alert')).toHaveTextContent('Synthetic outage')
  expect(post).not.toHaveBeenCalled()
})

it('leaves the settings entry accessible while configuration is still loading', async () => {
  const original = vi.mocked(api).getMockImplementation()!
  vi.mocked(api).mockImplementation(path => path === '/api/opencti/settings' ? new Promise(() => {}) : original(path))
  renderWithProviders(<Start onOpen={() => {}} />)
  fireEvent.click(screen.getByRole('button', { name: 'OpenCTI settings' }))
  expect(await screen.findByRole('status')).toHaveTextContent('Loading')
  expect(post).not.toHaveBeenCalled()
})
