import { act, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post, type Ioc } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { OpenCtiToolbar } from './OpenCti'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
let configured = false
beforeEach(() => {
  vi.clearAllMocks(); configured = false
  vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { configured } : { lookups: [{ score: 90 }] })
})
const iocs = [{ id: 1, type: 'ip', value: '198.51.100.1' }] as Ioc[]
it('shows and hides export after saved connection changes without reviving lookup actions', async () => {
  const { qc } = renderWithProviders(<OpenCtiToolbar slug="qa" iocs={iocs} selectedIds={[1]} trailingAction={<button>Local action</button>} />)
  await waitFor(() => expect(api).toHaveBeenCalledWith('/api/opencti/settings'))
  expect(screen.queryByRole('button', { name: 'Transfer to OpenCTI' })).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Local action' })).toBeVisible()
  configured = true
  await act(async () => { await qc.invalidateQueries({ queryKey: ['opencti-settings'] }) })
  expect(await screen.findByRole('button', { name: 'Transfer to OpenCTI' })).toBeEnabled()
  configured = false
  await act(async () => { await qc.invalidateQueries({ queryKey: ['opencti-settings'] }) })
  await waitFor(() => expect(screen.queryByRole('button', { name: 'Transfer to OpenCTI' })).not.toBeInTheDocument())
  expect(screen.queryByRole('button', { name: /Check|Enrich/ })).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})
