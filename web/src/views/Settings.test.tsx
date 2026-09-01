import { fireEvent, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { post, put, type SettingsInfo } from '../api'
import { renderWithProviders } from '../test/setup'
import { OpenCtiSection } from './Settings'

vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  post: vi.fn(), put: vi.fn(),
}))

const settings = {
  services: {}, enrichment_ack: false, path: '',
  opencti: {
    configured: true, verified: false,
    url: 'https://opencti.test',
    taxii_collection_url: 'https://opencti.test/taxii/collections/one/objects',
    token_hint: '…abcd', author_id: '', author_name: '',
    default_marking_id: '', default_marking_name: '',
    verified_at: '', version: '', capabilities: [], markings: [], authors: [],
  },
} satisfies SettingsInfo

describe('OpenCTI settings', () => {
  it('never pre-fills the token and tests only the stored connection', async () => {
    vi.mocked(post).mockResolvedValue({ ok: true })
    renderWithProviders(<OpenCtiSection settings={settings} />)

    const token = screen.getByLabelText('API token') as HTMLInputElement
    expect(token.type).toBe('password')
    expect(token.value).toBe('')
    expect(token.placeholder).toBe('…abcd')
    fireEvent.click(screen.getByRole('button', { name: 'Test connection' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/settings/opencti/test'))
  })

  it('sends a replacement token only when the operator enters one', async () => {
    vi.mocked(put).mockResolvedValue({})
    renderWithProviders(<OpenCtiSection settings={settings} />)
    fireEvent.change(screen.getByLabelText('API token'), {
      target: { value: 'replacement-secret' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save connection' }))
    await waitFor(() => expect(put).toHaveBeenCalledWith('/api/settings/opencti', {
      url: 'https://opencti.test',
      taxii_collection_url: 'https://opencti.test/taxii/collections/one/objects',
      token: 'replacement-secret',
    }))
  })
})
