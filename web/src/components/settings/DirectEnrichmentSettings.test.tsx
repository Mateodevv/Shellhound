import { beforeEach, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { api, post } from '../../api'
import { renderWithProviders } from '../../test/setup'
import { DirectEnrichmentSettings } from './DirectEnrichmentSettings'

vi.mock('../../api', async original => ({ ...(await original<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))

const settings = { services: { virustotal: { configured: true, hint: '…1234' }, abuseipdb: { configured: false, hint: '' } } }
beforeEach(() => {
  vi.mocked(api).mockImplementation(async path => path === '/api/settings' ? settings as never : { configured: false } as never)
  vi.mocked(post).mockResolvedValue({})
})

it('blocks editing and submission until settings load, then shows the stored hint with an empty input', async () => {
  let resolveSettings!: (value: never) => void
  vi.mocked(api).mockImplementation(async path => path === '/api/settings' ? new Promise(resolve => { resolveSettings = resolve }) : { configured: false } as never)
  renderWithProviders(<DirectEnrichmentSettings />)
  const key = screen.getByLabelText('VirusTotal API key')
  expect(key).toBeDisabled()
  expect(screen.getAllByRole('button', { name: 'Save' })[0]).toBeDisabled()
  fireEvent.submit(key.closest('form')!)
  expect(post).not.toHaveBeenCalled()
  resolveSettings(settings as never)
  expect(await screen.findByText('…1234')).toBeVisible()
  expect(key).toBeEnabled()
  expect(key).toHaveValue('')
  expect(screen.getAllByRole('button', { name: 'Save' })[0]).toBeDisabled()
})

it('keeps the draft and disables all provider actions after a failed refresh until retry succeeds', async () => {
  const { qc } = renderWithProviders(<DirectEnrichmentSettings />)
  const key = await screen.findByLabelText('VirusTotal API key')
  await screen.findByText('…1234')
  fireEvent.change(key, { target: { value: 'synthetic-draft' } })
  vi.mocked(api).mockImplementation(async path => {
    if (path === '/api/settings') throw new Error('Settings unavailable')
    return { configured: false } as never
  })
  await qc.refetchQueries({ queryKey: ['settings'] })
  expect(await screen.findByRole('alert')).toHaveTextContent('Settings unavailable')
  expect(key).toBeDisabled()
  expect(key).toHaveValue('synthetic-draft')
  const form = key.closest('form')!
  expect(within(form).getByRole('button', { name: 'Save' })).toBeDisabled()
  expect(within(form).getByRole('button', { name: 'Remove key' })).toBeDisabled()
  fireEvent.submit(form)
  fireEvent.click(within(form).getByRole('button', { name: 'Remove key' }))
  expect(post).not.toHaveBeenCalled()
  vi.mocked(api).mockImplementation(async path => path === '/api/settings' ? settings as never : { configured: false } as never)
  fireEvent.click(screen.getByRole('button', { name: 'Retry' }))
  await waitFor(() => expect(key).toBeEnabled())
  expect(key).toHaveValue('synthetic-draft')
  expect(within(form).getByRole('button', { name: 'Save' })).toBeEnabled()
  expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
})
