import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post, type Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { OpenCtiActivity } from './OpenCtiActivity'

vi.mock('../api', async original => ({ ...(await original<typeof import('../api')>()), api: vi.fn(), post: vi.fn() }))
const ioc = { id: 1, type: 'ip', value: '198.51.100.4' } as Ioc
let cleared = false
const show = () => renderWithProviders(<OpenCtiActivity slug="qa" iocs={[ioc]} allowRetry />)
beforeEach(() => {
  vi.clearAllMocks(); cleared = false
  vi.mocked(api).mockImplementation(async path => path === '/api/opencti/settings' ? { configured: true } : {
    lookups: [], sync: [],
    jobs: [
      { id: 1, kind: 'opencti-lookup', state: 'failed', message: 'Previous check', error: 'Synthetic error', created: '2026-09-11T12:00:00', activity_hidden: cleared },
      { id: 2, kind: 'opencti-lookup', state: 'running', message: 'Current check', created: '2026-09-11T12:01:00', progress: 0.4 },
    ],
    enrichments: [{ id: 'e', ioc_id: 1, connector_id: 'c', connector_name: 'Example connector', state: 'complete', updated: '2026-09-11T12:00:00', activity_hidden: cleared }],
    exports: [{ id: 'x', state: 'partial', updated: '2026-09-11T12:00:00', stats: { objects: 3 }, activity_hidden: cleared }],
  })
  vi.mocked(post).mockImplementation(async path => {
    if (path.endsWith('/activity/clear')) { cleared = true; return { cleared: 3 } }
    return { job_id: 3 }
  })
})
it('organizes jobs, enrichments and receipts in tabs and clears all finished activity while retaining running jobs', async () => {
  const view = show()
  expect(await screen.findByText('Previous check')).toBeVisible()
  expect(screen.getByRole('progressbar', { name: 'Progress' })).toHaveAttribute('value', '0.4')
  fireEvent.click(screen.getByRole('tab', { name: /Enrichment requests/ }))
  expect(screen.getByText(ioc.value)).toBeVisible()
  expect(screen.getByText('IPv4')).toBeVisible()
  expect(screen.getByText('Example connector')).toBeVisible()
  fireEvent.click(screen.getByRole('tab', { name: /Transfer history/ }))
  expect(screen.getByText('Transfer · 3 objects')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Retry incomplete transfer' })).toBeEnabled()
  expect(post).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Clear' })).toBeDisabled())
  expect(post).toHaveBeenCalledWith('/api/cases/qa/opencti/activity/clear', {})
  expect(screen.getByText('No activities to show.')).toBeVisible()
  fireEvent.click(screen.getByRole('tab', { name: /OpenCTI jobs/ }))
  expect(screen.getByText('Current check')).toBeVisible()
  expect(screen.queryByText('Previous check')).not.toBeInTheDocument()
  view.unmount(); show()
  expect(await screen.findByText('Current check')).toBeVisible()
  expect(screen.queryByText('Previous check')).not.toBeInTheDocument()
})
it('keeps activity visible when clearing fails', async () => {
  vi.mocked(post).mockRejectedValue(new Error('Synthetic clear failure'))
  show(); await screen.findByText('Previous check')
  fireEvent.click(screen.getByRole('button', { name: 'Clear' }))
  expect(await screen.findByText('Synthetic clear failure')).toBeVisible()
  expect(screen.getByText('Previous check')).toBeVisible()
  expect(screen.getByRole('button', { name: 'Clear' })).toBeEnabled()
})
