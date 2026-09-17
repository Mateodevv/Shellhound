import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post } from '../api'
import { renderWithProviders } from '../test/setup'
import type { LogEvent, LogSource } from '../logApi'
import { Logs } from './Logs'
import { LogImport } from '../components/logview/LogSources'
import { LogEntryContext } from '../components/logview/LogEntryContext'

vi.mock('../api', async orig => ({ ...(await orig<typeof import('../api')>()), api: vi.fn(), post: vi.fn(), patch: vi.fn() }))
vi.mock('./AccessLogs', () => ({ AccessLogs: () => <div>Access investigation</div> }))

const source = { id: 'ftp-source', path: 'C:/Sample logs/ftp.log', family: 'ftp', format: 'xferlog', settings: {},
  fresh: true, state: 'ready', warning: '', accepted: false, fingerprint: 'a'.repeat(64), stats: { events: 101 } } as LogSource
const entry = { id: 'event-one', source_id: source.id, source_name: 'ftp.log', fingerprint: source.fingerprint,
  family: 'ftp', epoch: 1789380123, raw_time: 'Mon Sep 14 10:02:03 2026', time_meaning: 'event',
  line: 1, line_end: 1, ip: '2001:db8::7', remote_host: '', account: 'demo', path: '/srv/site/marker.txt',
  artifact: '', operation: 'upload', outcome: 'success', signature: '', detection: false, raw: 'Harmless transfer', fresh: true } as LogEvent
const formats = { auto: 'Detect automatically', xferlog: 'FTP transfer log (xferlog)', text: 'Other text (manual review)' }

beforeEach(() => {
  history.replaceState({}, '', '/?case=demo&view=logs&section=ftp')
  vi.mocked(api).mockImplementation(async url => {
    if (url.endsWith('/log-sources')) return { sources: [source], formats }
    if (url.includes('/context?')) return { event: entry, lines: [{ line: 1, text: entry.raw, selected: true }] }
    throw new Error('Unexpected test endpoint')
  })
  vi.mocked(post).mockImplementation(async (url, body) => {
    if (url.endsWith('/search')) return (body as { offset?: number }).offset ?
      { rows: [{ ...entry, id: 'page-two', line: 101 }], total: 101, next_offset: null } :
      { rows: [entry, { ...entry, id: 'old', line: 2, fresh: false }], total: 101, next_offset: 100 }
    return {}
  })
})

it('defaults to an available log family and preserves the access investigation tab', async () => {
  history.replaceState({}, '', '/?case=demo&view=logs')
  const go = vi.fn()
  renderWithProviders(<Logs slug="demo" gotoView={go} />)
  expect(await screen.findByRole('checkbox', { name: 'Select ftp.log line 1' })).toBeEnabled()
  expect(screen.getByRole('tab', { name: /FTP/ })).toHaveAttribute('aria-selected', 'true')
  fireEvent.click(screen.getByRole('tab', { name: 'Access' }))
  expect(go).toHaveBeenCalledWith('logs', { section: 'access' })
})

it('applies only visible current selections and clears selection on another page', async () => {
  renderWithProviders(<Logs slug="demo" gotoView={vi.fn()} />)
  fireEvent.click(await screen.findByRole('checkbox', { name: 'Select visible current entries' }))
  expect(screen.getByRole('checkbox', { name: 'Select ftp.log line 2' })).toBeDisabled()
  fireEvent.click(screen.getByRole('button', { name: 'Add selected to Findings (1)' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/demo/log-events/apply', {
    selections: [{ id: entry.id, fingerprint: entry.fingerprint }], note: '',
  }))
  fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
  expect(await screen.findByRole('checkbox', { name: 'Select ftp.log line 101' })).not.toBeChecked()
  expect(screen.getByRole('button', { name: 'Add selected to Findings (0)' })).toBeDisabled()
})

it('keeps errors distinct from an empty successful search', async () => {
  vi.mocked(post).mockRejectedValue(new Error('Search unavailable'))
  renderWithProviders(<Logs slug="demo" gotoView={vi.fn()} />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Search unavailable')
  expect(screen.queryByText('No entries to display')).not.toBeInTheDocument()
})

it('previews and saves the analyst format correction and source timezone', async () => {
  vi.mocked(post).mockImplementation(async url => url.endsWith('/preview') ? { sources: [{ ...source, format: 'text', ambiguous: true }], formats } : {})
  const done = vi.fn()
  renderWithProviders(<LogImport slug="demo" path="C:/Sample logs" onClose={vi.fn()} onDone={done} />)
  const select = await screen.findByRole('combobox', { name: /Format for/ })
  fireEvent.change(select, { target: { value: 'xferlog' } })
  fireEvent.change(screen.getByLabelText('Source timezone (when not recorded)'), { target: { value: 'custom' } })
  fireEvent.change(screen.getByLabelText('Choose time zone…'), { target: { value: '+02:00' } })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Add these log sources' })).toBeEnabled())
  fireEvent.click(screen.getByRole('button', { name: 'Add these log sources' }))
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/demo/log-sources/register', {
    path: 'C:/Sample logs', label: '', timezone: '+02:00', formats: { [source.id]: 'xferlog' },
  }))
  expect(done).toHaveBeenCalled()
})

it('offers Open file only for a currently verified local evidence path', async () => {
  vi.mocked(api).mockResolvedValue({ event: { ...entry, artifact: '/missing/marker.txt', artifact_available: false }, lines: [] })
  renderWithProviders(<LogEntryContext slug="demo" event={entry} onFile={vi.fn()} />)
  await screen.findByRole('link', { name: 'Open in Logs' })
  expect(screen.queryByRole('button', { name: 'Open file' })).not.toBeInTheDocument()
})

it('retains the saved excerpt when current context is stale', async () => {
  vi.mocked(api).mockRejectedValue(new Error('Source changed; analyze again'))
  renderWithProviders(<LogEntryContext slug="demo" event={entry} />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Source changed')
  expect(screen.getByText(entry.raw)).toBeInTheDocument()
})
