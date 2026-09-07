import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, type Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { IocBox } from './IocBox'

vi.mock('../api', async orig => ({ ...(await orig<typeof import('../api')>()), api: vi.fn() }))
vi.mock('../components/OpenCti', () => ({ OpenCtiToolbar: ({ selectedIds }: { selectedIds: number[] }) => <div data-testid="action-ids">{selectedIds.join(',')}</div> }))
vi.mock('../components/IocDetails', () => ({ IocDetails: ({ id, onNavigate, onDirtyChange }: { id: number; onNavigate: (id: number) => void; onDirtyChange: (v: boolean) => void }) => <div><h2>Object detail {id}</h2><button onClick={() => onNavigate(2)}>Related object</button><button onClick={() => onDirtyChange(true)}>Edit draft</button></div> }))
const object = (id: number, overrides: Partial<Ioc> = {}): Ioc => ({ id, type: 'ip', value: `198.51.100.${id}`, note: '', tags: ['hunt'], origin: 'Pattern Hunt', added: String(id).padStart(4, '0'), first_seen: null, last_seen: null, links: [], assessment: 'malicious', ...overrides })
let rows: Ioc[]
beforeEach(() => {
  sessionStorage.clear(); history.replaceState(null, '', '/?view=iocbox&case=qa'); vi.clearAllMocks()
  rows = Array.from({ length: 126 }, (_, i) => object(i + 1))
  vi.mocked(api).mockImplementation(async url => url.endsWith('/iocs') ? rows : url.endsWith('/cross-case') ? { entries: [], cases_skipped: 0 } : { lookups: [], sync: [], jobs: [] })
})
const show = () => renderWithProviders(<IocBox slug="qa" gotoView={() => {}} />)
describe('IOC investigation workspace', () => {
  it('paginates the entire result set and separates inspection from selection', async () => {
    show(); await screen.findByRole('button', { name: 'Open 198.51.100.126' })
    expect(within(screen.getByRole('list', { name: 'Object list' })).getAllByRole('listitem')).toHaveLength(50)
    expect(screen.queryByLabelText('Selection actions')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Open 198.51.100.126' }))
    expect(await screen.findByText('Object detail 126')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Select 198.51.100.126' })).not.toBeChecked()
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(await screen.findByRole('button', { name: 'Open 198.51.100.76' })).toBeInTheDocument()
    expect(screen.getByText('Object detail 126')).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('Search objects…'), { target: { value: '198.51.100.1' } })
    expect(screen.getByRole('button', { name: 'Open 198.51.100.1' })).toBeInTheDocument()
  })
  it('retains the explicit selection across filters and excludes newly arriving objects', async () => {
    show(); await screen.findByRole('button', { name: 'Open 198.51.100.126' }); fireEvent.click(screen.getByRole('button', { name: 'Select page' }))
    await screen.findByText('50 objects selected')
    fireEvent.change(screen.getByPlaceholderText('Search objects…'), { target: { value: '198.51.100.1' } })
    expect(screen.getByText(/outside current filters/i)).toBeInTheDocument()
    expect(screen.getByTestId('action-ids').textContent?.split(',')).toHaveLength(50)
    fireEvent.click(screen.getByRole('button', { name: 'Clear selection' }))
    expect(screen.queryByTestId('action-ids')).not.toBeInTheDocument()
  })
  it('finds files by secondary hashes and includes their existing hash entries in actions', async () => {
    rows = [object(1, { type: 'file', value: 'a'.repeat(64), file: { names: ['sample.php'], hashes: { 'SHA-256': 'a'.repeat(64), MD5: 'b'.repeat(32) }, size: 4, classification: 'webshell', verified_at: '' } }), object(2, { type: 'hash', value: 'a'.repeat(64), file_ids: [1] })]
    show(); await screen.findByRole('button', { name: 'Open sample.php' })
    expect(screen.getAllByRole('listitem')).toHaveLength(1)
    fireEvent.change(screen.getByPlaceholderText('Search objects…'), { target: { value: 'b'.repeat(32) } })
    fireEvent.click(screen.getByRole('checkbox', { name: 'Select sample.php' }))
    expect(screen.getByTestId('action-ids')).toHaveTextContent('1,2')
  })
  it('keeps filters while traversing relationships and protects an unsaved draft', async () => {
    show(); fireEvent.click(await screen.findByRole('button', { name: 'Open 198.51.100.126' }))
    fireEvent.change(screen.getByPlaceholderText('Search objects…'), { target: { value: '198.51.100.126' } })
    fireEvent.click(screen.getByRole('button', { name: 'Related object' }))
    expect(await screen.findByText('Object detail 2')).toBeInTheDocument()
    expect(screen.getByText('Outside current filters')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Edit draft' }))
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    fireEvent.click(screen.getByRole('button', { name: 'Back' }))
    expect(screen.getByText('Object detail 2')).toBeInTheDocument()
    confirm.mockReturnValue(true)
    fireEvent.click(screen.getByRole('button', { name: 'Back' }))
    await waitFor(() => expect(screen.getByText('Object detail 126')).toBeInTheDocument())
    confirm.mockRestore()
  })
})
