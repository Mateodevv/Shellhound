import { fireEvent, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { api, post, type Ioc } from '../api'
import { renderWithProviders } from '../test/setup'
import { IocDetails } from './IocDetails'

vi.mock('../api', async orig => ({ ...(await orig<typeof import('../api')>()), api: vi.fn(), post: vi.fn(), patch: vi.fn() }))
const ip: Ioc = { id: 1, type: 'ip', value: '198.51.100.9', note: '', origin: 'Test source', tags: [],
  added: '', first_seen: null, last_seen: null, links: [], assessment: 'unassessed' }
const cve: Ioc = { ...ip, id: 2, type: 'vulnerability', value: 'CVE-2026-12345' }
const detail = { object: ip, observations: [{ id: 'obs-1', kind: 'http-request', source_ref: 'access-log-1', path: '/sample.txt',
  local_path: 'C:/evidence/raw.log', finding_id: null, evidence_id: 1, count: 5, first_seen: '', last_seen: '', detail: 'Five requests', active: true }],
  sources: [], findings: [], assessments: [], relationships: [],
  relationship_types: { 'exploit-attempt': { sources: ['ip'], targets: ['vulnerability'] },
    executed: { sources: ['ip'], targets: ['file'] } } }

beforeEach(() => {
  vi.mocked(api).mockImplementation(async url => url.endsWith('/detail') ? detail : { lookups: [] })
  vi.mocked(post).mockResolvedValue({})
  vi.clearAllMocks()
})
const show = () => renderWithProviders(<IocDetails slug="synthetic" id={1} iocs={[ip, cve]} onClose={() => {}} />)

describe('Structured IOC details', () => {
  it('loads local detail without starting enrichment or transfers', async () => {
    show()
    await screen.findByText('Case assessment:')
    expect(post).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Save assessment' })).toBeDisabled()
    fireEvent.click(screen.getByRole('tab', { name: 'Observations' }))
    expect(await screen.findByText('Five requests')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'OpenCTI' }))
    expect(post).not.toHaveBeenCalled()
  })

  it('saves a separate assessment with an explicit reason', async () => {
    show()
    await screen.findByText('Case assessment:')
    fireEvent.change(screen.getByLabelText('New assessment'), { target: { value: 'suspicious' } })
    fireEvent.change(screen.getByLabelText('Assessment reason'), { target: { value: 'Hostile request in log line 5' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save assessment' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/iocs/1/assessments', {
      state: 'suspicious', reason: 'Hostile request in log line 5',
    }))
  })

  it('filters relationship targets and requires a source reference', async () => {
    show()
    await screen.findByText('Case assessment:')
    fireEvent.click(screen.getByRole('tab', { name: 'Relationships' }))
    fireEvent.change(screen.getByLabelText('Relationship'), { target: { value: 'executed' } })
    expect(screen.queryByRole('option', { name: 'vulnerability: CVE-2026-12345', hidden: false })).toBeInTheDocument() // source selector only
    expect(screen.getByLabelText('Target').querySelectorAll('option')).toHaveLength(1)
    fireEvent.change(screen.getByLabelText('Relationship'), { target: { value: 'exploit-attempt' } })
    fireEvent.change(screen.getByLabelText('Target'), { target: { value: '2' } })
    expect(screen.getByRole('button', { name: 'Add relationship' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Evidence reference'), { target: { value: 'Log line 5' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add relationship' }))
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/synthetic/ioc-relationships', expect.objectContaining({
      src: 1, dst: 2, kind: 'exploit-attempt', reference: 'Log line 5',
    })))
  })
})
