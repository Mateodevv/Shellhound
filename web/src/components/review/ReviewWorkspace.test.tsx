import { beforeEach, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { api, post, type ArtifactContext, type Finding } from '../../api'
import { renderWithProviders, testQueryClient } from '../../test/setup'
import { ArtifactWindow } from './ArtifactWindow'
import { SuccessfulAccesses, TableRecord, FindingRequests } from './ReviewEvidence'
import { ArtifactEnrichment } from '../enrichment/ArtifactEnrichment'
vi.mock('../../api', async orig => ({ ...(await orig<typeof import('../../api')>()), api: vi.fn(), post: vi.fn() }))
vi.mock('../../geo', () => ({ useGeo: () => null }))
const finding: Finding = { id: 1, fingerprint: 'safe', source: 'webshell', severity: 1, rule: 'Synthetic observation', artifact_kind: 'file', artifact: '/evidence/note.txt', line: 2, evidence: 'marker', triage: 'new', triage_note: '', retired: 0, created: '', last_seen: '' }
const base: ArtifactContext = { artifact: finding.artifact, kind: 'file', findings: [finding], triage: 'new', triage_note: 'Historical note', triaged_at: '', worst: 1, sources: ['webshell'], related_ips: [], file: { exists: true, available: true, sha256: 'a'.repeat(64), preview: { from_line: 1, focus: 2, lines: ['safe text','selected marker'] } } }
function renderReview(context: ArtifactContext, configured = false) {
  vi.mocked(api).mockImplementation(async url => (url === '/api/opencti/settings' ? { configured } : url.includes('/file?') ? { mode: 'raw', size: 30, offset: 0, length: 30, window: 262144, eof: true, from_line: 1, lines: ['safe text', 'selected marker'] } : context) as never)
  return renderWithProviders(<ArtifactWindow slug="case" artifact={{ artifact: context.artifact, artifact_kind: context.kind, worst: 1, triage: 'new', triage_note: '' }} roots={[]} collected={[]} onClose={vi.fn()} onSave={vi.fn()} onView={vi.fn()} onTrace={vi.fn()} />,testQueryClient())
}
beforeEach(() => { vi.clearAllMocks(); vi.mocked(post).mockResolvedValue({ total: 0, rows: [], methods: [], timeline: [] }) })
it('keeps code visible on Linked IPs and moves file navigation into one dropdown', async () => {
  renderReview(base)
  expect(await screen.findByText('selected marker')).toBeVisible()
  await userEvent.click(screen.getByRole('tab', { name: /Linked IPs/ }))
  expect(screen.getByText('selected marker')).toBeVisible()
  expect(screen.getAllByRole('button', { name: /Expand file/ })).toHaveLength(1)
  expect(screen.queryByRole('button', { name: 'Show in file manager' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: 'Open…' }))
  expect(screen.getByRole('button', { name: 'Show in file manager' })).toBeVisible()
  expect(screen.getByRole('link', { name: 'Open IOC Box' })).toBeVisible()
  expect(screen.queryByRole('tab', { name: 'Enrichment' })).not.toBeInTheDocument()
})
it('uses an embedded Trace tab without a separate Requests tab or trace button', async () => {
  renderReview({ ...base, artifact: '192.0.2.1', kind: 'client', file: undefined, findings: [{ ...finding, artifact: '192.0.2.1', artifact_kind: 'client', line: null }] })
  expect(await screen.findByRole('tab', { name: 'Successful file accesses' })).toBeVisible()
  expect(screen.queryByRole('tab', { name: /^Requests/ })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: /Open trace/ })).not.toBeInTheDocument()
  expect(screen.getByRole('tab', { name: 'Trace' })).toHaveAttribute('aria-selected', 'true')
  expect(await screen.findByRole('button', { name: /Synthetic observation/ })).toBeVisible()
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/trace', expect.objectContaining({ ips: ['192.0.2.1'] })))
  expect(screen.getAllByRole('dialog')).toHaveLength(1)
})
it('keeps OpenCTI file enrichment in the IOC Box without silently collecting an artifact', async () => {
  renderReview(base,true)
  expect(await screen.findByText(/Lookups use your configured OpenCTI/)).toBeVisible()
  expect(screen.queryByRole('tab', { name: 'Enrichment' })).not.toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Ask VirusTotal' })).not.toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Open IOC Box' })).toBeVisible()
  expect(screen.getByText('selected marker')).toBeVisible()
  expect(post).not.toHaveBeenCalled()
})
it('resizes context with keyboard without triggering review scrolling', async () => {
  renderReview(base)
  const divider=await screen.findByRole('separator')
  fireEvent.keyDown(divider,{ key: 'ArrowRight' })
  expect(divider).toHaveAttribute('aria-valuenow','30')
})
it('links successful access evidence to its local file without network navigation', async () => {
  const onView=vi.fn()
  vi.mocked(api).mockResolvedValue({ available:true,total:1,rows:[{ path:'/note.txt',hits:3,last_epoch:20,statuses:[200,206],files:[{ path:'/evidence/note.txt',name:'note.txt' }] }] })
  renderWithProviders(<SuccessfulAccesses slug="case" ip="192.0.2.1" onView={onView} />)
  await userEvent.click(await screen.findByRole('button',{name:'Open file'}))
  expect(onView).toHaveBeenCalledWith('/evidence/note.txt',null)
  expect(screen.getByText('206')).toBeVisible()
})
it('requires source choice for table records and moves between real row ordinals', async () => {
  vi.mocked(api).mockResolvedValue({ table:'items',row:2,columns:[{name:'label',value:'safe marker',truncated:false}],truncated:false })
  renderWithProviders(<TableRecord slug="case" tableName="items" finding={{...finding,artifact_kind:'table',source:'sqldb',artifact:'items',evidence:'safe marker'}} sources={[{dump_id:1,dump_path:'/a.sql',table_id:10,rows:5},{dump_id:2,dump_path:'/b.sql',table_id:20,rows:4}]} />)
  expect(api).not.toHaveBeenCalled()
  await userEvent.selectOptions(screen.getByRole('combobox'), '2')
  expect(await screen.findByText('safe marker')).toBeVisible()
  expect(api).toHaveBeenCalledWith('/api/cases/case/database/table-row?table_id=20&row=2')
  await userEvent.click(screen.getByRole('button',{name:'Next row'}))
  await waitFor(() => expect(api).toHaveBeenCalledWith('/api/cases/case/database/table-row?table_id=20&row=3'))
})
it('previews compatible connectors and runs only explicitly selected enrichment', async () => {
  vi.mocked(api).mockImplementation(async url => (url==='/api/opencti/settings' ? { configured:true } : url.endsWith('/iocs') ? [{id:7,type:'ip',value:'192.0.2.1',tags:[]}] : { lookups:[],jobs:[],enrichments:[] }) as never)
  vi.mocked(post).mockResolvedValue({entities:[{ioc_id:7,type:'ip',value:'192.0.2.1',requires_creation:false}],connectors:[{id:'one',name:'Example connector',active:true,scope:['IPv4-Addr'],auto:false}],warnings:[]})
  renderWithProviders(<ArtifactEnrichment slug="case" ids={[7]} />)
  await userEvent.click(await screen.findByRole('button',{name:/Choose.*connector/i}))
  const run=await screen.findByRole('button',{name:'Run enrichment'})
  expect(run).toBeDisabled()
  await userEvent.click(screen.getByRole('checkbox'))
  await userEvent.click(run)
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/opencti/enrich',{ioc_ids:[7],connector_ids:['one'],create_missing:false}))
})
it('displays SQL export evidence and tables instead of interpreting the dump as a table row', async () => {
  const ctx={...base,kind:'dump' as const,artifact:'/evidence/data.sql',file:undefined,dump:{id:1,path:'/evidence/data.sql',meta:{},statements:4,size:99,cms:'WordPress'},tables:[{id:10,name:'items',rows:2,columns:2,dump_id:1}],findings:[{...finding,artifact:'/evidence/data.sql',artifact_kind:'dump' as const,line:3}]}
  vi.mocked(api).mockImplementation(async url => (url.includes('/sql-preview') ? {from_line:1,focus:3,lines:['-- example','SELECT 1;','-- selected SQL']} : url==='/api/opencti/settings' ? {configured:false} : ctx) as never)
  renderWithProviders(<ArtifactWindow slug="case" artifact={{artifact:ctx.artifact,artifact_kind:'dump',worst:1,triage:'new',triage_note:''}} roots={[]} collected={[]} onClose={vi.fn()} onSave={vi.fn()} onView={vi.fn()} onTrace={vi.fn()} />)
  expect(await screen.findByText('-- selected SQL')).toBeVisible()
  expect(screen.getByRole('button',{name:/Expand SQL/})).toBeVisible()
  await userEvent.click(screen.getByRole('tab',{name:/Tables/}))
  expect(within(screen.getByRole('combobox')).getByRole('option',{name:/items/})).toBeVisible()
})

it('keeps compact findings in Trace without a redundant Findings tab', async () => {
  const first={...finding,id:10,fingerprint:'upload',artifact:'192.0.2.1',artifact_kind:'client' as const,rule:'Upload PHP rule',source:'logs' as const,line:null}
  const second={...first,id:11,fingerprint:'login',rule:'Login flood rule'}
  renderReview({...base,kind:'client',artifact:first.artifact,file:undefined,findings:[first,second]})
  expect(await screen.findByRole('button',{name:/Upload PHP rule/})).toBeVisible()
  expect(screen.getByRole('button',{name:/Login flood rule/})).toBeVisible()
  expect(screen.queryByRole('tab',{name:/Findings/})).not.toBeInTheDocument()
  expect(screen.getByRole('tab',{name:'Trace'})).toHaveAttribute('aria-selected','true')
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/cases/case/trace',expect.objectContaining({finding_ids:[10,11]})))
})
it('explains unavailable historic request evidence without rendering a broad trace', async () => {
  vi.mocked(api).mockResolvedValue({available:false,total:0,rows:[],reason:'retired'})
  renderWithProviders(<FindingRequests slug="case" finding={finding} />)
  expect(await screen.findByText(/This finding is historical/)).toBeVisible()
  expect(screen.queryByRole('table')).not.toBeInTheDocument()
})
