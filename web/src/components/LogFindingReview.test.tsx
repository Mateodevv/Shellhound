import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, expect, it, vi } from 'vitest'
import { api, post, type ArtifactContext, type Finding } from '../api'
import type { LogEvent } from '../logApi'
import { renderWithProviders, testQueryClient } from '../test/setup'
import { LogFindingReview } from './LogFindingReview'
import { ArtifactWindow } from './ArtifactWindow'

vi.mock('../api', async orig => ({ ...(await orig<typeof import('../api')>()), api: vi.fn(), post: vi.fn() }))
vi.mock('./ArtifactEnrichment', () => ({ ArtifactEnrichment: ({ ids }: { ids: number[] }) => <div>Enrichment IDs: {ids.join(',')}</div> }))
const entry: LogEvent = { id:'ftp-one', source_id:'source', source_name:'ftp.log', fingerprint:'first', family:'ftp', epoch:1789375200, raw_time:'2026-09-14 10:00:00 +0200', time_meaning:'event', line:87, line_end:87, ip:'192.0.2.42', remote_host:'', account:'site-deploy', path:'/srv/site/marker.php', artifact:'/evidence/marker.php', artifact_available:true, operation:'upload', outcome:'success', signature:'', detection:false, raw:'Original harmless upload', fresh:true, bytes:616 }
const finding = { id:7, source:'log_observation', artifact:entry.artifact, artifact_kind:'file', line:null, rule:'FTP activity involving a flagged file', fingerprint:'finding', severity:2, evidence:entry.raw, triage:'new', triage_note:'', retired:0, last_seen:'', created:'' } as Finding
const context: ArtifactContext = {artifact:entry.artifact,kind:'file',findings:[finding],triage:'new',triage_note:'',triaged_at:'',worst:2,sources:['log_observation'],related_ips:[],ioc_ids:[42],file:{exists:true,available:true,size:616,classifications:['webshell']},log_observations:[entry]}
function eventContext(e=entry) {return {event:e,source_path:'/logs/'+e.source_name,lines:[{line:e.line-1,text:'Previous context',selected:false},{line:e.line,text:e.raw,selected:true}]}}
function network(e=entry) {
  vi.mocked(api).mockImplementation(async url => {
    if(url==='/api/opencti/settings')return {configured:true}
    if(url.includes('/context?'))return eventContext(e)
    if(url.includes('/artifact?'))return context
    if(url.includes('/file?'))return {mode:'raw',path:entry.artifact,lines:['<?php','echo "harmless";'],offset:0,length:30,size:30,eof:true,window:262144,from_line:1}
    throw Error('Unexpected endpoint: '+url)
  })
}
beforeEach(()=>{vi.clearAllMocks();network()})
function mount(e=entry, configured=true) {const qc=testQueryClient();const onFile=vi.fn();return {...renderWithProviders(<LogFindingReview slug="case" events={[e]} configured={configured} onFile={onFile}/>,qc),qc,onFile}}

it('shows actual FTP facts and opens a verified file without using the log line as a file line',async()=>{
 const {onFile}=mount()
 expect(await screen.findByRole('tab',{name:'Linked file'})).toBeVisible()
 expect(screen.getByText('site-deploy')).toBeVisible()
 expect(screen.getByText('616 B')).toBeVisible()
 expect(screen.queryByText('Login accepted')).not.toBeInTheDocument()
 fireEvent.click(screen.getByRole('button',{name:'Open file'}))
 await screen.findByText('echo "harmless";')
 const calls=vi.mocked(api).mock.calls.filter(([url])=>url.includes('/file?'))
 expect(calls.length).toBeGreaterThan(0)
 expect(calls.every(([url])=>!new URL(url,'http://localhost').searchParams.has('line'))).toBe(true)
 fireEvent.click(screen.getByRole('button',{name:/Expand file/}))
 expect(onFile).toHaveBeenCalledWith(entry.artifact,null)
 expect(post).not.toHaveBeenCalled()
})

it('enriches only the linked file IOC IDs and hides OpenCTI when unconfigured',async()=>{
 const view=mount()
 fireEvent.click(await screen.findByRole('tab',{name:'Enrichment'}))
 expect(await screen.findByText('Enrichment IDs: 42')).toBeVisible()
 expect(screen.getByRole('link',{name:'Open IOC Box'}).getAttribute('href')).toContain('ioc=42')
 expect(post).not.toHaveBeenCalled()
 view.rerender(<LogFindingReview slug="case" events={[entry]} configured={false} onFile={vi.fn()}/>)
 expect(screen.queryByRole('tab',{name:'Enrichment'})).not.toBeInTheDocument()
 expect(screen.getByRole('tab',{name:'Evidence'})).toHaveAttribute('aria-selected','true')
})

it('retains a stale excerpt but removes cached file and enrichment actions',async()=>{
 const {qc}=mount()
 fireEvent.click(await screen.findByRole('tab',{name:'Linked file'}))
 await screen.findByText('echo "harmless";')
 vi.mocked(api).mockRejectedValue(new Error('Source changed; analyze again'))
 await act(async()=>{await qc.invalidateQueries({queryKey:['log-context','case']})})
 expect(await screen.findByRole('alert')).toHaveTextContent('Source changed')
 expect(screen.getByText(entry.raw)).toBeVisible()
 expect(screen.queryByRole('tab',{name:'Linked file'})).not.toBeInTheDocument()
 expect(screen.queryByRole('tab',{name:'Enrichment'})).not.toBeInTheDocument()
 expect(screen.queryByText('echo "harmless";')).not.toBeInTheDocument()
})

it.each([
 ['error','web_error','error','Recorded error'],
 ['malware','malware_detection','reported_detection','Scanner observation'],
 ['text','observation','','Selected context'],
])('renders %s evidence without inventing file associations or timestamps',async(family,operation,outcome,heading)=>{
 const e={...entry,family,operation,outcome,artifact:'',artifact_available:false,epoch:null,raw_time:'',bytes:null,signature:family==='malware'?'Demo.Signature':'',detection:family==='malware',raw:'<strong>Literal original text</strong>'}
 network(e);mount(e)
 expect(await screen.findByRole('heading',{name:heading})).toBeVisible()
 await waitFor(()=>expect(screen.getByText(e.source_name+':87').parentElement).toBeInTheDocument())
 expect(screen.queryByRole('tab',{name:'Linked file'})).not.toBeInTheDocument()
 expect(screen.queryByRole('tab',{name:'Enrichment'})).not.toBeInTheDocument()
 const summary=screen.getByText(/Original log ·/)
 const details=summary.closest('details')!
 if(family==='malware'){expect(details).not.toHaveAttribute('open');fireEvent.click(summary)}else expect(details).toHaveAttribute('open')
 const original=await screen.findByRole('region',{name:'Original log'})
 expect(within(original).getByText(e.raw)).toBeVisible()
 expect(original.querySelector('strong')).toBeNull()
 expect(original.querySelector('[data-log-selected]')).toHaveTextContent(e.raw)
 if(family==='malware')expect(screen.getByText(/not an infection date/)).toBeVisible()
})

it('resets the detail tab and removes previous file actions when selecting another observation',async()=>{
 const other={...entry,id:'other',family:'text',artifact:'',artifact_available:false,path:'',line:3,line_end:3}
 vi.mocked(api).mockImplementation(async url=>url.includes('/other/context?')?eventContext(other):url.includes('/context?')?eventContext():context)
 renderWithProviders(<LogFindingReview slug="case" events={[entry,other]} configured onFile={vi.fn()}/>)
 fireEvent.click(await screen.findByRole('tab',{name:'Linked file'}))
 fireEvent.change(screen.getByRole('combobox',{name:'Observation'}),{target:{value:'other'}})
 expect(screen.getByRole('tab',{name:'Evidence'})).toHaveAttribute('aria-selected','true')
 expect(screen.queryByRole('tab',{name:'Linked file'})).not.toBeInTheDocument()
 expect(await screen.findByRole('heading',{name:'Selected context'})).toBeVisible()
})

it.each(['file','log_observation'] as const)('uses the new review for %s and preserves keyboard decisions',async kind=>{
 const artifact=kind==='file'?entry.artifact:'log-observation:ftp-one'
 const ctx={...context,artifact,kind,findings:[{...finding,artifact,artifact_kind:kind}],file:kind==='file'?context.file:undefined}
 vi.mocked(api).mockImplementation(async url=>url==='/api/opencti/settings'?{configured:false}:url.includes('/context?')?eventContext():ctx)
 const onSave=vi.fn().mockResolvedValue({updated:1,collected:[],linked:[],suggested:[],retained_iocs:[]})
 renderWithProviders(<ArtifactWindow slug="case" artifact={{artifact,artifact_kind:kind,worst:2,triage:'new',triage_note:''}} roots={[]} collected={[]} onSave={onSave} onClose={vi.fn()} onView={vi.fn()} onTrace={vi.fn()}/>)
 expect(await screen.findByRole('heading',{name:'Transfer context'})).toBeVisible()
 expect(screen.queryByRole('tab',{name:/Findings/})).not.toBeInTheDocument()
 await waitFor(()=>expect(screen.getByRole('radio',{name:'Skip for now'})).toBeEnabled())
 fireEvent.keyDown(window,{key:'2'});fireEvent.keyDown(window,{key:'Enter'})
 await waitFor(()=>expect(onSave).toHaveBeenCalledWith('reviewed','',...(kind==='file'?[['webshell']]:[])))
})
