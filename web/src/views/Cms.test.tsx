import { expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import { api, post } from '../api'
import { renderWithProviders } from '../test/setup'
import { Cms } from './Cms'
vi.mock('../api', async orig => ({...(await orig<typeof import('../api')>()),api:vi.fn(),post:vi.fn()}))
it('adds a plugin only on request with the displayed evidence path',async()=>{
 const version={version:'1.2',version_parsed:'1.2',version_source:'header',version_set:'',version_note:'',version_set_at:''}
 vi.mocked(api).mockImplementation(async url=>url.endsWith('/cms') ? {installs:[{...version,id:1,root:'/evidence/site',cms:'WordPress',items:[{...version,id:2,install_id:1,type:'Plugin',name:'Example plugin',slug:'example',path:'/evidence/site/plugins/example',artifacts:[],flagged:0}]}]} : {evidence_items:[]})
 vi.mocked(post).mockResolvedValue({id:7})
 renderWithProviders(<Cms slug="sample" gotoView={vi.fn()}/>)
 const add=await screen.findByRole('button',{name:'Add IOC'})
 expect(post).not.toHaveBeenCalled()
 fireEvent.click(add)
 await waitFor(()=>expect(post).toHaveBeenCalledExactlyOnceWith('/api/cases/sample/cms/items/2/ioc',{expected_path:'/evidence/site/plugins/example'}))
 expect(await screen.findByRole('button',{name:'Added to IOC Box'})).toBeDisabled()
})
