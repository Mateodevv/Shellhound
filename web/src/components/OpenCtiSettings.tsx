import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { patch, post } from '../api'
import { useT } from '../i18n'
import { useOpenCtiSettings, type OpenCtiSettings as Settings, type OpenCtiConnector } from '../opencti'
import { Button, Card, Section, Tag } from './ui'
import { CtiError, CtiField, ctiInput } from './CaseProfile'

export function OpenCtiSettings() {
  const query = useOpenCtiSettings()
  const tr = useT()
  return <Section title={tr('cti.title')} sub={tr('cti.settingsBody')}>
    <CtiError error={query.error} />
    {query.data && <SettingsForm key={`${query.data.url}:${query.data.ingester_id}:${query.data.configured}:${query.data.token_hint}`} initial={query.data} />}
  </Section>
}
function SettingsForm({ initial }: { initial: Settings }) {
  const tr = useT()
  const qc = useQueryClient()
  const [url, setUrl] = useState(initial.url)
  const [ingester, setIngester] = useState(initial.ingester_id)
  const [token, setToken] = useState('')
  const [clearToken, setClearToken] = useState(false)
  const [samples, setSamples] = useState(initial.sample_uploads)
  const [saved, setSaved] = useState(false)
  const save = useMutation({ mutationFn: () => patch('/api/opencti/settings', {
    url, ingester_id: ingester, sample_uploads: samples, ...(clearToken ? { token: '' } : token.trim() ? { token: token.trim() } : {}),
  }), onSuccess: () => {
    setToken(''); setClearToken(false); setSaved(true)
    qc.invalidateQueries({ queryKey: ['opencti-settings'] })
  } })
  const test = useMutation({ mutationFn: () => post<{ ok: boolean; version?: string; connectors: OpenCtiConnector[]; warnings: string[] }>('/api/opencti/test', {}) })
  const dirty = url !== initial.url || ingester !== initial.ingester_id || token !== '' || clearToken || samples !== initial.sample_uploads
  return <Card className="flex flex-col gap-3 p-4">
    <CtiField label={tr('cti.url')}><input type="url" placeholder="https://opencti.example" className={ctiInput} value={url} onChange={(e) => { setUrl(e.target.value); setSaved(false) }} /></CtiField>
    <CtiField label={tr('cti.ingester')}><input className={ctiInput} value={ingester} onChange={(e) => { setIngester(e.target.value); setSaved(false) }} /></CtiField>
    <CtiField label={tr('cti.token')}><input type="password" autoComplete="off" className={ctiInput} value={token} onChange={(e) => { setToken(e.target.value); setClearToken(false); setSaved(false) }} />
      <span>{tr('cti.tokenBody')}</span>{initial.configured && <span>{tr('cti.tokenHint', { hint: initial.token_hint })}</span>}
    </CtiField>
    {initial.configured && <label className="flex gap-2 text-[12px]"><input type="checkbox" checked={clearToken} onChange={(e) => { setClearToken(e.target.checked); setToken('') }} />{tr('cti.tokenRemove')}</label>}
    <label className="flex gap-2 text-[12px]"><input type="checkbox" checked={samples} onChange={(e) => setSamples(e.target.checked)} />{tr('cti.samplesEnable')}</label>
    <p className="text-[12px] text-[var(--muted)]">{tr('cti.samplesExternal')}</p>
    <div className="flex flex-wrap items-center gap-2"><Button variant="primary" disabled={save.isPending || !dirty} onClick={() => save.mutate()}>{tr('common.save')}</Button>
      <Button disabled={test.isPending || !initial.configured || dirty} onClick={() => test.mutate()}>{tr('cti.test')}</Button>{saved && <Tag tone="accent">{tr('cti.saved')}</Tag>}
    </div>
    <CtiError error={save.error || test.error} />
    {test.data && <div className="flex flex-col gap-2 text-[12px]">
      <Tag tone={test.data.ok ? 'accent' : 'danger'}>{tr(test.data.ok ? 'cti.testOk' : 'cti.testBad')}{test.data.version ? ` · ${test.data.version}` : ''}</Tag>
      {test.data.warnings?.map((warning) => <p key={warning} className="text-[var(--warn)]">{warning}</p>)}
      {test.data.connectors?.map((connector) => <div key={connector.id}>{connector.name} · {connector.scope.join(', ')} · {tr(connector.auto ? 'cti.automatic' : 'cti.manual')}</div>)}
    </div>}
  </Card>
}
