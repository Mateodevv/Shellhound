import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { patch, post } from '../../api'
import { useT } from '../../i18n'
import { openCtiHost, useOpenCtiSettings, type OpenCtiSettings as Settings } from '../../opencti'
import { Button, Card, Section, Tag } from '../ui/ui'
import { CtiError, CtiField, ctiInput } from '../casework/CaseProfile'

export function OpenCtiSettings({ slug }: { slug?: string }) {
  const query = useOpenCtiSettings()
  const tr = useT()
  return <Section title={tr('cti.title')} sub={tr('cti.settingsBody')}>
    <CtiError error={query.error} />
    {query.isPending && <p role="status">{tr('common.loading')}</p>}
    {query.data && <SettingsForm key={`${query.data.url}:${query.data.ingester_id}:${query.data.configured}:${query.data.token_hint}:${query.data.auto_match}`} initial={query.data} slug={slug} />}
  </Section>
}
function SettingsForm({ initial, slug }: { initial: Settings; slug?: string }) {
  const tr = useT()
  const qc = useQueryClient()
  const [url, setUrl] = useState(initial.url)
  const [ingester, setIngester] = useState(initial.ingester_id)
  const [token, setToken] = useState('')
  const [clearToken, setClearToken] = useState(false)
  const [saved, setSaved] = useState(false)
  const [autoMatch, setAutoMatch] = useState(initial.auto_match === true)
  const sameUrl = url.trim().replace(/\/+$/, '') === initial.url
  const save = useMutation({ mutationFn: () => patch('/api/opencti/settings', {
    url, ingester_id: ingester, ...(autoMatch !== (initial.auto_match === true) || (autoMatch && !sameUrl) ? { auto_match: autoMatch } : {}), ...(autoMatch && slug ? { case_slug: slug } : {}), ...(clearToken ? { token: '' } : token.trim() ? { token: token.trim() } : {}),
  }), onSuccess: () => {
    setToken(''); setClearToken(false); setSaved(true)
    qc.removeQueries({ queryKey: ['opencti-matches'] })
    qc.invalidateQueries({ queryKey: ['opencti-settings'] })
  } })
  const test = useMutation({ mutationFn: () => post<{ ok: boolean; version?: string }>('/api/opencti/test', {}) })
  const recheck = useMutation({ mutationFn: () => post<{ job_id: number }>(`/api/cases/${encodeURIComponent(slug!)}/opencti/matches/recheck`, { expected_url: initial.url }), onSuccess: () => { void qc.invalidateQueries({ queryKey: ['jobs', slug] }); void qc.invalidateQueries({ queryKey: ['opencti-matches', slug] }) } })
  const dirty = url !== initial.url || ingester !== initial.ingester_id || token !== '' || clearToken || autoMatch !== (initial.auto_match === true)
  const hasCredentials = Boolean(url.trim() && (token.trim() || (sameUrl && initial.token_hint && !clearToken)))
  return <Card className="flex flex-col gap-3 p-4">
    <CtiField label={tr('cti.url')}><input type="url" placeholder="https://opencti.example" className={ctiInput} value={url} onChange={(e) => { setUrl(e.target.value); if (e.target.value.trim().replace(/\/+$/, '') !== initial.url) setAutoMatch(false); setSaved(false) }} /></CtiField>
    <CtiField label={tr('cti.ingester')}><input className={ctiInput} value={ingester} onChange={(e) => { setIngester(e.target.value); setSaved(false) }} /></CtiField>
    <CtiField label={tr('cti.token')}><input type="password" autoComplete="off" className={ctiInput} value={token} onChange={(e) => { setToken(e.target.value); setClearToken(false); if (!e.target.value.trim() && !(sameUrl && initial.token_hint)) setAutoMatch(false); setSaved(false) }} />
      <span>{tr('cti.tokenBody')}</span>{initial.token_hint && <span>{tr('cti.tokenHint', { hint: initial.token_hint })}</span>}
    </CtiField>
    {initial.token_hint && <label className="flex gap-2 text-[12px]"><input type="checkbox" checked={clearToken} onChange={(e) => { setClearToken(e.target.checked); setToken(''); if (e.target.checked) setAutoMatch(false) }} />{tr('cti.tokenRemove')}</label>}
    <label className="flex items-start gap-2 text-[13px]"><input type="checkbox" checked={autoMatch} disabled={!hasCredentials && !autoMatch} onChange={e => { setAutoMatch(e.target.checked); setSaved(false) }} />{tr('ctiMatches.autoOption', { host: openCtiHost(url) })}</label>
    {!hasCredentials && <p className="text-[12px] text-[var(--muted)]">{tr('ctiMatches.credentialsNeeded')}</p>}
    <div className="flex flex-wrap items-center gap-2"><Button variant="primary" disabled={save.isPending || !dirty} onClick={() => save.mutate()}>{tr('common.save')}</Button>
      <Button disabled={test.isPending || !initial.configured || dirty} onClick={() => test.mutate()}>{tr('cti.test')}</Button>{saved && <Tag tone="accent">{tr('cti.saved')}</Tag>}
    </div>
    {slug && initial.lookup_configured && <div className="flex flex-wrap items-center gap-2 text-[12px]"><Button disabled={!initial.lookup_configured || dirty || recheck.isPending} onClick={() => recheck.mutate()}>{tr('ctiMatches.recheckAll')}</Button><span>{tr('ctiMatches.recheckScope', { case: slug, host: openCtiHost(initial.url) })}</span>{recheck.isSuccess && <Tag tone="accent">{tr('ctiMatches.recheckQueued')}</Tag>}</div>}
    <CtiError error={save.error || test.error || recheck.error} />
    {test.data && <div className="flex flex-col gap-2 text-[12px]">
      <Tag tone={test.data.ok ? 'accent' : 'danger'}>{tr(test.data.ok ? 'cti.testOk' : 'cti.testBad')}{test.data.version ? ` · ${test.data.version}` : ''}</Tag>
    </div>}
  </Card>
}
