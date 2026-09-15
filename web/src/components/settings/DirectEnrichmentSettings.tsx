import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { post } from '../../api'
import { useDirectSettings, providerTypes } from '../../directEnrichment'
import { useOpenCtiSettings } from '../../opencti'
import { useT } from '../../i18n'
import { Button, Section, Tag } from '../ui/ui'
import { CtiError } from '../casework/CaseProfile'
import { IocTypeBadge } from '../iocs/IocTypeBadge'
import { InfoDot } from '../ui/Tooltip'

export function DirectEnrichmentSettings() {
  const tr = useT()
  const settings = useDirectSettings()
  const cti = useOpenCtiSettings()
  return <Section title={tr('direct.settings')} sub={tr('direct.settingsHint')}>
    {cti.data?.configured && <p role="status" className="mb-3 text-[12px] text-[var(--muted)]">{tr('direct.openctiActive')}</p>}
    <CtiError error={settings.error} />
    <div className="space-y-3">{Object.keys(providerTypes).map(service => <ProviderKey key={service} service={service} configured={settings.data?.services?.[service]?.configured ?? false} hint={settings.data?.services?.[service]?.hint ?? ''} />)}</div>
  </Section>
}
function ProviderKey({ service, configured, hint }: { service: string; configured: boolean; hint: string }) {
  const tr = useT()
  const qc = useQueryClient()
  const [key, setKey] = useState('')
  const [saved, setSaved] = useState(false)
  const save = useMutation({ mutationFn: (value: string) => post('/api/settings/key', { service, key: value }), onSuccess: () => { setKey(''); setSaved(true); void qc.invalidateQueries({ queryKey: ['settings'] }) } })
  return <div className="space-y-3 rounded-lg border border-[var(--line)] bg-[var(--panel)] p-4">
    <div className="flex flex-wrap items-center gap-2"><strong>{tr(`enrich.${service}`)}</strong><InfoDot body={tr(`direct.help.${service}`)} />{configured && <Tag>{hint}</Tag>}<span className="ml-auto flex flex-wrap gap-1">{providerTypes[service].filter(type => type !== 'hash').map(type => <IocTypeBadge key={type} type={type} value={type === 'ip' ? '1.1.1.1' : ''} />)}</span></div>
    <form className="flex flex-wrap gap-2" onSubmit={event => { event.preventDefault(); save.mutate(key) }}>
      <label className="min-w-48 flex-1 text-[12px]">{tr('direct.apiKey')}<input type="password" autoComplete="new-password" spellCheck={false} aria-label={`${tr(`enrich.${service}`)} API key`} className="mt-1 w-full rounded border border-[var(--line)] bg-[var(--input)] px-3 py-2" value={key} onChange={event => { setKey(event.target.value); setSaved(false) }} placeholder={configured ? tr('direct.replaceKey') : tr('direct.enterKey')} /></label>
      <div className="flex items-end gap-2"><Button type="submit" disabled={save.isPending || !key.trim()}>{tr('common.save')}</Button>{configured && <Button type="button" disabled={save.isPending} onClick={() => save.mutate('')}>{tr('direct.removeKey')}</Button>}</div>
    </form>
    {saved && <p role="status" className="text-[12px] text-[var(--muted)]">{tr('direct.saved')}</p>}<CtiError error={save.error} />
  </div>
}
