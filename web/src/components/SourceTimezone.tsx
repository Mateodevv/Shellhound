import { useQuery } from '@tanstack/react-query'
import { useId, useState } from 'react'
import { api } from '../api'
import { useT } from '../i18n'

export const sourceInput = 'min-w-0 w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] text-[var(--fg)]'

export function SourceTimezone({ value, onChange, filesystem = false }: {
  value: string; onChange: (value: string) => void; filesystem?: boolean
}) {
  const tr = useT()
  const id = useId()
  const local = Intl.DateTimeFormat().resolvedOptions().timeZone
  const [customValue, setCustomValue] = useState<string | null>(null)
  const custom = customValue === value || (!!value && !['auto', 'unknown', 'UTC', local].includes(value))
  const zones = useQuery({ queryKey: ['timezones'], queryFn: () => api<{ zones: string[] }>('/api/timezones'), staleTime: Infinity })
  const mode = custom ? 'custom' : !value ? 'auto' : value === local && value !== 'UTC' ? 'local' : value
  return <div className="space-y-2">
    <label className="flex flex-col gap-1 text-xs" htmlFor={id}>{tr(filesystem ? 'sourceTime.websiteZone' : 'logEvidence.timezone')}</label>
    <select id={id} className={sourceInput} value={mode} onChange={event => {
      const next = event.target.value
      setCustomValue(next === 'custom' ? value : null)
      if (next !== 'custom') onChange(next === 'local' ? local : next)
    }}>
      <option value="auto">{tr('sourceTime.auto')}</option>
      <option value="UTC">UTC</option>
      {local !== 'UTC' && <option value="local">{tr('sourceTime.local', { zone: local })}</option>}
      <option value="custom">{tr('sourceTime.choose')}</option>
      <option value="unknown">{tr('sourceTime.unknown')}</option>
    </select>
    {custom && <><input className={sourceInput} list={`${id}-zones`} aria-label={tr('sourceTime.choose')} placeholder="Europe/Berlin" value={['auto', 'unknown'].includes(value) ? '' : value} onChange={event => { setCustomValue(event.target.value); onChange(event.target.value) }} />
      <datalist id={`${id}-zones`}>{zones.data?.zones.map(zone => <option key={zone} value={zone} />)}</datalist></>}
    {zones.error && <p role="alert" className="text-xs text-[var(--review-text)]">{tr('sourceTime.loadError')}</p>}
    <p className="text-[11px] text-[var(--muted)]">{tr(filesystem ? 'sourceTime.filesystemHelp' : 'sourceTime.help')}</p>
  </div>
}
