import { useState, type Dispatch, type SetStateAction } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api'
import type { CaseProfile } from '../../opencti'
import { useT } from '../../i18n'
import { CtiField, CtiError, ctiInput } from './CaseProfile'
import { SectorPicker } from './SectorPicker'
import { Button } from '../ui/ui'
import { X } from 'lucide-react'

export function AffectedOrganizationFields({ profile, onChange, active, required }: {
  profile: CaseProfile; onChange: Dispatch<SetStateAction<CaseProfile>>; active: boolean; required: boolean
}) {
  const tr = useT()
  const [countries, setCountries] = useState(profile.countries.join(', '))
  const catalogue = useQuery({ queryKey: ['profile-sectors'], queryFn: () => api<{ sectors: string[]; subsectors: Record<string, string[]> }>('/api/profile/sectors'), staleTime: Infinity, enabled: active })
  const change = <K extends keyof CaseProfile>(key: K, value: CaseProfile[K]) => onChange(previous => ({ ...previous, [key]: value }))
  return <>
    <CtiField label={`${tr('cti.organizationName')}${required ? ' *' : ''}`}><input required={active && required} maxLength={200} className={ctiInput} value={profile.organization_name || profile.pseudonym} onChange={event => onChange(previous => ({ ...previous, organization_name: event.target.value, pseudonym: '', organization_id: '' }))} /></CtiField>
    <SectorPicker sectors={catalogue.data?.sectors ?? []} profile={profile} onChange={onChange} required={required} />
    <CtiError error={catalogue.error} />
    {!!profile.sectors.length && <div className="grid gap-3 sm:grid-cols-2">{profile.sectors.map(sector => {
      const choices = catalogue.data?.subsectors?.[sector] ?? []
      const selected = (profile.subsectors ?? []).filter(item => item.sector === sector)
      return <fieldset key={sector} className="min-w-0 space-y-2 rounded-lg border border-[var(--line)] p-3">
      <legend className="px-1 text-[12px] font-medium">{sector}</legend>
      {(profile.subsectors ?? []).map((item, index) => item.sector === sector && <div key={index} className="flex items-center gap-2">
        <select aria-label={tr('cti.subsectorFor', { sector })} required className={ctiInput} value={item.name} onChange={event => onChange(previous => ({ ...previous, subsectors: previous.subsectors!.map((entry, i) => i === index ? { ...entry, name: event.target.value } : entry) }))}>
          <option value="">{tr('cti.choose')}</option>
          {item.name && !choices.includes(item.name) && <option value={item.name}>{tr('cti.savedSubsector', { name: item.name })}</option>}
          {choices.filter(name => name === item.name || !selected.some(other => other.name === name)).map(name => <option key={name}>{name}</option>)}
        </select>
        <Button type="button" variant="ghost" aria-label={tr('cti.removeSubsector', { name: item.name || sector })} onClick={() => onChange(previous => ({ ...previous, subsectors: previous.subsectors!.filter((_, i) => i !== index) }))}><X size={14} /></Button>
      </div>)}
      <Button type="button" variant="ghost" disabled={selected.some(item => !item.name) || choices.every(name => selected.some(item => item.name === name))} onClick={() => onChange(previous => ({ ...previous, subsectors: [...(previous.subsectors ?? []), { name: '', sector }] }))}>{tr('cti.newSubsector')}</Button>
    </fieldset>})}</div>}
    <div className="grid gap-3 sm:grid-cols-3">
      <CtiField label={`${tr('cti.country')}${required ? ' *' : ''}`}><input aria-label={`${tr('cti.country')}${required ? ' *' : ''}`} required={active && required} className={ctiInput} placeholder="DE, AT" value={countries} onChange={event => { setCountries(event.target.value); change('countries', event.target.value.split(',').map(value => value.trim().toUpperCase()).filter(Boolean)) }} /><span>{tr('cti.manualCountryHint')}</span></CtiField>
      <CtiField label={tr('cti.state')}><input maxLength={200} className={ctiInput} value={profile.state ?? ''} onChange={event => change('state', event.target.value)} /></CtiField>
      <CtiField label={tr('cti.city')}><input maxLength={200} className={ctiInput} value={profile.city ?? ''} onChange={event => change('city', event.target.value)} /></CtiField>
    </div>
  </>
}
