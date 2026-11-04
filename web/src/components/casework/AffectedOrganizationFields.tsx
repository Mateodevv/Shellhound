import { useState, type Dispatch, type SetStateAction } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api'
import type { CaseProfile } from '../../opencti'
import { useT } from '../../i18n'
import { CtiField, CtiError, ctiInput } from './CaseProfile'
import { SectorPicker } from './SectorPicker'
import { Button } from '../ui/ui'

export function AffectedOrganizationFields({ profile, onChange, active, required }: {
  profile: CaseProfile; onChange: Dispatch<SetStateAction<CaseProfile>>; active: boolean; required: boolean
}) {
  const tr = useT()
  const [countries, setCountries] = useState(profile.countries.join(', '))
  const catalogue = useQuery({ queryKey: ['profile-sectors'], queryFn: () => api<{ sectors: string[] }>('/api/profile/sectors'), staleTime: Infinity, enabled: active })
  const change = <K extends keyof CaseProfile>(key: K, value: CaseProfile[K]) => onChange(previous => ({ ...previous, [key]: value }))
  return <>
    <CtiField label={`${tr('cti.organizationName')}${required ? ' *' : ''}`}><input required={active && required} maxLength={200} className={ctiInput} value={profile.organization_name || profile.pseudonym} onChange={event => onChange(previous => ({ ...previous, organization_name: event.target.value, pseudonym: '', organization_id: '' }))} /></CtiField>
    <SectorPicker sectors={catalogue.data?.sectors ?? []} profile={profile} onChange={onChange} required={required} />
    <CtiError error={catalogue.error} />
    {(profile.subsectors ?? []).map((item, index) => <div key={index} className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
      <CtiField label={tr('cti.parentSector')}><select className={ctiInput} value={item.sector} onChange={event => change('subsectors', profile.subsectors!.map((entry, i) => i === index ? { ...entry, sector: event.target.value } : entry))}><option value="">{tr('cti.choose')}</option>{profile.sectors.map(sector => <option key={sector}>{sector}</option>)}</select></CtiField>
      <CtiField label={tr('cti.subsectorName')}><input required maxLength={200} className={ctiInput} value={item.name} onChange={event => change('subsectors', profile.subsectors!.map((entry, i) => i === index ? { ...entry, name: event.target.value } : entry))} /></CtiField>
      <Button type="button" onClick={() => change('subsectors', profile.subsectors!.filter((_, i) => i !== index))}>{tr('common.remove')}</Button>
    </div>)}
    <Button type="button" disabled={!profile.sectors.length} onClick={() => change('subsectors', [...(profile.subsectors ?? []), { name: '', sector: profile.sectors[0] }])}>{tr('cti.newSubsector')}</Button>
    <div className="grid gap-3 sm:grid-cols-2">
      <CtiField label={`${tr('cti.country')}${required ? ' *' : ''}`}><input aria-label={`${tr('cti.country')}${required ? ' *' : ''}`} required={active && required} className={ctiInput} placeholder="DE, AT" value={countries} onChange={event => { setCountries(event.target.value); change('countries', event.target.value.split(',').map(value => value.trim().toUpperCase()).filter(Boolean)) }} /><span>{tr('cti.manualCountryHint')}</span></CtiField>
      <CtiField label={tr('cti.state')}><input maxLength={200} className={ctiInput} value={profile.state ?? ''} onChange={event => change('state', event.target.value)} /></CtiField>
      <CtiField label={tr('cti.city')}><input maxLength={200} className={ctiInput} value={profile.city ?? ''} onChange={event => change('city', event.target.value)} /></CtiField>
    </div>
  </>
}
