import { useId, useState, type Dispatch, type SetStateAction } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../api'
import type { CaseProfile, Organization } from '../../opencti'
import { useT } from '../../i18n'
import { CtiField, CtiError, ctiInput } from './CaseProfile'
import { SectorPicker, type Sector } from './SectorPicker'
import { Button } from '../ui/ui'

export interface Geography { countries: { code: string; name: string }[]; states: Record<string, { code: string; name: string }[]> }
export function AffectedOrganizationFields({ profile, onChange, active, required }: {
  profile: CaseProfile; onChange: Dispatch<SetStateAction<CaseProfile>>; active: boolean; required: boolean
}) {
  const tr = useT()
  const organizationsId = useId()
  const [creating, setCreating] = useState<'sector' | 'subsector' | null>(null)
  const [draft, setDraft] = useState('')
  const [parent, setParent] = useState('')
  const [createError, setCreateError] = useState('')
  const organizations = useQuery({ queryKey: ['organizations'], queryFn: () => api<Organization[]>('/api/organizations'), enabled: active })
  const taxonomy = useQuery({ queryKey: ['opencti-sectors'], queryFn: () => api<{ sectors: Sector[]; stale: boolean }>('/api/opencti/sectors'), enabled: active, staleTime: 900_000, retry: false })
  const geo = useQuery({ queryKey: ['profile-geography'], queryFn: () => api<Geography>('/api/profile/geography'), enabled: active, staleTime: Infinity })
  const sectors = taxonomy.data?.sectors ?? []
  const country = profile.countries[0] ?? ''
  const states = geo.data?.states[country] ?? []
  const subs = profile.subsectors ?? []
  const parentOptions = [...new Set([...sectors.filter(item => !item.subsector).map(item => item.name), ...sectors.flatMap(item => item.parents), ...profile.sectors])].sort((a, b) => a.localeCompare(b))
  const change = <K extends keyof CaseProfile>(key: K, value: CaseProfile[K]) => onChange(previous => ({ ...previous, [key]: value }))
  const beginCreate = (kind: 'sector' | 'subsector', name: string) => {
    setCreating(kind); setDraft(name); setCreateError('')
    setParent(profile.sectors.length === 1 ? profile.sectors[0] : '')
  }
  const addDraft = () => {
    const name = draft.trim()
    if (!name || name.length > 200 || /[\u0000-\u001f\u007f]/.test(name)) return
    const sameName = (value: string) => value.toLowerCase() === name.toLowerCase()
    const existing = sectors.find(item => sameName(item.name))
    if (creating === 'sector') {
      if (existing?.subsector || subs.some(item => sameName(item.name))) { setCreateError(tr('cti.sectorNameConflict')); return }
      const canonical = existing?.name ?? profile.sectors.find(sameName) ?? name
      onChange(previous => ({ ...previous, sectors: [...new Set([...previous.sectors, canonical])] }))
    } else {
      if (!parentOptions.includes(parent)) return
      if (parentOptions.some(sameName) || (existing && !existing.parents.includes(parent)) || subs.some(item => sameName(item.name) && item.sector !== parent)) {
        setCreateError(tr('cti.sectorNameConflict')); return
      }
      const canonical = existing?.name ?? subs.find(item => sameName(item.name))?.name ?? name
      onChange(previous => ({ ...previous, sectors: [...new Set([...previous.sectors, parent])], subsectors: [...(previous.subsectors ?? []).filter(item => !(item.name === canonical && item.sector === parent)), { name: canonical, sector: parent }] }))
    }
    setCreating(null); setDraft(''); setCreateError('')
  }
  return <>
    <CtiField label={`${tr('cti.organizationName')}${required ? ' *' : ''}`}>
      <input aria-label={`${tr('cti.organizationName')}${required ? ' *' : ''}`} required={active && required} maxLength={200} list={organizationsId} className={ctiInput} value={profile.organization_name || profile.pseudonym} onChange={event => {
        const name = event.target.value
        onChange(previous => ({ ...previous, organization_name: name, pseudonym: '', organization_id: organizations.data?.find(org => org.name === name)?.id ?? '' }))
      }} />
      <datalist id={organizationsId}>{organizations.data?.map(org => <option key={org.id} value={org.name} />)}</datalist>
      <span>{tr('cti.organizationNameHint')}</span>
    </CtiField>
    <SectorPicker sectors={sectors} profile={profile} onChange={onChange} required={required} loading={taxonomy.isPending && active} onCreate={beginCreate} />
    <div className="grid gap-3 sm:grid-cols-2">
      {creating && <div role="group" aria-label={tr(creating === 'sector' ? 'cti.newSector' : 'cti.newSubsector')} className="flex flex-col gap-3 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 sm:col-span-2">
        <p className="text-[12px] text-[var(--muted)]">{tr('cti.newSectorHint')}</p>
        {creating === 'subsector' && <CtiField label={tr('cti.parentSector')}><select aria-label={tr('cti.parentSector')} className={ctiInput} value={parent} onChange={event => { setParent(event.target.value); setCreateError('') }}>
          <option value="">{tr('cti.choose')}</option>{parentOptions.map(name => <option key={name} value={name}>{name}</option>)}
        </select></CtiField>}
        <CtiField label={tr(creating === 'sector' ? 'cti.sectorName' : 'cti.subsectorName')}><input autoFocus maxLength={200} className={ctiInput} value={draft} onChange={event => { setDraft(event.target.value); setCreateError('') }} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); addDraft() } }} /></CtiField>
        <CtiError error={createError} />
        <div className="flex justify-end gap-2"><Button type="button" onClick={() => setCreating(null)}>{tr('common.cancel')}</Button><Button type="button" variant="primary" disabled={!draft.trim() || /[\u0000-\u001f\u007f]/.test(draft) || (creating === 'subsector' && !parentOptions.includes(parent))} onClick={addDraft}>{tr('cti.addSectorToCase')}</Button></div>
      </div>}
      <CtiField label={`${tr('cti.country')}${required ? ' *' : ''}`}><select aria-label={`${tr('cti.country')}${required ? ' *' : ''}`} required={active && required} disabled={geo.isPending} className={ctiInput} value={country} onChange={event => onChange(previous => ({ ...previous, countries: event.target.value ? [event.target.value] : [], state: '', city: '' }))}>
        <option value="">{tr('cti.choose')}</option>{geo.data?.countries.map(item => <option key={item.code} value={item.code}>{item.name}</option>)}
      </select></CtiField>
      <CtiField label={tr('cti.state')}><select aria-label={tr('cti.state')} className={ctiInput} disabled={!country || !states.length} value={profile.state ?? ''} onChange={event => change('state', event.target.value)}>
        <option value="">{tr(!country ? 'cti.chooseCountry' : states.length ? 'cti.none' : 'cti.noStates')}</option>
        {states.map(item => <option key={item.code} value={item.code}>{item.name}</option>)}
      </select></CtiField>
      <div className="sm:col-span-2"><CtiField label={tr('cti.city')}><input maxLength={200} className={ctiInput} value={profile.city ?? ''} onChange={event => change('city', event.target.value)} /></CtiField></div>
    </div>
    {taxonomy.isPending && active && <p role="status" className="text-xs text-[var(--muted)]">{tr('cti.loadingSectors')}</p>}
    {taxonomy.data?.stale && <p role="status" className="text-xs text-[var(--muted)]">{tr('cti.staleSectors')}</p>}
    {!taxonomy.isPending && !taxonomy.error && !sectors.length && active && <p className="text-xs text-[var(--muted)]">{tr('cti.noSectors')}</p>}
    <CtiError error={taxonomy.error || geo.error} />
    {(taxonomy.error || geo.error) && <Button type="button" onClick={() => { void taxonomy.refetch(); void geo.refetch() }}>{tr('cti.reloadChoices')}</Button>}
  </>
}
