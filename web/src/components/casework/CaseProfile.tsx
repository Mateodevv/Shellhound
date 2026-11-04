import { useState, type ReactNode, type Dispatch, type SetStateAction } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { SlidersHorizontal } from 'lucide-react'
import { api, patch, type CaseInfo } from '../../api'
import { newCaseProfile, type CaseProfile } from '../../opencti'
import { AffectedOrganizationFields } from './AffectedOrganizationFields'
import { useT } from '../../i18n'
import { Button, Modal } from '../ui/ui'

export const ctiInput = 'w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] outline-none focus:border-[var(--accent)]'
export function CtiField({ label, children }: { label: string; children: ReactNode }) {
  return <label className="flex min-w-0 flex-col gap-1.5 text-[12px] text-[var(--muted)]">{label}{children}</label>
}
export function CtiError({ error }: { error: unknown }) {
  if (!error) return null
  return <div role="alert" className="break-words rounded-lg border border-[var(--danger-text)]/40 bg-[var(--danger-soft)] p-3 text-[12px] text-[var(--danger-text)]">{error instanceof Error ? error.message : String(error)}</div>
}
export function CaseProfileButton({ slug }: { slug: string }) {
  const tr = useT()
  const [open, setOpen] = useState(false)
  return <div className="flex flex-wrap items-center gap-2"><Button onClick={() => setOpen(true)}><SlidersHorizontal size={14} />{tr('cti.profile')}</Button>{open && <CaseProfileDialog slug={slug} onClose={() => setOpen(false)} />}</div>
}
function CaseProfileDialog({ slug, onClose }: { slug: string; onClose: () => void }) {
  const tr = useT()
  const query = useQuery({ queryKey: ['case', slug], queryFn: () => api<CaseInfo>(`/api/cases/${slug}`) })
  return <Modal open onClose={onClose} title={tr('cti.profile')}>
    <CtiError error={query.error} />
    {query.data ? <CaseProfileForm slug={slug} info={query.data} onClose={onClose} /> : !query.error && <p>{tr('common.loading')}</p>}
  </Modal>
}
export function CaseProfileForm({ slug, info, onClose }: { slug: string; info: CaseInfo; onClose: () => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [name, setName] = useState(info.name)
  const [revision] = useState(info.profile_revision)
  const [reference, setReference] = useState(info.reference)
  const [profile, setProfile] = useState<CaseProfile>({ ...newCaseProfile(), ...info.profile })
  const invalidDates = !!profile.first_seen && !!profile.last_seen && new Date(profile.first_seen).getTime() > new Date(profile.last_seen).getTime()
  const save = useMutation({ mutationFn: () => patch(`/api/cases/${slug}`, {
    name: name.trim(), reference: reference.trim(), profile, expected_profile_revision: revision,
  }), onSuccess: () => {
    qc.invalidateQueries({ queryKey: ['case', slug] })
    qc.invalidateQueries({ queryKey: ['state'] })
    qc.invalidateQueries({ queryKey: ['close-summary', slug] })
    qc.invalidateQueries({ queryKey: ['opencti', slug] })
    onClose()
  } })
  return <form className="flex flex-col gap-4" onSubmit={(event) => { event.preventDefault(); if (!invalidDates && name.trim() && !save.isPending) save.mutate() }}>
    <p className="text-[12px] text-[var(--muted)]">{tr('profileChanges.localSave')}</p>
    <fieldset disabled={save.isPending} className="flex flex-col gap-4">
    <CtiField label={tr('wizard.name')}><input aria-label={tr('wizard.name')} required value={name} onChange={e => setName(e.target.value)} className={ctiInput} /><span>{tr('profileChanges.localName')}</span></CtiField>
    <CtiField label={tr('cti.caseId')}><input aria-label={tr('cti.caseId')} value={reference} readOnly={info.reference_locked} onChange={(e) => setReference(e.target.value)} className={ctiInput} /><span>{tr(info.reference_locked ? 'profileChanges.referenceLocked' : 'cti.caseIdHint')}</span></CtiField>
    <CaseProfileFields profile={profile} onChange={setProfile} />
    </fieldset>
    <CtiError error={invalidDates ? tr('cti.dateError') : save.error} />
    <div className="flex justify-end gap-2"><Button type="button" disabled={save.isPending} onClick={onClose}>{tr('common.cancel')}</Button><Button type="submit" variant="primary" disabled={save.isPending || invalidDates || !name.trim()}>{tr('common.save')}</Button></div>
  </form>
}

export function CaseProfileFields({ profile, onChange, section = 'all', requiredContext = false }: {
  profile: CaseProfile; onChange: Dispatch<SetStateAction<CaseProfile>>; section?: 'all' | 'affected' | 'technical' | 'hidden'; requiredContext?: boolean
}) {
  const tr = useT()
  const change = <K extends keyof CaseProfile>(key: K, value: CaseProfile[K]) => onChange(previous => ({ ...previous, [key]: value }))
  return <>
    {section === 'all' && <>
    <CtiField label={tr('cti.summary')}><textarea className={ctiInput} rows={3} value={profile.summary} onChange={(e) => change('summary', e.target.value)} /></CtiField>
    </>}
    <div hidden={section !== 'all' && section !== 'affected'}><div className="flex flex-col gap-4">
    <AffectedOrganizationFields profile={profile} onChange={onChange} active={section === 'all' || section === 'affected'} required={requiredContext} />
    <div className="grid gap-3 sm:grid-cols-2">
      <CtiField label={tr('cti.firstSeen')}><input type="date" className={ctiInput} value={profile.first_seen.slice(0, 10)} onChange={(e) => change('first_seen', e.target.value)} /></CtiField>
      <CtiField label={tr('cti.lastSeen')}><input type="date" className={ctiInput} value={profile.last_seen.slice(0, 10)} onChange={(e) => change('last_seen', e.target.value)} /></CtiField>
    </div>
    <CtiField label={tr('cti.marking')}><select className={ctiInput} value={profile.marking} onChange={(e) => change('marking', e.target.value)}>
      {['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'].map((marking) => <option key={marking}>{marking}</option>)}
    </select><span>{tr('cti.markingHint')}</span></CtiField>
    </div></div>
    {section === 'all' && <>
      <fieldset className="space-y-3 rounded-lg border border-[var(--line)] p-3">
        <legend>{tr('cti.profileSoftware')}</legend>
        {profile.software.map((item, index) => <div key={index} className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
          <CtiField label={tr('cti.softwareName')}><input required className={ctiInput} value={item.name} onChange={event => change('software', profile.software.map((entry, i) => i === index ? { ...entry, name: event.target.value } : entry))} /></CtiField>
          <CtiField label={tr('cti.softwareVersion')}><input className={ctiInput} value={item.version} onChange={event => change('software', profile.software.map((entry, i) => i === index ? { ...entry, version: event.target.value } : entry))} /></CtiField>
          <Button type="button" onClick={() => change('software', profile.software.filter((_, i) => i !== index))}>{tr('common.remove')}</Button>
        </div>)}
        <Button type="button" onClick={() => change('software', [...profile.software, { name: '', version: '' }])}>{tr('cti.addSoftware')}</Button>
      </fieldset>
      <fieldset className="space-y-3 rounded-lg border border-[var(--line)] p-3">
        <legend>{tr('cti.profileCves')}</legend>
        {profile.vulnerabilities.map((item, index) => <div key={index} className="space-y-2 border-b border-[var(--line)] pb-3">
          <CtiField label={tr('cti.vulnerabilityName')}><input required className={ctiInput} value={item.name} onChange={event => change('vulnerabilities', profile.vulnerabilities.map((entry, i) => i === index ? { ...entry, name: event.target.value } : entry))} /></CtiField>
          <CtiField label={tr('cti.status')}><select className={ctiInput} value={item.status} onChange={event => change('vulnerabilities', profile.vulnerabilities.map((entry, i) => i === index ? { ...entry, status: event.target.value as 'confirmed' | 'suspected' } : entry))}><option value="suspected">{tr('cti.suspected')}</option><option value="confirmed">{tr('cti.confirmed')}</option></select></CtiField>
          <CtiField label={tr('cti.description')}><textarea className={ctiInput} value={item.description} onChange={event => change('vulnerabilities', profile.vulnerabilities.map((entry, i) => i === index ? { ...entry, description: event.target.value } : entry))} /></CtiField>
          <Button type="button" onClick={() => change('vulnerabilities', profile.vulnerabilities.filter((_, i) => i !== index))}>{tr('common.remove')}</Button>
        </div>)}
        <Button type="button" onClick={() => change('vulnerabilities', [...profile.vulnerabilities, { name: '', status: 'suspected', description: '' }])}>{tr('cti.addVulnerability')}</Button>
      </fieldset>
    </>}
  </>
}
