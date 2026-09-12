import { useState, type ReactNode, type Dispatch, type SetStateAction } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import { api, patch, type CaseInfo } from '../api'
import { newCaseProfile, type CaseProfile } from '../opencti'
import { AffectedOrganizationFields } from './AffectedOrganizationFields'
import { useT } from '../i18n'
import { Button, Modal } from './ui'

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
  return <><Button onClick={() => setOpen(true)}>{tr('cti.profile')}</Button>{open && <CaseProfileDialog slug={slug} onClose={() => setOpen(false)} />}</>
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
  const [reference, setReference] = useState(info.reference)
  const [profile, setProfile] = useState<CaseProfile>({ ...newCaseProfile(), ...info.profile })
  const invalidDates = !!profile.first_seen && !!profile.last_seen && new Date(profile.first_seen).getTime() > new Date(profile.last_seen).getTime()
  const save = useMutation({ mutationFn: () => patch(`/api/cases/${slug}`, {
    reference: reference.trim(), profile,
  }), onSuccess: () => {
    qc.invalidateQueries({ queryKey: ['case', slug] })
    qc.invalidateQueries({ queryKey: ['state'] })
    qc.invalidateQueries({ queryKey: ['opencti', slug] })
    onClose()
  } })
  return <form className="flex flex-col gap-4" onSubmit={(event) => { event.preventDefault(); if (!invalidDates) save.mutate() }}>
    <CtiField label={tr('cti.caseId')}><input value={reference} onChange={(e) => setReference(e.target.value)} className={ctiInput} /><span>{tr('cti.caseIdHint')}</span></CtiField>
    <CaseProfileFields profile={profile} onChange={setProfile} />
    <CtiError error={invalidDates ? tr('cti.dateError') : save.error} />
    <div className="flex justify-end gap-2"><Button type="button" onClick={onClose}>{tr('common.cancel')}</Button><Button type="submit" variant="primary" disabled={save.isPending || invalidDates}>{tr('common.save')}</Button></div>
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
    <div hidden={section !== 'all' && section !== 'technical'}><div className="flex flex-col gap-4">
    <fieldset className="flex flex-col gap-2"><legend className="mb-2 text-[13px] font-semibold">{tr('cti.software')}</legend>
      {profile.software.map((item, index) => <div key={index} className="flex gap-2">
        <input aria-label={tr('cti.softwareName')} placeholder={tr('cti.softwareName')} className={ctiInput} value={item.name} onChange={(e) => change('software', profile.software.map((v, n) => n === index ? { ...v, name: e.target.value } : v))} required={section === 'all' || section === 'technical'} />
        <input aria-label={tr('cti.version')} placeholder={tr('cti.version')} className={ctiInput} value={item.version} onChange={(e) => change('software', profile.software.map((v, n) => n === index ? { ...v, version: e.target.value } : v))} />
        <Button type="button" aria-label={tr('common.remove')} onClick={() => change('software', profile.software.filter((_, n) => n !== index))}><Trash2 size={14} /></Button>
      </div>)}
      <Button type="button" onClick={() => change('software', [...profile.software, { name: '', version: '' }])}><Plus size={13} />{tr('common.add')}</Button>
    </fieldset>
    <fieldset className="flex flex-col gap-2"><legend className="mb-2 text-[13px] font-semibold">{tr('cti.vulns')}</legend>
      {profile.vulnerabilities.map((item, index) => <div key={index} className="flex flex-col gap-2 rounded-lg border border-[var(--line)] p-3">
        <div className="flex gap-2"><input aria-label={tr('cti.vulnName')} placeholder={tr('cti.vulnName')} className={ctiInput} value={item.name} onChange={(e) => change('vulnerabilities', profile.vulnerabilities.map((v, n) => n === index ? { ...v, name: e.target.value } : v))} required={section === 'all' || section === 'technical'} />
          <Button type="button" aria-label={tr('common.remove')} onClick={() => change('vulnerabilities', profile.vulnerabilities.filter((_, n) => n !== index))}><Trash2 size={14} /></Button></div>
        <select aria-label={tr('cti.vulns')} className={ctiInput} value={item.status} onChange={(e) => change('vulnerabilities', profile.vulnerabilities.map((v, n) => n === index ? { ...v, status: e.target.value as 'confirmed' | 'suspected' } : v))}>
          <option value="suspected">{tr('cti.suspected')}</option><option value="confirmed">{tr('cti.confirmed')}</option>
        </select>
        <textarea aria-label={tr('cti.vulnDescription')} placeholder={tr('cti.vulnDescription')} className={ctiInput} value={item.description} onChange={(e) => change('vulnerabilities', profile.vulnerabilities.map((v, n) => n === index ? { ...v, description: e.target.value } : v))} />
      </div>)}
      <Button type="button" onClick={() => change('vulnerabilities', [...profile.vulnerabilities, { name: '', status: 'suspected', description: '' }])}><Plus size={13} />{tr('common.add')}</Button>
    </fieldset>
    </div></div>
  </>
}
