import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { api, post, type CaseInfo } from '../api'
import type { Geography } from './AffectedOrganizationFields'
import { useOpenCtiSettings, newCaseProfile } from '../opencti'
import { useT } from '../i18n'
import { Button, Modal, Tag } from './ui'
import { CaseProfileFields, CtiError, CtiField, ctiInput } from './CaseProfile'

export function CaseWizard({ onClose, onCreated }: { onClose: () => void; onCreated: (info: CaseInfo) => void }) {
  const settings = useOpenCtiSettings()
  const tr = useT()
  if (settings.isPending) return <Modal open onClose={onClose} title={tr('wizard.title')}><p role="status">{tr('common.loading')}</p></Modal>
  return <CaseWizardForm configured={settings.data?.configured === true} onClose={onClose} onCreated={onCreated} />
}

function CaseWizardForm({ configured, onClose, onCreated }: { configured: boolean; onClose: () => void; onCreated: (info: CaseInfo) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [step, setStep] = useState(0)
  const [name, setName] = useState('')
  const [reference, setReference] = useState('')
  const [profile, setProfile] = useState(newCaseProfile)
  const steps = configured ? ['case', 'affected', 'technical', 'review'] : ['case', 'review']
  const current = steps[step]
  const invalidCountries = profile.countries.some(value => !/^[A-Za-z]{2}$/.test(value))
  const invalidDates = !!profile.first_seen && !!profile.last_seen && profile.first_seen > profile.last_seen
  const caseValid = Boolean(name.trim() && (!configured || (reference.trim() && profile.summary.trim())))
  const affectedValid = Boolean((profile.organization_name?.trim() || (profile.organization_id && profile.pseudonym)) && profile.sectors.length && profile.countries.length && !invalidCountries && !invalidDates)
  const geography = useQuery({ queryKey: ['profile-geography'], queryFn: () => api<Geography>('/api/profile/geography'), enabled: configured, staleTime: Infinity })
  const technicalValid = profile.software.every(item => item.name.trim()) && profile.vulnerabilities.every(item => item.name.trim() && (/^CVE-\d{4}-\d{4,}$/i.test(item.name.trim()) || item.description.trim()))
  const valid = caseValid && (!configured || (affectedValid && technicalValid))
  const stepValid = current === 'case' ? caseValid : current === 'affected' ? affectedValid : current === 'technical' ? technicalValid : valid
  const save = useMutation({
    mutationFn: () => post<CaseInfo>('/api/cases', { name: name.trim(), reference: reference.trim(), profile }),
    onSuccess: info => { qc.invalidateQueries({ queryKey: ['state'] }); onCreated(info) },
  })
  const close = () => { if (!save.isPending) onClose() }
  const summaryItem = (label: string, value: string) => <div className="min-w-0"><dt className="text-[12px] font-semibold text-[var(--muted)]">{label}</dt><dd className="mt-1 whitespace-pre-wrap break-words text-[13px]">{value || tr('wizard.unknown')}</dd></div>
  return <Modal open contained onClose={close} title={tr('wizard.title')} bodyClassName="min-h-0 flex-1 overflow-hidden p-5">
    <form className="flex h-full min-h-0 flex-col gap-4" onSubmit={event => {
      event.preventDefault()
      if (save.isPending || !stepValid) return
      if (current === 'review') save.mutate(); else setStep(step + 1)
    }}>
      <nav aria-label={tr('wizard.steps')} className="shrink-0 border-b border-[var(--line)] pb-4">
        <ol className="flex flex-wrap gap-2">{steps.map((item, index) => <li key={item}>
          <button type="button" aria-current={step === index ? 'step' : undefined} disabled={index > step || save.isPending} onClick={() => setStep(index)} className={`ui-press flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] ${index === step ? 'bg-[var(--accent-soft)] font-semibold text-[var(--accent-text)]' : 'text-[var(--muted)] disabled:opacity-50'}`}>
            <span className="flex h-5 w-5 items-center justify-center rounded-full border border-current text-[11px]">{index + 1}</span>{tr(`wizard.step.${item}`)}
          </button>
        </li>)}</ol>
      </nav>
      <div className="min-h-0 flex-1 overflow-y-auto pr-2">
        <div className="mx-auto flex max-w-3xl flex-col gap-4">
          <h2 className="text-lg font-semibold">{tr(`wizard.step.${current}`)}</h2>
          <p className="text-[13px] text-[var(--muted)]">{tr(`wizard.help.${current}${!configured && current === 'case' ? '.local' : ''}`)}</p>
          {current === 'case' && <>
            <CtiField label={`${tr('wizard.name')} *`}><input autoFocus required maxLength={200} className={ctiInput} value={name} onChange={e => setName(e.target.value)} /></CtiField>
            <CtiField label={`${tr('cti.caseId')}${configured ? ' *' : ''}`}><input required={configured} maxLength={200} className={ctiInput} value={reference} onChange={e => setReference(e.target.value)} /></CtiField>
            <CtiField label={`${tr('cti.summary')}${configured ? ' *' : ''}`}><textarea required={configured} maxLength={10000} rows={4} className={ctiInput} value={profile.summary} onChange={e => setProfile({ ...profile, summary: e.target.value })} /></CtiField>
          </>}
          {configured && <CaseProfileFields profile={profile} onChange={setProfile} section={current === 'affected' || current === 'technical' ? current : 'hidden'} requiredContext />}
          {current === 'affected' && <CtiError error={invalidCountries ? tr('wizard.countriesError') : invalidDates ? tr('cti.dateError') : null} />}
          {current === 'technical' && !technicalValid && <CtiError error={tr('wizard.technicalError')} />}
          {current === 'review' && <>
            <dl className="grid gap-5 sm:grid-cols-2">
              {summaryItem(tr('wizard.name'), name)}{summaryItem(tr('cti.caseId'), reference)}
              <div className="sm:col-span-2">{summaryItem(tr('cti.summary'), profile.summary)}</div>
              {configured && <>
                {summaryItem(tr('cti.organizationName'), profile.organization_name || profile.pseudonym)}{summaryItem(tr('cti.marking'), profile.marking)}
                {summaryItem(tr('cti.sectors'), profile.sectors.join(', '))}{summaryItem(tr('cti.subsectors'), (profile.subsectors ?? []).map(item => item.name).join(', '))}
                {summaryItem(tr('cti.country'), profile.countries.map(code => geography.data?.countries.find(item => item.code === code)?.name || code).join(', '))}
                {summaryItem(tr('cti.state'), geography.data?.states[profile.countries[0]]?.find(item => item.code === profile.state)?.name || profile.state || '')}
                {summaryItem(tr('cti.city'), profile.city || '')}
                {summaryItem(tr('cti.firstSeen'), profile.first_seen)}{summaryItem(tr('cti.lastSeen'), profile.last_seen)}
                {summaryItem(tr('cti.software'), profile.software.map(item => `${item.name}${item.version ? ` · ${item.version}` : ''}`).join('\n'))}
              </>}
            </dl>
            {configured && <section className="space-y-2"><h3 className="text-[13px] font-semibold">{tr('cti.vulns')}</h3>
              {profile.vulnerabilities.length ? profile.vulnerabilities.map((item, index) => <div key={index} className="rounded-lg border border-[var(--line)] p-3 text-[13px]"><div className="flex flex-wrap items-center gap-2"><strong>{item.name}</strong><Tag tone={item.status === 'confirmed' ? 'danger' : 'warn'}>{tr(item.status === 'confirmed' ? 'cti.confirmed' : 'cti.suspected')}</Tag></div>{item.description && <p className="mt-2 whitespace-pre-wrap">{item.description}</p>}</div>) : <p className="text-[13px]">{tr('wizard.unknown')}</p>}
            </section>}
            <p className="rounded-lg bg-[var(--panel-2)] p-3 text-[12px] text-[var(--muted)]">{tr(configured ? 'wizard.savedLocally' : 'wizard.savedLocally.local')}</p>
          </>}
        </div>
      </div>
      <CtiError error={save.error} />
      <footer className="flex shrink-0 items-center gap-2 border-t border-[var(--line)] pt-4">
        <Button type="button" disabled={save.isPending} onClick={close}>{tr('common.cancel')}</Button>
        <div className="ml-auto flex gap-2">
          {step > 0 && <Button type="button" disabled={save.isPending} onClick={() => setStep(step - 1)}><ChevronLeft size={14} />{tr('wizard.back')}</Button>}
          <Button type="submit" variant="primary" disabled={!stepValid || save.isPending}>{tr(save.isPending ? 'wizard.creating' : current === 'review' ? 'start.create' : 'wizard.next')}{current !== 'review' && <ChevronRight size={14} />}</Button>
        </div>
      </footer>
    </form>
  </Modal>
}
