import { useState, type Dispatch, type SetStateAction } from 'react'
import { newCaseContext, useProfileOptions, type CaseContext, type CaseProfile } from '../../opencti'
import { useT, type Translate } from '../../i18n'
import { CtiError, CtiField, ctiInput } from './CaseProfile'
import { Button } from '../ui/ui'

const groups: { name: string; fields: (keyof CaseContext)[] }[] = [
  { name: 'company', fields: ['employee_count', 'hosting_model', 'hosting_providers', 'it_operating_model'] },
  { name: 'incident', fields: ['initial_access', 'initial_access_status', 'spread', 'data_exfiltration', 'attacker_encryption', 'discovered_by', 'discovery_method'] },
]

function optionLabel(field: keyof CaseContext, value: string, tr: Translate) {
  const key = value === 'unknown' ? 'caseContext.unknown' : `caseContext.option.${field}.${value}`
  return tr(key)
}

export function CaseContextFields({ profile, onChange }: {
  profile: CaseProfile; onChange: Dispatch<SetStateAction<CaseProfile>>
}) {
  const tr = useT()
  const catalogue = useProfileOptions()
  const context = { ...newCaseContext(), ...profile }
  const [customProvider, setCustomProvider] = useState('')
  const [showCustomProvider, setShowCustomProvider] = useState(false)
  const addProvider = (value: string) => {
    const name = value.trim()
    if (!name || context.hosting_providers.length >= 20 || context.hosting_providers.some(item => item.toLowerCase() === name.toLowerCase())) return
    onChange(previous => ({ ...previous, hosting_providers: [...(previous.hosting_providers ?? []), name] }))
    setCustomProvider('')
    setShowCustomProvider(false)
  }
  return <div className="space-y-5">
    <p className="text-[12px] text-[var(--muted)]">{tr('caseContext.manualHint')}</p>
    <CtiError error={catalogue.error} />
    {groups.map(group => <fieldset key={group.name} className="grid gap-3 rounded-lg border border-[var(--line)] p-3 sm:grid-cols-2">
      <legend className="px-1 text-[13px] font-semibold">{tr(`caseContext.group.${group.name}`)}</legend>
      <p className="text-[12px] text-[var(--muted)] sm:col-span-2">{tr(`caseContext.hint.${group.name}`)}</p>
      {group.fields.map(field => {
        const choices = catalogue.data?.context_options?.[field] ?? []
        if (field === 'hosting_providers') return <fieldset key={field} className="min-w-0 space-y-2">
          <legend className="mb-1 text-[12px] text-[var(--muted)]">{tr('caseContext.field.hosting_providers')}</legend>
          <select aria-label={tr('caseContext.field.hosting_providers')} className={ctiInput} value={showCustomProvider ? '__other__' : ''} disabled={context.hosting_providers.length >= 20} onChange={event => {
            if (event.target.value === '__other__') setShowCustomProvider(true)
            else if (event.target.value) addProvider(event.target.value)
            else setShowCustomProvider(false)
          }}>
            <option value="">{tr('caseContext.chooseProvider')}</option>
            {choices.map(value => <option key={value} value={value} disabled={context.hosting_providers.some(item => item.toLowerCase() === value.toLowerCase())}>{value}</option>)}
            <option value="__other__">{tr('caseContext.otherProvider')}</option>
          </select>
          {showCustomProvider && <div className="space-y-2">
            <CtiField label={tr('caseContext.providerName')}><input className={ctiInput} maxLength={200} value={customProvider} onChange={event => setCustomProvider(event.target.value)} onKeyDown={event => {
              if (event.key === 'Enter') { event.preventDefault(); addProvider(customProvider) }
            }} /></CtiField>
            <Button type="button" disabled={!customProvider.trim() || context.hosting_providers.some(item => item.toLowerCase() === customProvider.trim().toLowerCase())} onClick={() => addProvider(customProvider)}>{tr('caseContext.addProvider')}</Button>
          </div>}
          {context.hosting_providers.length > 0 && <ul className="space-y-1">{context.hosting_providers.map((value, index) => <li key={value} className="flex items-center justify-between gap-2 text-[13px]">
            <span className="min-w-0 break-words">{value}</span>
            <Button type="button" aria-label={tr('caseContext.removeProvider', { name: value })} onClick={() => onChange(previous => ({ ...previous, hosting_providers: (previous.hosting_providers ?? []).filter((_, i) => i !== index) }))}>{tr('common.remove')}</Button>
          </li>)}</ul>}
          <p className="text-[12px] text-[var(--muted)]">{tr('caseContext.providersHint')}</p>
        </fieldset>
        if (field === 'spread') return <fieldset key={field} className="space-y-2 sm:col-span-2">
          <legend className="text-[12px] text-[var(--muted)]">{tr('caseContext.field.spread')}</legend>
          <div className="grid gap-2 sm:grid-cols-2">{choices.map(value => <label key={value} className="flex items-center gap-2 text-[13px]">
            <input type="checkbox" checked={context.spread.includes(value)} onChange={event => onChange(previous => ({ ...previous,
              spread: event.target.checked ? [...(previous.spread ?? []), value] : (previous.spread ?? []).filter(item => item !== value),
            }))} />{optionLabel(field, value, tr)}
          </label>)}</div>
          <p className="text-[12px] text-[var(--muted)]">{tr('caseContext.spreadHint')}</p>
        </fieldset>
        const value = context[field]
        const options = [...new Set(['unknown', ...choices, value])]
        return <CtiField key={field} label={tr(`caseContext.field.${field}`)}>
          <select className={ctiInput} value={value} disabled={field === 'initial_access_status' && context.initial_access === 'unknown'} onChange={event => {
            const selected = event.target.value
            onChange(previous => ({ ...previous, [field]: selected,
              ...(field === 'initial_access' && selected === 'unknown' ? { initial_access_status: 'unknown' } : {}),
            }))
          }}>{options.map(item => <option key={item} value={item}>{optionLabel(field, item, tr)}</option>)}</select>
        </CtiField>
      })}
    </fieldset>)}
  </div>
}

export function CaseContextSummary({ profile }: { profile?: Partial<CaseContext> }) {
  const tr = useT()
  const context = { ...newCaseContext(), ...profile }
  return <dl aria-label={tr('caseContext.summary')} className="grid gap-x-6 gap-y-4 sm:grid-cols-2">
    {groups.flatMap(group => group.fields).map(field => {
      const value = context[field]
      const text = Array.isArray(value)
        ? value.map(item => field === 'hosting_providers' ? item : optionLabel(field, item, tr)).join(', ')
        : optionLabel(field, value, tr)
      return <div key={field} className="min-w-0 space-y-1"><dt className="text-[12px] text-[var(--muted)]">{tr(`caseContext.field.${field}`)}</dt>
        <dd className="whitespace-pre-wrap break-words text-[13px]">{text || tr('caseContext.unknown')}</dd></div>
    })}
  </dl>
}
