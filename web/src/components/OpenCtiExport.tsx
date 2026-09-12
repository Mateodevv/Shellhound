import { useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { post, type CaseInfo } from '../api'
import { useT } from '../i18n'
import { formatBytes } from '../format'
import type { OpenCtiOptions, OpenCtiPreview } from '../opencti'
import { Button, Modal, Tag, Tabs } from './ui'
import { CaseProfileButton, CtiError } from './CaseProfile'
import { IocTag } from './IocTags'
import { InfoDot, Tooltip } from './Tooltip'
import { SelectColumn } from './OpenCtiSelection'
import { iocCategories, inIocCategory, selectBatch, selectionTable, selectionHead } from './ctiSelectionModel'
import { webshellIndicatorDefaults } from './ctiSelectionModel'

function toggled<T>(values: T[], item: T, present: boolean): T[] { return present ? [...new Set([...values, item])] : values.filter((value) => value !== item) }

export function OpenCtiExportDialog({ slug, initial, initialOptions, onClose, onQueued, wizard = false, caseInfo, embedded = false, activeStep, onStepChange, onSkipTransfer }: {
  slug: string; initial: OpenCtiPreview; initialOptions: OpenCtiOptions; onClose: () => void; onQueued: (result: { job_id: number; export_id?: string }) => void
  wizard?: boolean; caseInfo?: CaseInfo; embedded?: boolean; activeStep?: number; onStepChange?: (step: number) => void; onSkipTransfer?: () => void
}) {
  const tr = useT()
  const [tab, setTab] = useState('all')
  const [localStep, setLocalStep] = useState(0)
  const step = activeStep ?? localStep
  const setStep = (value: number) => { setLocalStep(value); onStepChange?.(value) }
  const steps = ['context', 'iocs', 'samples', 'review']
  const contextVersion = JSON.stringify([caseInfo?.reference, caseInfo?.profile])
  const [options, setOptions] = useState<OpenCtiOptions>(() => ({ ...initialOptions, exclude_relationship_ids: [],
    indicator_ids: [...new Set([...initialOptions.indicator_ids, ...webshellIndicatorDefaults(initial, initialOptions)])] }))
  const [preview, setPreview] = useState(initial)
  const [reviewedOptions, setReviewedOptions] = useState(JSON.stringify([initialOptions, contextVersion]))
  const optionsKey = JSON.stringify([options, contextVersion])
  const dirty = optionsKey !== reviewedOptions
  const [failure, setFailure] = useState<{ key: string; error: Error } | null>(null)
  const [retry, setRetry] = useState(0)
  const buildError = dirty && failure?.key === optionsKey ? failure.error : null
  const change = <K extends keyof OpenCtiOptions>(key: K, value: OpenCtiOptions[K]) => setOptions((o) => ({ ...o, [key]: value }))
  useEffect(() => {
    if (optionsKey === reviewedOptions) return
    let current = true
    const timer = window.setTimeout(() => {
      setFailure(null)
      void post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, JSON.parse(optionsKey)[0]).then(data => {
        if (!current) return
        setPreview(data)
        setReviewedOptions(optionsKey)
      }).catch(error => {
        if (current) setFailure({ key: optionsKey, error: error instanceof Error ? error : new Error(String(error)) })
      })
    }, 300)
    return () => { current = false; window.clearTimeout(timer) }
  }, [optionsKey, reviewedOptions, slug, retry])
  const transfer = useMutation({ mutationFn: (previewId: string) => post<{ job_id: number; export_id?: string }>(`/api/cases/${slug}/opencti/export`, { preview_id: previewId }), onSuccess: onQueued })
  const selected = (id: number) => options.ioc_ids?.includes(id) ?? true
  const category = (!wizard || step === 1) && iocCategories.includes(tab)
  const visible = initial.iocs.filter(ioc => inIocCategory(ioc.type, tab))
  const included = visible.filter(ioc => selected(ioc.id))
  const indicators = included.filter(ioc => ioc.indicator_supported)
  const chooseIocs = (ids: number[], checked: boolean) => setOptions(previous => {
    const removed = initial.iocs.filter(ioc => ids.includes(ioc.id))
    return { ...previous, ioc_ids: selectBatch(previous.ioc_ids ?? initial.iocs.map(ioc => ioc.id), ids, checked),
      indicator_ids: checked ? previous.indicator_ids : previous.indicator_ids.filter(id => !ids.includes(id)),
      sample_ids: checked ? previous.sample_ids : previous.sample_ids.filter(id => !initial.samples.some(sample => sample.id === id && removed.some(ioc => ioc.object_ids.includes(sample.file_id)))) }
  })
  const usableSamples = initial.samples.filter(sample => sample.available && initial.iocs.some(ioc => selected(ioc.id) && ioc.object_ids.includes(sample.file_id)))
  const columnCount = 5 + Number(options.include_notes) + Number(options.include_evidence)
  const profile = caseInfo?.profile
  const item = (label: string, value: string) => <div className="min-w-0"><dt className="text-[12px] font-semibold text-[var(--muted)]">{label}</dt><dd className="mt-1 whitespace-pre-wrap break-words text-[13px]">{value || tr('wizard.unknown')}</dd></div>
  const selectedCount = initial.iocs.filter(ioc => selected(ioc.id)).length
  const close = () => { if (!transfer.isPending) onClose() }
  const content = <div className="flex h-full min-h-0 flex-col gap-3 text-[12px]">
    {wizard && !embedded && <nav aria-label={tr('transferWizard.steps')} className="shrink-0 border-b border-[var(--line)] pb-3"><ol className="flex flex-wrap gap-2">{steps.map((name, index) => <li key={name}><button type="button" disabled={index > step || transfer.isPending} aria-current={step === index ? 'step' : undefined} onClick={() => setStep(index)} className={`ui-press flex items-center gap-2 rounded-lg px-3 py-2 text-[13px] ${step === index ? 'bg-[var(--accent-soft)] font-semibold text-[var(--accent-text)]' : 'text-[var(--muted)] disabled:opacity-50'}`}><span className="flex h-5 w-5 items-center justify-center rounded-full border border-current text-[11px]">{index + 1}</span>{tr(`transferWizard.step.${name}`)}</button></li>)}</ol></nav>}
    <div className="shrink-0 space-y-3">
    <p>{tr(wizard ? `transferWizard.help.${steps[step]}` : 'cti.simplePreviewBody')}</p><div className="flex items-center gap-2"><Tag>{preview.case_reference || tr('cti.caseId')}</Tag></div>
    {preview.errors.map((error) => <CtiError key={error} error={error} />)}
    <div hidden={wizard && step !== 1}><div className="flex flex-wrap gap-3"><label className="flex gap-2"><input type="checkbox" checked={options.include_notes} onChange={(e) => change('include_notes', e.target.checked)} />{tr('cti.previewNotes')}</label><InfoDot body={tr('cti.previewNotesHelp')} />
      <label className="flex gap-2"><input type="checkbox" checked={options.include_evidence} onChange={(e) => change('include_evidence', e.target.checked)} />{tr('cti.previewEvidence')}</label><InfoDot body={tr('cti.previewEvidenceHelp')} />
    </div></div>
    </div>
    <div hidden={wizard && step !== 1} className="shrink-0 space-y-1 [&_[role=tab]]:shrink-0 [&_[role=tab]]:whitespace-nowrap">
    <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={[...iocCategories.map(id => ({ id, label: tr(`cti.category.${id}`), badge: <span className="ml-1 text-[10px]">{initial.iocs.filter(ioc => inIocCategory(ioc.type, id)).length}</span> })), ...(!wizard ? [{ id: 'samples', label: tr('cti.samples'), badge: <span className="ml-1 text-[10px]">{initial.samples.length}</span> }] : [])]} /></div>
    {!wizard && !!preview.warnings.length && <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={[{ id: 'notices', label: tr('cti.notices'), badge: <span className="ml-2">{preview.warnings.length}</span> }]} /></div>}</div>
    <div className="min-h-0 flex-1 overflow-hidden">
    {wizard && step === 0 && <section className="h-full overflow-y-auto pr-2" aria-label={tr('transferWizard.step.context')}><div className="mb-4 flex items-center justify-between gap-2"><h2 className="text-lg font-semibold">{caseInfo?.name || preview.case_reference}</h2><CaseProfileButton slug={slug} /></div><dl className="grid gap-4 sm:grid-cols-2">
      {item(tr('cti.caseId'), caseInfo?.reference || preview.case_reference)}{item(tr('cti.marking'), profile?.marking || '')}
      <div className="sm:col-span-2">{item(tr('cti.summary'), profile?.summary || '')}</div>
      {item(tr('cti.organizationName'), profile?.organization_name || profile?.pseudonym || '')}{item(tr('cti.sectors'), profile?.sectors.join(', ') || '')}
      {item(tr('cti.subsectors'), profile?.subsectors?.map(entry => entry.name).join(', ') || '')}{item(tr('cti.country'), profile?.countries.join(', ') || '')}
      {item(tr('cti.state'), profile?.state || '')}{item(tr('cti.city'), profile?.city || '')}
      {item(tr('cti.firstSeen'), profile?.first_seen || '')}{item(tr('cti.lastSeen'), profile?.last_seen || '')}
      {item(tr('cti.software'), profile?.software.map(entry => [entry.name, entry.version].filter(Boolean).join(' ')).join(', ') || '')}
      {item(tr('cti.vulns'), profile?.vulnerabilities.map(entry => entry.name).join(', ') || '')}
    </dl></section>}
    {wizard && step === 3 && <section aria-label={tr('transferWizard.step.review')} className="h-full space-y-4 overflow-y-auto pr-2">
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {item(tr('cti.caseId'), preview.case_reference)}{item(tr('cti.iocs'), String(selectedCount))}{item(tr('cti.indicator'), String(options.indicator_ids.length))}
        {item(tr('cti.samples'), String(options.sample_ids.length))}{item(tr('cti.previewNotes'), tr(options.include_notes ? 'transferWizard.included' : 'transferWizard.excluded'))}{item(tr('cti.previewEvidence'), tr(options.include_evidence ? 'transferWizard.included' : 'transferWizard.excluded'))}
      </dl>
      <p className="rounded-lg border border-[var(--line)] p-3">{tr('cti.caseModel')} {tr('transferWizard.relationships')}</p>
      <div className="flex flex-wrap gap-2">{[...new Set(preview.objects.map(object => object.type))].map(type => <Tag key={type}>{type === 'x-opencti-case-incident' ? tr('cti.caseContainer') : type} · {preview.objects.filter(object => object.type === type).length}</Tag>)}</div>
      {preview.warnings.map(warning => <p key={warning} className="rounded border border-[var(--line)] p-3 text-[var(--review-text)]">{warning}</p>)}
      <p className="text-[var(--muted)]">{tr(embedded ? 'closeWizard.transferHelp' : 'transferWizard.finalHelp')}</p>
    </section>}

    <div hidden={wizard || tab !== 'notices'} role="tabpanel" aria-label={tr('cti.notices')} className="h-full overflow-y-auto [scrollbar-gutter:stable] space-y-2">{preview.warnings.map(warning => <p key={warning} className="rounded border border-[var(--line)] p-3 text-[var(--review-text)]">{warning}</p>)}</div>
    <div hidden={!category} role="tabpanel" aria-label={tr('cti.iocs')} className="h-full overflow-auto [scrollbar-gutter:stable]">
      <table className={selectionTable}>
        <colgroup><col style={{ width: 48 }} /><col /><col style={{ width: 100 }} /><col style={{ width: '28%' }} />{options.include_notes && <col style={{ width: 80 }} />}{options.include_evidence && <col style={{ width: 90 }} />}<col style={{ width: 160 }} /></colgroup>
        <thead className={selectionHead}><tr>
          <th><SelectColumn label={tr('cti.iocs')} states={visible.map(ioc => selected(ioc.id))} onChange={checked => chooseIocs(visible.map(ioc => ioc.id), checked)} /></th>
          <th>{tr('iocTable.object')}</th><th>{tr('iocTable.type')}</th><th>{tr('iocTags.title')}</th>
          {options.include_notes && <th className="text-left"><div className="flex items-center gap-2"><SelectColumn label={tr('cti.notes')} states={included.map(ioc => !options.exclude_note_ioc_ids.includes(ioc.id))} onChange={checked => change('exclude_note_ioc_ids', selectBatch(options.exclude_note_ioc_ids, included.map(ioc => ioc.id), !checked))} />{tr('cti.notes')}</div></th>}
          {options.include_evidence && <th className="text-left"><div className="flex items-center gap-2"><SelectColumn label={tr('cti.evidence')} states={included.map(ioc => !options.exclude_evidence_ioc_ids.includes(ioc.id))} onChange={checked => change('exclude_evidence_ioc_ids', selectBatch(options.exclude_evidence_ioc_ids, included.map(ioc => ioc.id), !checked))} />{tr('cti.evidence')}</div></th>}
          <th className="text-left"><div className="flex items-center gap-2"><SelectColumn label={tr('cti.indicator')} states={indicators.map(ioc => options.indicator_ids.includes(ioc.id))} onChange={checked => change('indicator_ids', selectBatch(options.indicator_ids, indicators.map(ioc => ioc.id), checked))} />{tr('cti.indicator')}</div></th>
        </tr></thead>
        <tbody>{visible.map(ioc => <tr key={ioc.id}>
          <td><input type="checkbox" aria-label={tr('cti.selectIoc', { value: ioc.value })} checked={selected(ioc.id)} onChange={e => chooseIocs([ioc.id], e.target.checked)} /></td>
          <td><span className="break-all font-normal tabular-nums">{ioc.value}</span>{ioc.warnings.map(warning => <p key={warning} className="text-[var(--review-text)]">{warning}</p>)}</td>
          <td><Tag>{ioc.type}</Tag></td>
          <td><div className="flex flex-wrap items-center gap-1">{ioc.tags?.slice(0, 2).map(tag => <IocTag key={tag} value={tag} />)}{(ioc.tags?.length ?? 0) > 2 && <Tooltip body={ioc.tags!.slice(2).join(' · ')}><span className="rounded bg-[var(--panel-2)] px-1.5 py-0.5 text-[11px] text-[var(--muted)]" aria-label={tr('cti.moreTags', { n: ioc.tags!.length - 2 })}>+{ioc.tags!.length - 2}</span></Tooltip>}</div></td>
          {options.include_notes && <td className="text-left"><input type="checkbox" aria-label={tr('cti.optionFor', { option: tr('cti.notes'), value: ioc.value })} disabled={!selected(ioc.id)} checked={selected(ioc.id) && !options.exclude_note_ioc_ids.includes(ioc.id)} onChange={e => change('exclude_note_ioc_ids', toggled(options.exclude_note_ioc_ids, ioc.id, !e.target.checked))} /></td>}
          {options.include_evidence && <td className="text-left"><input type="checkbox" aria-label={tr('cti.optionFor', { option: tr('cti.evidence'), value: ioc.value })} disabled={!selected(ioc.id)} checked={selected(ioc.id) && !options.exclude_evidence_ioc_ids.includes(ioc.id)} onChange={e => change('exclude_evidence_ioc_ids', toggled(options.exclude_evidence_ioc_ids, ioc.id, !e.target.checked))} /></td>}
          <td className="relative text-left">{ioc.indicator_supported ? <><input type="checkbox" aria-label={tr('cti.optionFor', { option: tr('cti.indicator'), value: ioc.value })} disabled={!selected(ioc.id)} checked={options.indicator_ids.includes(ioc.id)} onChange={e => change('indicator_ids', toggled(options.indicator_ids, ioc.id, e.target.checked))} />{ioc.indicator_suggested && <span className="absolute ml-2"><InfoDot body={tr('cti.suggested')} /></span>}</> : '—'}</td>
        </tr>)}{!visible.length && <tr><td colSpan={columnCount}>{tr('iocWorkspace.no_matching_objects')}</td></tr>}</tbody>
      </table>
    </div>
    <div hidden={wizard ? step !== 2 : tab !== 'samples'} role="tabpanel" aria-label={tr('cti.samples')} className="h-full overflow-auto [scrollbar-gutter:stable]">
      <table className={selectionTable}><colgroup><col style={{ width: 48 }} /><col style={{ width: '35%' }} /><col style={{ width: 80 }} /><col /></colgroup>
        <thead className={selectionHead}><tr><th><SelectColumn label={tr('cti.samples')} states={usableSamples.map(sample => options.sample_ids.includes(sample.id))} onChange={checked => change('sample_ids', selectBatch(options.sample_ids, usableSamples.map(sample => sample.id), checked))} /></th><th>{tr('cti.sampleFile')}</th><th>{tr('cti.sampleSize')}</th><th>SHA-256</th></tr></thead>
        <tbody>{initial.samples.map(sample => <tr key={sample.id}><td><input type="checkbox" aria-label={tr('cti.selectSample', { path: sample.display_path })} disabled={!usableSamples.some(item => item.id === sample.id)} checked={options.sample_ids.includes(sample.id)} onChange={e => change('sample_ids', toggled(options.sample_ids, sample.id, e.target.checked))} /></td><td className="break-all">{sample.display_path}{sample.reason && <p className="text-[var(--review-text)]">{sample.reason}</p>}</td><td className="whitespace-nowrap">{formatBytes(sample.size)}</td><td className="break-all font-normal">{sample.sha256}</td></tr>)}{!initial.samples.length && <tr><td colSpan={4}>{tr('cti.noSamples')}</td></tr>}</tbody>
      </table>
    </div>
    </div>
    <div className="shrink-0 space-y-2 border-t border-[var(--line)] pt-3">
    <CtiError error={buildError || transfer.error} />
    <div className="flex min-h-10 flex-wrap items-center gap-2">
      <p className="mr-auto text-[12px] text-[var(--muted)]" role="status">{dirty ? tr(buildError ? 'cti.previewFailed' : 'cti.previewUpdating') : tr('cti.selectionCount', { n: initial.iocs.filter(ioc => selected(ioc.id)).length, total: initial.iocs.length })}</p>
      {!embedded && <Button disabled={transfer.isPending} onClick={close}>{tr('common.cancel')}</Button>}
      {onSkipTransfer && <Button disabled={transfer.isPending} onClick={onSkipTransfer}>{tr('closeWizard.skip')}</Button>}
      {buildError && <Button onClick={() => { setFailure(null); setRetry(value => value + 1) }}>{tr('cti.previewRetry')}</Button>}
      {wizard && step > 0 && <Button disabled={transfer.isPending} onClick={() => setStep(step - 1)}>{tr('wizard.back')}</Button>}
      {wizard && step < 3 ? <Button variant="primary" disabled={step === 1 && !selectedCount} onClick={() => { setTab('all'); setStep(step + 1) }}>{tr('wizard.next')}</Button> : <Button variant="primary" disabled={dirty || transfer.isPending || !!preview.errors.length || !preview.case_reference || !options.ioc_ids?.length} onClick={() => transfer.mutate(preview.preview_id)}>{tr('cti.confirmTransfer')}</Button>}
    </div>
    </div>
  </div>
  return embedded ? content : <Modal open title={tr(wizard ? 'transferWizard.title' : 'cti.preview')} onClose={close} contained bodyClassName="overflow-hidden px-5 py-4">{content}</Modal>
}
