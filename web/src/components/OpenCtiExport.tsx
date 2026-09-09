import { useEffect, useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { post } from '../api'
import { useT } from '../i18n'
import { formatBytes } from '../format'
import type { OpenCtiOptions, OpenCtiPreview } from '../opencti'
import { Button, Modal, Tag, Tabs } from './ui'
import { CtiError } from './CaseProfile'
import { IocTag } from './IocTags'
import { InfoDot, Tooltip } from './Tooltip'
import { SelectColumn } from './OpenCtiSelection'
import { iocCategories, inIocCategory, selectBatch, selectionTable, selectionHead } from './ctiSelectionModel'

function toggled<T>(values: T[], item: T, present: boolean): T[] { return present ? [...new Set([...values, item])] : values.filter((value) => value !== item) }

export function OpenCtiExportDialog({ slug, initial, initialOptions, onClose, onQueued }: {
  slug: string; initial: OpenCtiPreview; initialOptions: OpenCtiOptions; onClose: () => void; onQueued: () => void
}) {
  const tr = useT()
  const [tab, setTab] = useState('all')
  const [options, setOptions] = useState<OpenCtiOptions>(() => ({ ...initialOptions, exclude_relationship_ids: [] }))
  const [preview, setPreview] = useState(initial)
  const [reviewedOptions, setReviewedOptions] = useState(JSON.stringify(initialOptions))
  const optionsKey = JSON.stringify(options)
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
      void post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, JSON.parse(optionsKey)).then(data => {
        if (!current) return
        setPreview(data)
        setReviewedOptions(optionsKey)
      }).catch(error => {
        if (current) setFailure({ key: optionsKey, error: error instanceof Error ? error : new Error(String(error)) })
      })
    }, 300)
    return () => { current = false; window.clearTimeout(timer) }
  }, [optionsKey, reviewedOptions, slug, retry])
  const transfer = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/export`, { preview_id: preview.preview_id }), onSuccess: onQueued })
  const selected = (id: number) => options.ioc_ids?.includes(id) ?? true
  const category = iocCategories.includes(tab)
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
  return <Modal open title={tr('cti.preview')} onClose={onClose} contained bodyClassName="overflow-hidden px-5 py-4"><div className="flex h-full min-h-0 flex-col gap-3 text-[12px]">
    <div className="shrink-0 space-y-3">
    <p>{tr('cti.simplePreviewBody')}</p><div className="flex items-center gap-2"><Tag>{preview.case_reference || tr('cti.caseId')}</Tag></div>
    {preview.errors.map((error) => <CtiError key={error} error={error} />)}
    <div className="flex flex-wrap gap-3"><label className="flex gap-2"><input type="checkbox" checked={options.include_notes} onChange={(e) => change('include_notes', e.target.checked)} />{tr('cti.previewNotes')}</label><InfoDot body={tr('cti.previewNotesHelp')} />
      <label className="flex gap-2"><input type="checkbox" checked={options.include_evidence} onChange={(e) => change('include_evidence', e.target.checked)} />{tr('cti.previewEvidence')}</label><InfoDot body={tr('cti.previewEvidenceHelp')} />
    </div>
    </div>
    <div className="shrink-0 space-y-1 [&_[role=tab]]:shrink-0 [&_[role=tab]]:whitespace-nowrap">
    <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={[...iocCategories.map(id => ({ id, label: tr(`cti.category.${id}`), badge: <span className="ml-1 text-[10px]">{initial.iocs.filter(ioc => inIocCategory(ioc.type, id)).length}</span> })), { id: 'samples', label: tr('cti.samples'), badge: <span className="ml-1 text-[10px]">{initial.samples.length}</span> }]} /></div>
    {!!preview.warnings.length && <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={[{ id: 'notices', label: tr('cti.notices'), badge: <span className="ml-2">{preview.warnings.length}</span> }]} /></div>}</div>
    <div className="min-h-0 flex-1 overflow-hidden">
    <div hidden={tab !== 'notices'} role="tabpanel" aria-label={tr('cti.notices')} className="h-full overflow-y-auto [scrollbar-gutter:stable] space-y-2">{preview.warnings.map(warning => <p key={warning} className="rounded border border-[var(--line)] p-3 text-[var(--review-text)]">{warning}</p>)}</div>
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
    <div hidden={tab !== 'samples'} role="tabpanel" aria-label={tr('cti.samples')} className="h-full overflow-auto [scrollbar-gutter:stable]">
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
      <Button onClick={onClose}>{tr('common.cancel')}</Button>
      {buildError && <Button onClick={() => { setFailure(null); setRetry(value => value + 1) }}>{tr('cti.previewRetry')}</Button>}
      <Button variant="primary" disabled={dirty || transfer.isPending || !!preview.errors.length || !preview.case_reference || !options.ioc_ids?.length} onClick={() => transfer.mutate()}>{tr('cti.confirmTransfer')}</Button>
    </div>
    </div>
  </div></Modal>
}
