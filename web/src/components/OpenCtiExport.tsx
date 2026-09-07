import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { post } from '../api'
import { useT } from '../i18n'
import { formatBytes } from '../format'
import type { OpenCtiOptions, OpenCtiPreview } from '../opencti'
import { Button, Modal, Tag } from './ui'
import { CaseProfileButton, CtiError } from './CaseProfile'

const profileLabels: Record<string, string> = { summary: 'cti.summary', software: 'cti.software', vulnerabilities: 'cti.vulns', sectors: 'cti.sectors', countries: 'cti.countries', first_seen: 'cti.firstSeen', last_seen: 'cti.lastSeen', case_notes: 'cti.caseNotes' }
function toggled<T>(values: T[], item: T, present: boolean): T[] { return present ? [...new Set([...values, item])] : values.filter((value) => value !== item) }

export function OpenCtiExportDialog({ slug, initial, initialOptions, onClose, onQueued }: {
  slug: string; initial: OpenCtiPreview; initialOptions: OpenCtiOptions; onClose: () => void; onQueued: () => void
}) {
  const tr = useT()
  const [options, setOptions] = useState(initialOptions)
  const [preview, setPreview] = useState(initial)
  const [reviewedOptions, setReviewedOptions] = useState(JSON.stringify(initialOptions))
  const dirty = JSON.stringify(options) !== reviewedOptions
  const change = <K extends keyof OpenCtiOptions>(key: K, value: OpenCtiOptions[K]) => setOptions((o) => ({ ...o, [key]: value }))
  const build = useMutation({ mutationFn: async () => ({ options: JSON.stringify(options), data: await post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, options) }), onSuccess: (result) => {
    setPreview(result.data); setReviewedOptions(result.options)
  } })
  const transfer = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/export`, { preview_id: preview.preview_id }), onSuccess: onQueued })
  const selected = (id: number) => options.ioc_ids?.includes(id) ?? true
  const values = new Map(initial.iocs.map((ioc) => [ioc.id, ioc.value]))
  return <Modal open title={tr('cti.preview')} onClose={onClose}><div className="flex flex-col gap-4 text-[12px]">
    <p>{tr('cti.previewBody')}</p><div className="flex items-center gap-2"><Tag>{preview.case_reference || tr('cti.caseId')}</Tag><CaseProfileButton slug={slug} /></div>
    {preview.warnings.map((warning) => <p key={warning} className="text-[var(--warn)]">{warning}</p>)}
    {preview.errors.map((error) => <CtiError key={error} error={error} />)}
    <div className="flex flex-wrap gap-3"><label className="flex gap-2"><input type="checkbox" checked={options.include_notes} onChange={(e) => change('include_notes', e.target.checked)} />{tr('cti.previewNotes')}</label>
      <label className="flex gap-2"><input type="checkbox" checked={options.include_evidence} onChange={(e) => change('include_evidence', e.target.checked)} />{tr('cti.previewEvidence')}</label>
    </div>
    <details><summary className="cursor-pointer font-semibold">{tr('cti.profileFields')}</summary><div className="mt-2 flex flex-wrap gap-3">{Object.entries(profileLabels).map(([key, label]) => <label key={key} className="flex gap-2"><input type="checkbox" checked={!options.exclude_profile_fields.includes(key)} onChange={(e) => change('exclude_profile_fields', toggled(options.exclude_profile_fields, key, !e.target.checked))} />{tr(label)}</label>)}</div></details>
    <fieldset className="flex flex-col gap-2"><legend className="mb-2 font-semibold">{tr('cti.iocs')}</legend>{initial.iocs.map((ioc) => <div key={ioc.id} className="flex flex-col gap-2 rounded-lg border border-[var(--line)] p-3">
      <label className="flex items-start gap-2"><input type="checkbox" checked={selected(ioc.id)} onChange={(e) => {
        const ids = options.ioc_ids ?? initial.iocs.map((v) => v.id)
        const included = e.target.checked
        setOptions((previous) => ({ ...previous, ioc_ids: toggled(ids, ioc.id, included), indicator_ids: included ? previous.indicator_ids : previous.indicator_ids.filter((id) => id !== ioc.id), sample_ids: included ? previous.sample_ids : previous.sample_ids.filter((id) => !initial.samples.some((sample) => sample.id === id && ioc.object_ids.includes(sample.file_id))) }))
      }} /><span className="mono break-all">{ioc.value}</span><Tag>{ioc.type}</Tag></label>
      {ioc.warnings.map((warning) => <p key={warning} className="text-[var(--warn)]">{warning}</p>)}
      <div className="flex flex-wrap gap-3 pl-5">
        {options.include_notes && <label className="flex gap-2"><input type="checkbox" disabled={!selected(ioc.id)} checked={!options.exclude_note_ioc_ids.includes(ioc.id)} onChange={(e) => change('exclude_note_ioc_ids', toggled(options.exclude_note_ioc_ids, ioc.id, !e.target.checked))} />{tr('cti.notes')}</label>}
        {options.include_evidence && <label className="flex gap-2"><input type="checkbox" disabled={!selected(ioc.id)} checked={!options.exclude_evidence_ioc_ids.includes(ioc.id)} onChange={(e) => change('exclude_evidence_ioc_ids', toggled(options.exclude_evidence_ioc_ids, ioc.id, !e.target.checked))} />{tr('cti.evidence')}</label>}
        {ioc.indicator_supported && <label className="flex gap-2"><input type="checkbox" disabled={!selected(ioc.id)} checked={options.indicator_ids.includes(ioc.id)} onChange={(e) => change('indicator_ids', toggled(options.indicator_ids, ioc.id, e.target.checked))} /><span>{tr('cti.indicator')}{ioc.indicator_suggested && <span className="ml-2 text-[var(--muted)]">{tr('cti.suggested')}</span>}</span></label>}
      </div>
    </div>)}</fieldset>
    {!!initial.relationships.length && <details open><summary className="cursor-pointer font-semibold">{tr('cti.relationships')}</summary><div className="mt-2 flex flex-col gap-2">{initial.relationships.map((relationship) => <label key={relationship.id} className="flex items-start gap-2 rounded border border-[var(--line)] p-2">
      <input type="checkbox" disabled={!selected(relationship.src_id) || !selected(relationship.dst_id)} checked={!options.exclude_relationship_ids.includes(relationship.id) && selected(relationship.src_id) && selected(relationship.dst_id)} onChange={(e) => change('exclude_relationship_ids', toggled(options.exclude_relationship_ids, relationship.id, !e.target.checked))} />
      <span className="break-all">{values.get(relationship.src_id)} → {relationship.kind} → {values.get(relationship.dst_id)}{relationship.note && <span className="block text-[var(--muted)]">{relationship.note}</span>}</span>
    </label>)}</div></details>}
    <fieldset className="flex flex-col gap-2"><legend className="mb-2 font-semibold">{tr('cti.samples')}</legend>{!initial.samples.length && <p className="text-[var(--muted)]">{tr('cti.noSamples')}</p>}
      {initial.samples.map((sample) => <label key={sample.id} className="flex items-start gap-2 rounded border border-[var(--line)] p-2"><input type="checkbox" disabled={!sample.available} checked={options.sample_ids.includes(sample.id)} onChange={(e) => change('sample_ids', toggled(options.sample_ids, sample.id, e.target.checked))} />
        <span className="min-w-0"><span className="break-all">{sample.display_path} · {formatBytes(sample.size)}</span><span className="mono block break-all">{sample.sha256}</span>{sample.reason && <span className="block text-[var(--warn)]">{sample.reason}</span>}</span>
      </label>)}
    </fieldset>
    <details><summary className="cursor-pointer font-semibold">{tr('cti.objects')} · {preview.objects.length}</summary><pre className="mono mt-2 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-[var(--code-bg)] p-3 text-[11px]">{JSON.stringify(preview.objects, null, 2)}</pre></details>
    {dirty && <p role="status" className="text-[var(--warn)]">{tr('cti.dirty')}</p>}
    <CtiError error={build.error || transfer.error} />
    <div className="sticky bottom-0 flex flex-wrap justify-end gap-2 border-t border-[var(--line)] bg-[var(--panel)] pt-3">
      <Button onClick={onClose}>{tr('common.cancel')}</Button><Button disabled={build.isPending || transfer.isPending} onClick={() => build.mutate()}>{tr('cti.rebuild')}</Button>
      <Button variant="primary" disabled={dirty || build.isPending || transfer.isPending || !!preview.errors.length || !preview.case_reference || !options.ioc_ids?.length} onClick={() => transfer.mutate()}>{tr('cti.confirmTransfer')}</Button>
    </div>
  </div></Modal>
}
