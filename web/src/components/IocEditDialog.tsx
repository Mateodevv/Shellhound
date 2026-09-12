import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { post, type Ioc } from '../api'
import { useT } from '../i18n'
import { Button, Modal } from './ui'

const field = 'mt-1 w-full rounded-md border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 font-normal'

export function IocEditDialog({ slug, object, assessments = [], edits = [], onClose }: { slug: string; object: Ioc; assessments?: { id: number; state: string; reason: string; created: string }[]; edits?: { previous_value: string; value: string; reason: string; created: string }[]; onClose: () => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [value, setValue] = useState(object.value)
  const [note, setNote] = useState(object.note)
  const [assessment, setAssessment] = useState(object.assessment || 'malicious')
  const [tags, setTags] = useState(object.tags.join(', '))
  const [reason, setReason] = useState('')
  const locked = object.type === 'file' || (object.type === 'hash' && !!object.file_ids?.length)
  const changed = value !== object.value || note !== object.note || assessment !== (object.assessment || 'malicious') || tags !== object.tags.join(', ')
  const needsReason = value.trim() !== object.value || assessment !== (object.assessment || 'malicious')
  const save = useMutation({ mutationFn: () => {
    const nextTags = tags === object.tags.join(', ') ? object.tags : [...new Set(tags.split(',').map(tag => tag.trim()).filter(Boolean))]
    return post(`/api/cases/${slug}/iocs/${object.id}/edit`, {
      value, note, assessment, expected_value: object.value, expected_note: object.note,
      expected_assessment: object.assessment || 'malicious', reason,
      add_tags: nextTags.filter(tag => !object.tags.includes(tag)),
      remove_tags: object.tags.filter(tag => !nextTags.includes(tag)),
    })
  }, onSuccess: () => {
    qc.invalidateQueries({ queryKey: ['iocs'] })
    qc.invalidateQueries({ queryKey: ['opencti', slug] })
    onClose()
  } })
  const close = () => { if (!save.isPending && (!changed || window.confirm(tr('iocEdit.discard')))) onClose() }
  return <Modal open title={tr('iocEdit.title')} onClose={close} layer={1}>
    <form className="space-y-4 text-[13px]" onSubmit={event => { event.preventDefault(); save.mutate() }}>
      <label className="block font-semibold">{tr('iocEdit.value')}<input className={field} value={value} readOnly={locked} required maxLength={8192} onChange={event => setValue(event.target.value)} /></label>
      {locked && <p className="text-[var(--muted)]">{tr('iocEdit.contentIdentity')}</p>}
      <label className="block font-semibold">{tr('iocEdit.assessment')}<select className={field} value={assessment} onChange={event => setAssessment(event.target.value as NonNullable<Ioc['assessment']>)}>
        {['unassessed', 'suspicious', 'malicious', 'benign'].map(state => <option key={state} value={state}>{state}</option>)}
      </select></label>
      <label className="block font-semibold">{tr('iocWorkspace.note')}<textarea className={field} rows={4} value={note} maxLength={10000} onChange={event => setNote(event.target.value)} /></label>
      <label className="block font-semibold">{tr('iocTags.title')}<input className={field} value={tags} onChange={event => setTags(event.target.value)} /><span className="text-[11px] font-normal text-[var(--muted)]">{tr('iocEdit.tagHint')}</span></label>
      {needsReason && <label className="block font-semibold">{tr('iocEdit.reason')}<textarea className={field} required maxLength={2000} value={reason} onChange={event => setReason(event.target.value)} /></label>}
      {save.error && <p role="alert" className="text-[var(--danger-text)]">{save.error.message}</p>}
      {!!assessments.length && <details><summary className="cursor-pointer font-semibold">{tr('iocWorkspace.assessment_history')}</summary><div className="mt-2 space-y-2">{assessments.map(entry => <div key={entry.id}><strong>{entry.state}</strong> · {entry.created}<p>{entry.reason}</p></div>)}</div></details>}
      {!!edits.length && <details><summary className="cursor-pointer font-semibold">{tr('iocEdit.history')}</summary><div className="mt-2 space-y-3">{edits.map((entry, index) => <div key={index} className="break-words"><p>{entry.previous_value} → {entry.value}</p><p>{entry.reason}</p><span className="text-[var(--muted)]">{entry.created}</span></div>)}</div></details>}
      <div className="flex justify-end gap-2"><Button type="button" disabled={save.isPending} onClick={close}>{tr('common.cancel')}</Button><Button type="submit" variant="primary" disabled={!changed || !value.trim() || (needsReason && !reason.trim()) || save.isPending}>{tr('common.save')}</Button></div>
    </form>
  </Modal>
}
