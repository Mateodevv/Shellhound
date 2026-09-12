import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, X } from 'lucide-react'
import { post, type Ioc } from '../api'
import { useT } from '../i18n'
import { Button } from './ui'

export function IocTag({ value, onRemove, disabled }: { value: string; onRemove?: () => void; disabled?: boolean }) {
  const tr = useT()
  // Stable color for a label everywhere it appears, independent of its order.
  const color = [...value.toLowerCase()].reduce((sum, c) => sum + c.charCodeAt(0), 0) % 5
  return <span className={`ioc-tag ioc-tone-${['purple', 'rose', 'green', 'blue', 'yellow'][color]}`}>
    <span className="min-w-0 break-words">{value}</span>
    {onRemove && <button type="button" disabled={disabled} onClick={onRemove} aria-label={tr('iocTags.remove', { tag: value })}><X size={12} /></button>}
  </span>
}

export function IocTags({ slug, object }: { slug: string; object: Ioc }) {
  const tr = useT()
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState('')
  const [saved, setSaved] = useState(false)
  const save = useMutation({
    mutationFn: (change: { add?: string[]; remove?: string[] }) => post<{ tags: string[] }>(`/api/cases/${slug}/iocs/${object.id}/tags`, change),
    onSuccess: () => {
      setDraft(''); setAdding(false); setSaved(true)
      qc.invalidateQueries({ queryKey: ['iocs'] })
      qc.invalidateQueries({ queryKey: ['opencti', slug] })
    },
  })
  return <div className="space-y-2">
    <div className="flex flex-wrap items-center gap-1.5">
      {object.tags.map(tag => <IocTag key={tag} value={tag} disabled={save.isPending} onRemove={() => save.mutate({ remove: [tag] })} />)}
      <button type="button" className="ioc-tag-add" onClick={() => { setAdding(true); setSaved(false) }}><Plus size={12} />{tr('iocTags.add')}</button>
    </div>
    {adding && <form className="flex flex-wrap gap-2" onSubmit={e => { e.preventDefault(); if (draft.trim()) save.mutate({ add: [draft.trim()] }) }}>
      <input autoFocus aria-label={tr('iocTags.name')} maxLength={128} value={draft} onChange={e => setDraft(e.target.value)} className="min-w-0 flex-1 rounded-md border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1" />
      <Button disabled={!draft.trim() || save.isPending}>{tr('common.save')}</Button>
      <Button type="button" onClick={() => { setAdding(false); setDraft('') }}>{tr('common.cancel')}</Button>
    </form>}
    {saved && <p role="status" className="text-[11px] text-[var(--muted)]">{tr('iocTags.saved')}</p>}
    {save.error && <p role="alert" className="text-[var(--danger-text)]">{save.error.message}</p>}
  </div>
}
