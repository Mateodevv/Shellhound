import { ArrowRight, Clock3, Flag, RotateCcw } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import type { FirstSign as FirstSignData, ChainEvent } from '../api'
import { post } from '../api'
import { formatLogTime } from '../format'
import { useT } from '../i18n'
import { Button, Modal } from './ui'

/** This timestamp is an observation tied to a confirmed finding. Its source
 * stays visible so confirmation of the finding never confirms a copied date. */
export function FirstSign({ slug, data, onTimeline, editing = false, onChoose }: {
  slug: string
  data?: FirstSignData
  onTimeline: (id?: string) => void
  editing?: boolean
  onChoose?: () => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const reset = useMutation({
    mutationFn: () => post<FirstSignData>(`/api/cases/${slug}/first-sign`, { event_id: null }),
    onSuccess: (value) => {
      qc.setQueryData(['first-sign', slug], value)
      void qc.invalidateQueries({ queryKey: ['dashboard', slug] })
      void qc.invalidateQueries({ queryKey: ['chain', slug] })
    },
  })
  const event = data?.event
  const warning = data?.state === 'metadata_only' || data?.state === 'stale_override'
  const tone = warning ? 'var(--review-text)' : event ? 'var(--danger-text)' : 'var(--muted)'
  const background = warning ? 'var(--review-soft)' : event ? 'var(--danger-soft)' : 'var(--panel-2)'
  const source = event?.first_sign_basis === 'filesystem' ? 'firstSign.fileSource'
    : event?.first_sign_basis === 'hunt_match' ? 'firstSign.huntSource' : 'firstSign.logSource'
  const description = !data ? 'firstSign.unavailable' : data.state === 'no_confirmed' ? 'firstSign.noConfirmed'
    : data.state === 'undated' ? 'firstSign.undated' : null
  return <section aria-label={tr('firstSign.title')} className="rounded-xl border border-[var(--line)] px-4 py-3 sm:px-5"
    style={{ background }}>
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="flex min-w-0 flex-1 items-start gap-3">
        {event ? <Flag size={17} className="mt-1 shrink-0" style={{ color: tone }} />
          : <Clock3 size={17} className="mt-1 shrink-0" style={{ color: tone }} />}
        <div className="min-w-0">
          <h3 className="text-sm font-semibold" style={{ color: tone }}>{tr('firstSign.title')}</h3>
          {event ? <>
            <button type="button" onClick={() => onTimeline(event.id)}
              className="mt-1 block cursor-pointer rounded text-left text-sm leading-relaxed hover:underline focus-visible:outline-2 focus-visible:outline-[var(--accent)]">
              <span className="tabular font-semibold">{formatLogTime(event.epoch, 0, { mode: 'utc', withZone: true })}</span>
              <span className="mx-2 text-[var(--muted)]">·</span>
              <span className="break-words">{event.title}</span>
            </button>
            <p className="mt-1 text-xs text-[var(--muted)]">
              {tr(data?.mode === 'manual' ? 'firstSign.manual' : 'firstSign.automatic')} · {tr(source)}
            </p>
          </> : <p role="status" className="mt-1 text-sm text-[var(--muted)]">{tr(description!)}</p>}
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {editing && onChoose ? <Button onClick={onChoose}>{tr('firstSign.choose')}</Button>
          : <Button variant="ghost" onClick={() => onTimeline(event?.id)}>{tr('firstSign.timeline')}<ArrowRight size={14} /></Button>}
        {editing && data?.mode === 'manual' && <Button variant="ghost" disabled={reset.isPending}
          onClick={() => reset.mutate()}><RotateCcw size={13} />{tr('firstSign.restore')}</Button>}
      </div>
    </div>
    {data?.state === 'metadata_only' && <p className="mt-2 text-xs text-[var(--review-text)]">{tr('firstSign.metadata')}</p>}
    {data?.state === 'stale_override' && <p role="status" className="mt-2 text-xs text-[var(--review-text)]">
      {tr('firstSign.stale')} {data.stale_reason}
    </p>}
    {data?.earlier_candidate && <p role="status" className="mt-2 text-xs text-[var(--review-text)]">{tr('firstSign.earlier')}</p>}
    {editing && data?.mode === 'manual' && data.automatic_event && data.automatic_event.id !== event?.id && (
      <div className="mt-3 border-t border-[var(--line)] pt-3 text-xs">
        <span className="mr-2 text-[var(--muted)]">{tr('firstSign.currentSuggestion')}</span>
        <button type="button" onClick={() => onTimeline(data.automatic_event?.id)}
          className="cursor-pointer rounded text-left text-[var(--accent-text)] hover:underline">
          {formatLogTime(data.automatic_event.epoch, 0, { mode: 'utc', withZone: true })}
          {' · '}{data.automatic_event.title}<ArrowRight size={12} className="ml-1 inline" />
        </button>
      </div>
    )}
    {data?.note && <p className={`mt-2 whitespace-pre-wrap break-words text-xs text-[var(--muted)] ${editing ? '' : 'line-clamp-2'}`}>{tr('firstSign.reason')}: {data.note}</p>}
    {reset.error && <p role="alert" className="mt-2 text-xs text-[var(--danger-text)]">{reset.error.message}</p>}
  </section>
}

export function FirstSignEditor({ slug, event, initialNote, onClose, onSaved }: {
  slug: string; event: ChainEvent; initialNote: string; onClose: () => void; onSaved: () => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const [note, setNote] = useState(initialNote)
  const save = useMutation({
    mutationFn: () => post<FirstSignData>(`/api/cases/${slug}/first-sign`, { event_id: event.id, note }),
    onSuccess: (value) => {
      qc.setQueryData(['first-sign', slug], value)
      void qc.invalidateQueries({ queryKey: ['dashboard', slug] })
      void qc.invalidateQueries({ queryKey: ['chain', slug] })
      onSaved()
    },
  })
  return <Modal open title={tr('firstSign.choose')} onClose={() => { if (!save.isPending) onClose() }} layer={1}>
    <div className="flex flex-col gap-4 text-sm">
      <p>{tr('firstSign.overrideHelp')}</p>
      <div className="rounded-lg bg-[var(--panel-2)] p-3">
        <p className="tabular font-semibold">{formatLogTime(event.epoch, 0, { mode: 'utc', withZone: true })}</p>
        <p className="mt-1 break-words">{event.title}</p>
        <p className="mt-1 break-words text-xs text-[var(--muted)]">{event.detail}</p>
      </div>
      {event.first_sign_basis === 'filesystem' && <p className="text-xs text-[var(--review-text)]">{tr('firstSign.metadata')}</p>}
      <label className="flex flex-col gap-1 font-medium">{tr('firstSign.reasonOptional')}
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} maxLength={2000} disabled={save.isPending}
          className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 font-normal text-[var(--fg)]" />
      </label>
      {save.error && <p role="alert" className="text-[var(--danger-text)]">{save.error.message}</p>}
      <div className="flex justify-end gap-2">
        <Button onClick={onClose} disabled={save.isPending}>{tr('common.cancel')}</Button>
        <Button variant="primary" onClick={() => save.mutate()} disabled={save.isPending || !event.id}>{tr('firstSign.save')}</Button>
      </div>
    </div>
  </Modal>
}
