import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, LoaderCircle, Network, Send } from 'lucide-react'
import { post, type Ioc } from '../../api'
import { useT } from '../../i18n'
import { initialExportOptions, openCtiKey, transferableIoc, useOpenCtiSettings, type OpenCtiPreview } from '../../opencti'
import { Button } from '../ui/ui'
import { CtiError } from '../casework/CaseProfile'
import { OpenCtiExportDialog } from './OpenCtiExport'
import { OpenCtiActivity } from './OpenCtiActivity'

export function GroupedActions({ children, busy = false, label, icon }: { children: ReactNode; busy?: boolean; label?: string; icon?: ReactNode }) {
  const tr = useT()
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const panelId = useId()
  useEffect(() => {
    if (!open) return
    const dismiss = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', dismiss)
    return () => document.removeEventListener('pointerdown', dismiss)
  }, [open])
  return <div ref={root} className="relative" onBlur={event => {
    if (!event.currentTarget.contains(event.relatedTarget as Node)) setOpen(false)
  }} onKeyDown={event => {
    if (event.key === 'Escape' && open) {
      event.stopPropagation()
      setOpen(false)
      root.current?.querySelector('button')?.focus()
    }
  }}>
    <Button type="button" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen(value => !value)}>
      {busy ? <LoaderCircle size={14} className="animate-spin" /> : icon || <Network size={14} />}
      {label || tr('cti.actions')}<ChevronDown size={14} />
    </Button>
    {open && <div id={panelId} className="absolute right-0 top-full z-50 mt-1 flex min-w-56 flex-col gap-1 rounded-lg border border-[var(--line-strong)] bg-[var(--panel)] p-1.5 shadow-xl animate-fade-in" onClick={event => {
      if ((event.target as HTMLElement).closest('button:not(:disabled)')) {
        setOpen(false)
        root.current?.querySelector('button')?.focus()
      }
    }}>{children}</div>}
  </div>
}


export function OpenCtiToolbar({ slug, iocs, selectedIds, mode = 'full', actionScope = 'selection', leadingAction, trailingAction }: {
  slug: string; iocs: Ioc[]; selectedIds: number[]
  mode?: 'full' | 'activity'; actionScope?: 'case' | 'selection'
  leadingAction?: ReactNode; trailingAction?: ReactNode
}) {
  const tr = useT()
  const qc = useQueryClient()
  const settings = useOpenCtiSettings()
  const [preview, setPreview] = useState<OpenCtiPreview | null>(null)
  const ids = iocs.filter(ioc => transferableIoc(ioc.type) && (actionScope === 'case' || selectedIds.includes(ioc.id))).map(ioc => ioc.id)
  const prepare = useMutation({ mutationFn: () => post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, { ioc_ids: ids }), onSuccess: setPreview })
  const queued = () => { setPreview(null); void qc.invalidateQueries({ queryKey: openCtiKey(slug) }); void qc.invalidateQueries({ queryKey: ['jobs', slug] }) }
  return <div className="flex flex-wrap items-center gap-2">
    {leadingAction}
    {settings.data?.configured && (mode === 'activity'
      ? <OpenCtiActivity slug={slug} allowRetry />
      : <Button disabled={prepare.isPending || (actionScope !== 'case' && !ids.length)} onClick={() => prepare.mutate()}><Send size={14} />{tr('cti.transfer')}</Button>)}
    {trailingAction}
    <CtiError error={prepare.error} />
    {preview && <OpenCtiExportDialog slug={slug} initial={preview} initialOptions={{ ...initialExportOptions(), ioc_ids: ids }} onClose={() => setPreview(null)} onQueued={queued} />}
  </div>
}
