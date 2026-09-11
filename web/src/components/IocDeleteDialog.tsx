import { useMutation, useQueryClient } from '@tanstack/react-query'
import { del, post, type Ioc } from '../api'
import { useT } from '../i18n'
import { ConfirmDialog } from './ui'
import { iocName } from './iocPresentation'

export function IocDeleteDialog({ slug, objects, onClose, onDeleted }: {
  slug: string; objects: Ioc[]; onClose: () => void; onDeleted: (ids: number[]) => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const remove = useMutation({
    mutationFn: () => objects.length === 1
      ? del<{ deleted_ids: number[] }>(`/api/cases/${slug}/iocs/${objects[0].id}`)
      : post<{ deleted_ids: number[] }>(`/api/cases/${slug}/iocs/delete`, { ids: objects.map(i => i.id) }),
    onSuccess: result => {
      onDeleted(result.deleted_ids)
      onClose()
      void qc.invalidateQueries({ queryKey: ['iocs'] })
      void qc.invalidateQueries({ queryKey: ['opencti', slug] })
      void qc.invalidateQueries({ queryKey: ['case', slug] })
      void qc.invalidateQueries({ queryKey: ['dashboard', slug] })
    },
  })
  return <ConfirmDialog open danger pending={remove.isPending}
    onClose={() => { if (!remove.isPending) onClose() }}
    title={tr('iocDelete.title', { n: objects.length })} confirmLabel={tr('iocDelete.confirm')}
    onConfirm={() => remove.mutate()}
    body={<div className="space-y-3">
      <p>{tr('iocDelete.description')}</p>
      <ul className="max-h-48 list-disc overflow-y-auto pl-5">{objects.map(object => <li key={object.id} className="break-all">{iocName(object)}</li>)}</ul>
      {objects.some(object => object.type === 'file') && <p>{tr('iocDelete.hashes')}</p>}
      <p>{tr('iocDelete.remote')}</p>
      {remove.error && <p role="alert" className="text-[var(--danger-text)]">{remove.error.message}</p>}
    </div>} />
}
