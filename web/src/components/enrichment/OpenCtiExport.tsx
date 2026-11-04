import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, post, type CaseInfo } from '../../api'
import { useT } from '../../i18n'
import type { OpenCtiOptions, OpenCtiPreview } from '../../opencti'
import { Button, Modal, Tag } from '../ui/ui'
import { CaseProfileButton, CtiError } from '../casework/CaseProfile'
import { IocTag } from '../iocs/IocTags'

export function OpenCtiExportDialog({ slug, initial, initialOptions, onClose, onQueued, caseInfo, embedded = false, onSkipTransfer }: {
  slug: string; initial: OpenCtiPreview; initialOptions: OpenCtiOptions; onClose: () => void; onQueued: (result: { job_id: number; export_id?: string }) => void
  caseInfo?: CaseInfo; embedded?: boolean; onSkipTransfer?: () => void
}) {
  const tr = useT()
  const context = useQuery({ queryKey: ['case', slug], queryFn: () => api<CaseInfo>(`/api/cases/${slug}`) })
  const info = context.data ?? caseInfo
  const profile = info?.profile
  const [ids, setIds] = useState(initialOptions.ioc_ids ?? initial.iocs.map(ioc => ioc.id))
  const [preview, setPreview] = useState(initial)
  const [reviewed, setReviewed] = useState(JSON.stringify([ids, info?.profile_revision]))
  const key = JSON.stringify([ids, info?.profile_revision])
  const [error, setError] = useState<unknown>(null)
  const [retry, setRetry] = useState(0)
  const dirty = key !== reviewed
  useEffect(() => {
    if (!dirty) return
    let current = true
    setError(null)
    void post<OpenCtiPreview>(`/api/cases/${slug}/opencti/preview`, { ioc_ids: ids }).then(data => {
      if (current) { setPreview(data); setReviewed(key) }
    }).catch(failure => { if (current) setError(failure) })
    return () => { current = false }
  }, [dirty, key, retry, slug, ids])
  const transfer = useMutation({ mutationFn: () => post<{ job_id: number; export_id?: string }>(`/api/cases/${slug}/opencti/export`, { preview_id: preview.preview_id }), onSuccess: result => onQueued(result) })
  const content = <div className="flex h-full min-h-0 flex-col gap-4 text-[13px]">
    <div className="flex flex-wrap items-center justify-between gap-2"><Tag>{preview.case_reference || tr('cti.caseId')}</Tag><CaseProfileButton slug={slug} /></div>
    <p className="text-[var(--muted)]">{tr('cti.exportOnlyHint')}</p>
    <div className="min-h-0 flex-1 space-y-4 overflow-auto">
      <dl className="grid gap-3 rounded-lg border border-[var(--line)] p-3 sm:grid-cols-2">
        {[[tr('cti.organizationName'), profile?.organization_name || profile?.pseudonym], [tr('cti.sectors'), profile?.sectors.join(', ')],
          [tr('cti.subsectors'), profile?.subsectors?.map(item => `${item.sector}: ${item.name}`).join(', ')], [tr('cti.country'), profile?.countries.join(', ')],
          [tr('cti.state'), profile?.state], [tr('cti.city'), profile?.city], [tr('cti.firstSeen'), profile?.first_seen], [tr('cti.lastSeen'), profile?.last_seen],
          [tr('cti.marking'), profile?.marking], [tr('cti.summary'), profile?.summary],
          [tr('cti.profileSoftware'), profile?.software.map(item => `${item.name} ${item.version}`.trim()).join(', ')],
          [tr('cti.profileCves'), profile?.vulnerabilities.map(item => `${item.name} (${item.status})`).join(', ')]].map(([label, value]) => <div key={label}><dt className="text-[12px] text-[var(--muted)]">{label}</dt><dd className="whitespace-pre-wrap break-words">{value || '—'}</dd></div>)}
      </dl>
      <table className="ioc-relationships w-full text-left text-[12px]"><thead><tr><th>{tr('cti.exportSelect')}</th><th>{tr('iocTable.object')}</th><th>{tr('iocTable.type')}</th><th>{tr('iocTags.title')}</th></tr></thead>
        <tbody>{initial.iocs.map(ioc => <tr key={ioc.id}>
          <td><input type="checkbox" aria-label={tr('cti.selectIoc', { value: ioc.value })} disabled={transfer.isPending} checked={ids.includes(ioc.id)} onChange={event => setIds(current => event.target.checked ? [...current, ioc.id] : current.filter(id => id !== ioc.id))} /></td>
          <td className="break-all">{ioc.value}{ioc.warnings.map(warning => <p key={warning}>{warning}</p>)}</td><td>{ioc.type}</td><td><div className="flex flex-wrap gap-1">{ioc.tags.map(tag => <IocTag key={tag} value={tag} />)}</div></td>
        </tr>)}</tbody>
      </table>
      {!initial.iocs.length && <p>{tr('cti.profileOnly')}</p>}
      {preview.errors.map(message => <CtiError key={message} error={message} />)}
      {preview.warnings.map(message => <p key={message} className="text-[var(--review-text)]">{message}</p>)}
    </div>
    <CtiError error={error || context.error || transfer.error} />
    <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[var(--line)] pt-3">
      {dirty && !error && <p role="status" className="mr-auto">{tr('cti.previewUpdating')}</p>}
      {Boolean(error) && <Button onClick={() => setRetry(value => value + 1)}>{tr('common.retry')}</Button>}
      {!embedded && <Button disabled={transfer.isPending} onClick={onClose}>{tr('common.cancel')}</Button>}
      {onSkipTransfer && <Button disabled={transfer.isPending} onClick={onSkipTransfer}>{tr('closeWizard.skip')}</Button>}
      <Button variant="primary" disabled={dirty || context.isPending || transfer.isPending || !!preview.errors.length || !preview.case_reference} onClick={() => transfer.mutate()}>{tr('cti.confirmTransfer')}</Button>
    </div>
  </div>
  return embedded ? content : <Modal open title={tr('cti.preview')} onClose={() => { if (!transfer.isPending) onClose() }} contained bodyClassName="overflow-hidden px-5 py-4">{content}</Modal>
}
