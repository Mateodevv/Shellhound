import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, post, type CaseInfo } from '../../api'
import { useT } from '../../i18n'
import type { OpenCtiOptions, OpenCtiPreview } from '../../opencti'
import { Button, Modal } from '../ui/ui'
import { CaseProfileButton, CtiError } from '../casework/CaseProfile'
import { IocTag } from '../iocs/IocTags'
import { OpenCtiReceipt } from './OpenCtiReceipt'

export function OpenCtiExportDialog({ slug, initial, initialOptions, onClose, onQueued, caseInfo, embedded = false, onSkipTransfer }: {
  slug: string; initial: OpenCtiPreview; initialOptions: OpenCtiOptions; onClose: () => void; onQueued: (result: { job_id: number; export_id?: string }) => void
  caseInfo?: CaseInfo; embedded?: boolean; onSkipTransfer?: () => void
}) {
  const tr = useT()
  const context = useQuery({ queryKey: ['case', slug], queryFn: () => api<CaseInfo>(`/api/cases/${slug}`) })
  const info = context.data ?? caseInfo
  const [ids, setIds] = useState(initialOptions.ioc_ids ?? initial.iocs.map(ioc => ioc.id))
  const [preview, setPreview] = useState(initial)
  const profile = preview.profile
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
  const groups = [
    { label: tr('hunt.flow.ipAddresses'), types: ['ip'] },
    { label: tr('iocWorkspace.group.CVEs'), types: ['vulnerability'] },
    { label: tr('iocWorkspace.group.Hashes'), types: ['hash', 'file'] },
  ].map(group => ({ ...group, iocs: preview.iocs.filter(ioc => group.types.includes(ioc.type)) })).filter(group => group.iocs.length)
  const content = <div className="flex h-full min-h-0 flex-col gap-4 text-[13px]">
    <div className="min-h-0 flex-1 space-y-4 overflow-auto">
      <section aria-label={tr('cti.profile')} className="space-y-4 rounded-lg border border-[var(--line)] p-4">
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-[var(--line)] pb-4">
          <div className="min-w-0 space-y-1"><h2 className="break-words text-xl font-semibold leading-tight">{profile?.organization_name || tr('cti.profile')}</h2><p className="font-mono text-[12px] text-[var(--muted)]">{preview.case_reference}</p></div>
          <CaseProfileButton slug={slug} />
        </header>
        {profile?.summary && <div className="space-y-2"><h3 className="text-[12px] font-semibold uppercase tracking-wide text-[var(--muted)]">{tr('cti.summary')}</h3><p className="max-w-prose whitespace-pre-wrap break-words text-[14px] leading-relaxed">{profile.summary}</p></div>}
        <dl className="grid gap-x-6 gap-y-4 border-t border-[var(--line)] pt-4 sm:grid-cols-2">
          {[[tr('cti.sectors'), [...(profile?.sectors ?? []), ...(profile?.subsectors ?? []).map(item => item.name)].join(', ')],
            [tr('cti.location'), [profile?.city, profile?.state, ...(profile?.countries ?? [])].filter(Boolean).join(', ')],
            [tr('cti.period'), [profile?.first_seen, profile?.last_seen].filter(Boolean).join(' – ')],
            [tr('cti.marking'), profile?.marking]].map(([label, value]) => <div key={label} className="space-y-1"><dt className="text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">{label}</dt><dd className="whitespace-pre-wrap break-words text-[13px] leading-relaxed">{value || '—'}</dd></div>)}
        </dl>
      </section>
      {preview.redacted && <p role="status" className="text-[var(--review-text)]">{tr('cti.redacted')}</p>}
      {preview.already_exported && <div role="status" className="space-y-1 rounded-lg border border-[var(--line)] p-3"><p>{tr('cti.alreadyExported')}</p><OpenCtiReceipt counts={preview.counts} caseUrl={preview.already_exported.case_url} /></div>}
      <table className="ioc-relationships w-full text-left text-[12px]"><thead><tr><th scope="col" className="w-16">{tr('cti.exportSelect')}</th><th scope="col">{tr('iocTable.object')}</th><th scope="col">{tr('iocTags.title')}</th></tr></thead>
        {groups.map(group => <tbody key={group.label} aria-label={group.label}>
          <tr><th scope="rowgroup" colSpan={3}><span className="text-[13px] font-semibold text-[var(--fg)]">{group.label}</span><span className="ml-2 text-[11px] text-[var(--muted)]">{group.iocs.length}</span></th></tr>
          {group.iocs.map(ioc => <tr key={ioc.id}>
          <td><input type="checkbox" aria-label={tr('cti.selectIoc', { value: ioc.value })} disabled={transfer.isPending} checked={ids.includes(ioc.id)} onChange={event => setIds(current => event.target.checked ? [...current, ioc.id] : current.filter(id => id !== ioc.id))} /></td>
          <td className="break-all">{ioc.value}{ioc.warnings.map(warning => <p key={warning}>{warning}</p>)}</td><td><div className="flex flex-wrap gap-1">{ioc.tags.map(tag => <IocTag key={tag} value={tag} />)}</div></td>
        </tr>)}</tbody>)}
      </table>
      {!preview.iocs.length && <p>{tr('cti.profileOnly')}</p>}
      {preview.errors.map(message => <CtiError key={message} error={message} />)}
      {preview.warnings.map(message => <p key={message} className="text-[var(--review-text)]">{message}</p>)}
    </div>
    <CtiError error={error || context.error || transfer.error} />
    <p className="break-all text-[12px] text-[var(--muted)]">{tr('cti.destination')}: {preview.target?.url || '—'} · {profile?.marking || '—'}<br />{tr('cti.collection')}: {preview.target?.ingester_id || '—'}</p>
    <div className="flex flex-wrap items-center justify-end gap-2 border-t border-[var(--line)] pt-3">
      {dirty && !error && <p role="status" className="mr-auto">{tr('cti.previewUpdating')}</p>}
      {Boolean(error) && <Button onClick={() => setRetry(value => value + 1)}>{tr('common.retry')}</Button>}
      {!embedded && <Button disabled={transfer.isPending} onClick={onClose}>{tr('common.cancel')}</Button>}
      {onSkipTransfer && <Button disabled={transfer.isPending} onClick={onSkipTransfer}>{tr('closeWizard.skip')}</Button>}
      <Button variant="primary" disabled={dirty || context.isPending || context.isError || transfer.isPending || !!preview.errors.length || !preview.case_reference || !!preview.already_exported} onClick={() => transfer.mutate()}>{tr('cti.confirmTransfer')}</Button>
    </div>
  </div>
  return embedded ? content : <Modal open title={tr('cti.preview')} onClose={() => { if (!transfer.isPending) onClose() }} contained bodyClassName="overflow-hidden px-5 py-4">{content}</Modal>
}
