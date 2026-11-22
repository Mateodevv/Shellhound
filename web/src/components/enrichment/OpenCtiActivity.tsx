import { useMutation, useQueryClient } from '@tanstack/react-query'
import { post } from '../../api'
import { useT } from '../../i18n'
import { openCtiKey, useOpenCti } from '../../opencti'
import { Button, Tag } from '../ui/ui'
import { CtiError } from '../casework/CaseProfile'
import { OpenCtiReceipt } from './OpenCtiReceipt'

export function OpenCtiActivity({ slug, allowRetry = false }: { slug: string; allowRetry?: boolean }) {
  const tr = useT()
  const qc = useQueryClient()
  const status = useOpenCti(slug)
  const retry = useMutation({ mutationFn: (export_id: string) => post(`/api/cases/${slug}/opencti/retry`, { export_id }), onSuccess: () => { void qc.invalidateQueries({ queryKey: openCtiKey(slug) }); void qc.invalidateQueries({ queryKey: ['jobs', slug] }) } })
  return <section className="w-full space-y-3 text-[12px]" aria-label={tr('cti.exportHistory')}>
    <CtiError error={status.error || retry.error} />
    {(status.data?.exports ?? []).map(entry => <div key={entry.id} className="flex flex-wrap items-center gap-2 rounded-lg border border-[var(--line)] p-3">
      <Tag>{entry.state}</Tag>{entry.state === 'complete' ? <OpenCtiReceipt counts={entry.stats.counts} caseUrl={entry.case_url} /> : <span>{tr('ctiActivity.transfer', { n: Number(entry.stats.objects ?? 0) })}</span>}<span className="ml-auto text-[var(--muted)]">{entry.updated}</span>
      <CtiError error={entry.error} />
      {allowRetry && ['failed', 'partial', 'pending', 'paused'].includes(entry.state) && <Button disabled={retry.isPending} onClick={() => retry.mutate(entry.id)}>{tr('cti.retry')}</Button>}
    </div>)}
    {!status.isPending && !status.data?.exports.length && <p>{tr('cti.noTransfers')}</p>}
  </section>
}
