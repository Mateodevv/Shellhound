import { useQuery } from '@tanstack/react-query'
import { api, type CaseDetail } from '../api'
import { useT } from '../i18n'
import { CtiError } from '../components/CaseProfile'
import { ReportTransfer } from '../components/ReportTransfer'
import type { Navigate } from '../App'

export function Report({ slug, onClosed, gotoView }: { slug: string; onClosed?: () => void; gotoView: Navigate }) {
  const tr = useT()
  const { data: caseInfo, error, isPending } = useQuery({
    queryKey: ['case', slug], queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  return <div className="flex flex-col gap-6">
    <CtiError error={error} />
    {isPending && <p role="status">{tr('common.loading')}</p>}
    {caseInfo && <ReportTransfer key={slug} slug={slug} caseInfo={caseInfo} onClosed={onClosed} onExit={() => gotoView('dashboard')} />}
  </div>
}
