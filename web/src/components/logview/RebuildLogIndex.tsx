import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { RefreshCw } from 'lucide-react'
import { api, post, type Job } from '../../api'
import { useT } from '../../i18n'
import { Button } from '../ui/ui'

export function RebuildLogIndex({ slug, onStarted }: { slug: string; onStarted?: () => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const jobs = useQuery({
    queryKey: ['jobs', slug], queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`),
    refetchInterval: query => query.state.data?.some(job => ['queued', 'running'].includes(job.state)) ? 1000 : false,
  })
  const active = jobs.data?.filter(job => ['queued', 'running'].includes(job.state)) ?? []
  const indexing = active.some(job => job.kind === 'index_logs')
  const rebuild = useMutation({
    mutationFn: async () => {
      await qc.cancelQueries({ predicate: query => query.queryKey[1] === slug
        && typeof query.queryKey[0] === 'string' && query.queryKey[0].startsWith('access-') })
      return post(`/api/cases/${slug}/access/reindex`, {})
    },
    onSuccess: () => {
      onStarted?.()
      qc.invalidateQueries({ queryKey: ['jobs', slug] })
      qc.invalidateQueries({ queryKey: ['case', slug] })
    },
  })
  return <div className="space-y-2">
    <Button disabled={rebuild.isPending || jobs.isPending || !!active.length}
      title={active.length ? tr('logs.index.busy') : undefined} onClick={() => rebuild.mutate()}>
      <RefreshCw size={14} className={indexing ? 'animate-spin' : ''} />
      {tr(indexing ? 'logs.index.rebuilding' : 'logs.index.rebuild')}
    </Button>
    {rebuild.error && <p role="alert" className="text-sm text-[var(--danger-text)]">{rebuild.error.message}</p>}
  </div>
}
