import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, post, type Job } from '../../api'
import { useT } from '../../i18n'
import { Button, Modal, ProgressBar } from '../ui/ui'

export function TestcaseDialog({ onClose, onOpen }: { onClose: () => void; onOpen: (slug: string) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [size, setSize] = useState('small')
  const [analyse, setAnalyse] = useState(true)
  const generate = useMutation({
    mutationFn: () => post<{ slug: string; job_id: number }>('/api/testcase/jobs', { size, run_analysis: analyse }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['state'] }) },
  })
  const slug = generate.data?.slug
  const jobs = useQuery({ queryKey: ['jobs', slug], enabled: !!slug,
    queryFn: () => api<Job[]>(`/api/cases/${slug}/jobs`), refetchInterval: 1000 })
  const active = (jobs.data ?? []).filter(job => ['queued', 'running'].includes(job.state))
  const cancel = useMutation({ mutationFn: async () => {
    // Stop generation first; if it handed off, also cancel newly queued engines.
    await post(`/api/cases/${slug}/jobs/${generate.data!.job_id}/cancel`, {})
    const current = await api<Job[]>(`/api/cases/${slug}/jobs`)
    await Promise.all(current.filter(job => ['queued', 'running'].includes(job.state))
      .map(job => post(`/api/cases/${slug}/jobs/${job.id}/cancel`, {})))
  }, onSuccess: () => { void qc.invalidateQueries({ queryKey: ['jobs', slug] }) } })
  const error = generate.error ?? jobs.error ?? cancel.error
  return <Modal open onClose={onClose} title={tr('start.generateTestcase')} maxWidth={560}>
    {!slug ? <div className="space-y-4">
      <label className="block">{tr('testcase.size')}
        <select className="mt-1 w-full rounded border border-[var(--line)] bg-[var(--panel-2)] p-2" value={size} disabled={generate.isPending} onChange={e => setSize(e.target.value)}>
          <option value="small">{tr('testcase.small')}</option><option value="large">{tr('testcase.large')}</option>
        </select>
      </label>
      <p>{tr(`testcase.${size}Counts`)}</p>
      <p className="text-sm text-[var(--muted)]">{tr(`testcase.${size}Disk`)}</p>
      <label className="flex items-center gap-2"><input type="checkbox" checked={analyse} disabled={generate.isPending} onChange={e => setAnalyse(e.target.checked)} />{tr('testcase.analyse')}</label>
      <p className="text-sm text-[var(--muted)]">{tr('testcase.local')}</p>
      <Button variant="primary" disabled={generate.isPending} onClick={() => generate.mutate()}>{tr('testcase.generate')}</Button>
    </div> : <div className="space-y-4">
      <p>{tr('testcase.background')}</p>
      {!jobs.data && <p>{tr('common.loading')}</p>}
      {jobs.data?.map(job => <div key={job.id}>
        <div className="flex justify-between gap-2 text-sm"><span>{tr(`job.${job.kind}`)}</span><span>{job.state}</span></div>
        <p className="break-words text-sm text-[var(--muted)]">{job.message}</p>
        <ProgressBar value={job.progress} label={tr(`job.${job.kind}`)} />
        {job.error && <p role="alert" className="break-words text-sm text-[var(--danger-text)]">{job.error}</p>}
      </div>)}
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onClick={() => { onOpen(slug); onClose() }}>{tr('testcase.open')}</Button>
        {active.length > 0 && <Button disabled={cancel.isPending} onClick={() => cancel.mutate()}>{tr('common.cancel')}</Button>}
      </div>
    </div>}
    {error && <p role="alert" className="mt-3 text-sm text-[var(--danger-text)]">{error.message}</p>}
  </Modal>
}
