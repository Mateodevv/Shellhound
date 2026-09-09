// ws.ts — the live wire: job progress + invalidations pushed by the server.
import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { TOKEN, type Job } from './api'

interface JobEvent { type: 'job'; case_slug?: string; job: Partial<Job> & { id: number } }
interface InvalidateEvent { type: 'invalidate'; scope: string }
type Event = JobEvent | InvalidateEvent

// Which query keys a finished engine invalidates. "Everything relevant"
// beats a stale view; the queries are cheap reads of local SQLite.
const SCOPE_KEYS: Record<string, string[]> = {
  'opencti-lookup': ['iocs', 'opencti', 'jobs'],
  index_logs: ['dashboard', 'actors', 'findings', 'jobs', 'case', 'trace', 'hunt-batches', 'hunt-batch', 'hunt-clients', 'hunt-clusters', 'hunt-request'],
  hunt: ['dashboard', 'hunt-batches', 'hunt-batch', 'hunt-tests', 'jobs'],
  webshell: ['dashboard', 'findings', 'jobs', 'case', 'job-skips'],
  yara: ['dashboard', 'findings', 'jobs', 'case', 'job-skips'],
  cms: ['dashboard', 'cms', 'jobs', 'case'],
  sqldb: ['dashboard', 'database', 'findings', 'jobs', 'case'],
  findings: ['dashboard', 'findings', 'iocs', 'case'],
  iocs: ['iocs', 'dashboard', 'case', 'actors'],
  // a case was closed or imported: the landing view's lists changed
  workspace: ['state', 'archives'],
}

export function useLiveEvents(onJob?: (job: JobEvent['job']) => void) {
  const qc = useQueryClient()
  const onJobRef = useRef(onJob)
  onJobRef.current = onJob

  useEffect(() => {
    let ws: WebSocket | null = null
    let closed = false
    let retry = 1000

    const connect = () => {
      const proto = location.protocol === 'https:' ? 'wss' : 'ws'
      ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(TOKEN)}`)
      ws.onopen = () => { retry = 1000 }
      ws.onmessage = (msg) => {
        let event: Event
        try { event = JSON.parse(msg.data) } catch { return }
        if (event.type === 'job') {
          // Row IDs repeat in every case database. Only a case-scoped event
          // can safely update cached progress; legacy events still refetch.
          if (typeof event.case_slug === 'string' && event.case_slug) {
            qc.setQueryData<Job[]>(['jobs', event.case_slug], (current) => current?.map((job) => {
              if (job.id !== event.job.id) return job
              const finished = ['done', 'failed', 'cancelled'].includes(job.state)
              if (finished && ['running', 'queued'].includes(event.job.state ?? '')) return job
              return { ...job, ...event.job }
            }))
          }
          onJobRef.current?.(event.job)
          if (event.job.kind === 'hunt') {
            for (const key of ['hunt-batches', 'hunt-batch', 'hunt-tests']) {
              qc.invalidateQueries({ queryKey: event.case_slug ? [key, event.case_slug] : [key] })
            }
          }
          if (event.job.state && event.job.state !== 'running') {
            qc.invalidateQueries({ queryKey: ['jobs'] })
            qc.invalidateQueries({ queryKey: ['dashboard'] })
            // Any engine may be the last prerequisite for an evidence
            // receipt, including YARA, SIGMA and error-log correlations.
            qc.invalidateQueries({ queryKey: ['case'] })
            qc.invalidateQueries({ queryKey: ['job-skips'] })
          }
        } else if (event.type === 'invalidate') {
          for (const key of SCOPE_KEYS[event.scope] ?? ['dashboard']) {
            qc.invalidateQueries({ queryKey: [key] })
          }
        }
      }
      ws.onclose = () => {
        if (closed) return
        setTimeout(connect, retry)
        retry = Math.min(retry * 2, 15000)
      }
    }
    connect()
    return () => { closed = true; ws?.close() }
  }, [qc])
}
