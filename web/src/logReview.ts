import { useQuery } from '@tanstack/react-query'
import { api } from './api'
import type { LogContext, LogEvent } from './logApi'

export function useLogContext(slug: string, event: LogEvent) {
  return useQuery({
    queryKey: ['log-context', slug, event.id, event.fingerprint],
    queryFn: () => api<LogContext>(`/api/cases/${slug}/log-events/${encodeURIComponent(event.id)}/context?fingerprint=${encodeURIComponent(event.fingerprint)}`),
  })
}
export function logEventTime(event: LogEvent) {
  return event.epoch == null ? event.raw_time : new Date(event.epoch * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC')
}
export function logReviewReason(event: LogEvent) {
  if (event.family === 'ftp') return `logReview.reason.ftp.${['success', 'failed', 'incomplete'].includes(event.outcome) ? event.outcome : 'unknown'}`
  if (event.family === 'malware') return event.detection ? 'logReview.reason.detection' : 'logReview.reason.scan'
  return event.family === 'error' ? 'logReview.reason.error' : 'logReview.reason.text'
}
export function logSourceLink(slug: string, event: LogEvent) {
  const url = new URL(location.href)
  url.search = new URLSearchParams({ case: slug, view: 'logs', section: event.family, event: event.id }).toString()
  return url.toString()
}
