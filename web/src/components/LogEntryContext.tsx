import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { LogContext, LogEvent } from '../logApi'
import { useT } from '../i18n'
import { Button, Tag } from './ui'
const eventTime = (event: LogEvent) => event.epoch == null ? event.raw_time : new Date(event.epoch * 1000).toISOString().replace('T', ' ').replace('.000Z', ' UTC')

export function LogEntryContext({ slug, event, onFile }: { slug: string; event: LogEvent; onFile?: (path: string, line: number | null) => void }) {
  const tr = useT()
  const query = useQuery({ queryKey: ['log-context', slug, event.id, event.fingerprint], queryFn: () => api<LogContext>(`/api/cases/${slug}/log-events/${event.id}/context?fingerprint=${event.fingerprint}`) })
  const current = query.data?.event
  const shown = current ?? event
  const link = new URL(location.href)
  link.searchParams.set('view', 'logs'); link.searchParams.set('section', event.family); link.searchParams.set('event', event.id)
  link.searchParams.delete('artifact')
  return <div className="space-y-3 text-sm">
    <div className="flex flex-wrap items-center gap-2"><Tag>{tr(`logEvidence.family.${event.family}`)}</Tag><span className="text-xs text-[var(--muted)]">{event.source_name}:{event.line}{event.line_end !== event.line && `–${event.line_end}`}</span></div>
    {query.data?.source_path && <p className="mono break-all text-xs text-[var(--muted)]">{query.data.source_path}</p>}
    <dl className="grid gap-3 sm:grid-cols-2">
      <div><dt className="text-xs text-[var(--muted)]">{tr('logEvidence.time')}</dt><dd>{eventTime(shown) || tr('logEvidence.undated')}</dd>{shown.epoch == null && shown.raw_time && <p className="text-xs text-[var(--review-text)]">{tr('logEvidence.unknownZone')}</p>}</div>
      <div><dt className="text-xs text-[var(--muted)]">{tr('logEvidence.operation')}</dt><dd>{tr(`logEvidence.operation.${event.operation}`)} · {tr(`logEvidence.outcome.${event.outcome || 'unknown'}`)}</dd></div>
      {(event.ip || event.remote_host) && <div><dt className="text-xs text-[var(--muted)]">{tr('logEvidence.remote')}</dt><dd className="mono break-all">{event.ip || event.remote_host}</dd></div>}
      {event.path && <div><dt className="text-xs text-[var(--muted)]">{tr('logEvidence.path')}</dt><dd className="mono break-all">{event.path}</dd></div>}
    </dl>
    {event.raw_time && event.epoch != null && <p className="text-xs text-[var(--muted)]">{tr('logEvidence.originalTime', { value: event.raw_time })}</p>}
    {!!current?.clock_correction && <p className="text-xs text-[var(--muted)]">{tr('logEvidence.clockCorrection', { n: current.clock_correction })}</p>}
    <p className="text-xs text-[var(--muted)]">{tr('logEvidence.observationHelp')}</p>
    {query.isPending && <p role="status">{tr('common.loading')}</p>}
    {query.error && <><p role="alert" className="text-[var(--review-text)]">{query.error.message}</p><p className="text-xs">{tr('logEvidence.savedExcerpt')}</p><pre className="overflow-auto whitespace-pre-wrap break-all rounded-lg bg-[var(--panel-2)] p-3 text-xs">{event.raw}</pre></>}
    {query.data && <div className="max-h-96 overflow-auto rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3 font-mono text-xs">{query.data.lines.map(line => <div key={line.line} className={`flex gap-3 ${line.selected ? 'bg-[var(--review-soft)]' : ''}`}><span className="w-10 shrink-0 select-none text-right text-[var(--muted)]">{line.line}</span><pre className="min-w-0 whitespace-pre-wrap break-all">{line.text}</pre></div>)}</div>}
    <div className="flex flex-wrap gap-2">{current?.artifact_available && onFile && <Button onClick={() => onFile(current.artifact, null)}>{tr('review.openFile')}</Button>}
      <a className="text-xs text-[var(--accent)] underline underline-offset-4" href={link.toString()}>{tr('logEvidence.openLogs')}</a></div>
    {event.path && !current?.artifact_available && <p className="text-xs text-[var(--muted)]">{tr('logEvidence.unmatchedPath')}</p>}
  </div>
}
