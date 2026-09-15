import { ArrowDownToLine, ArrowUpFromLine, FileText, ScanLine, TriangleAlert } from 'lucide-react'
import type { LogContext, LogEvent } from '../../logApi'
import { formatBytes } from '../../format'
import { useT } from '../../i18n'
import { logEventTime, logReviewReason, logSourceLink, useLogContext } from '../../logReview'
import { Button, CopyButton, Tag } from '../ui/ui'
import { IocTypeBadge } from '../iocs/IocTypeBadge'

export function LogEventFacts({ event, sourcePath, compact = false }: { event: LogEvent; sourcePath?: string; compact?: boolean }) {
  const tr = useT()
  const facts = [
    [tr('logEvidence.time'), logEventTime(event) || tr('logEvidence.undated')],
    [tr('logEvidence.operation'), tr(`logEvidence.operation.${event.operation}`)],
    [tr('logEvidence.outcome'), tr(`logEvidence.outcome.${event.outcome || 'unknown'}`)],
    ...(event.ip || event.remote_host ? [[tr('logEvidence.remote'), event.ip || event.remote_host]] : []),
    ...(event.account ? [[tr('logEvidence.account'), event.account]] : []),
    ...(event.bytes != null ? [[tr('logReview.transferred'), formatBytes(event.bytes)]] : []),
    ...(event.signature ? [[tr('logReview.signature'), event.signature]] : []),
    ...(event.path ? [[tr('logEvidence.path'), event.path]] : []),
  ]
  return <div className="min-w-0 text-[12px]">
    <div className="flex flex-wrap items-center gap-2"><Tag tone="accent">{tr(`logEvidence.family.${event.family}`)}</Tag><span className="min-w-0 break-all text-[var(--muted)]">{event.source_name}:{event.line}{event.line_end !== event.line && `–${event.line_end}`}</span><CopyButton value={`${event.source_name}:${event.line}`} label={tr('logEvidence.copyReference')} /></div>
    <dl className={compact ? 'mt-2 grid gap-x-4 sm:grid-cols-2' : 'mt-3'}>{facts.map(([label, value]) => <div key={label} className="min-w-0 border-b border-[var(--line-soft)] py-2"><dt className="text-[11px] text-[var(--muted)]">{label}</dt><dd className="mt-1 break-all">{value}</dd></div>)}</dl>
    {event.epoch == null && event.raw_time && <p className="mt-2 text-[var(--review-text)]">{tr('logEvidence.unknownZone')}</p>}
    {event.raw_time && event.epoch != null && <p className="mt-2 break-all text-[11px] text-[var(--muted)]">{tr('logEvidence.originalTime', { value: event.raw_time })}</p>}
    {!!event.clock_correction && <p className="mt-2 text-[11px] text-[var(--muted)]">{tr('logEvidence.clockCorrection', { n: event.clock_correction })}</p>}
    {sourcePath && <div className="mt-4"><p className="text-[11px] font-semibold uppercase text-[var(--muted)]">{tr('logEvidence.source')}</p><p className="mono mt-1 break-all text-[11px] text-[var(--muted)]">{sourcePath}</p></div>}
  </div>
}

export function LogEventEvidence({ event, context, error, loading, onFile }: {
  event: LogEvent; context?: LogContext; error?: Error | null; loading?: boolean; onFile?: () => void
}) {
  const tr = useT()
  const current = !error ? context?.event : undefined
  const available = !!current?.artifact_available && !!current.artifact
  const Icon = event.family === 'ftp' ? (event.operation === 'download' ? ArrowDownToLine : ArrowUpFromLine)
    : event.family === 'malware' ? ScanLine : event.family === 'error' ? TriangleAlert : FileText
  const section = event.family === 'ftp' ? 'transfer' : event.family === 'error' ? 'error' : event.family === 'malware' ? 'scanner' : 'text'
  return <section className="min-w-0 space-y-4 text-[12px]">
    <div className="rounded-lg border-l-2 border-[var(--review-text)] bg-[var(--panel-2)] px-3 py-2.5">
      <p className="font-semibold">{tr(logReviewReason(event))}</p>
      <p className="mt-1 text-[var(--muted)]">{tr(`logReview.help.${section}`)}</p>
    </div>
    <div>
      <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wide text-[var(--muted)]">{tr(`logReview.section.${section}`)}</h3>
      <div className="flex items-start gap-3 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-3">
        <Icon size={18} className="mt-0.5 shrink-0 text-[var(--accent)]" />
        <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center justify-between gap-2"><strong>{tr(`logEvidence.operation.${event.operation}`)}</strong><Tag tone={event.triage === 'confirmed' ? 'danger' : event.detection || event.outcome === 'failed' || event.outcome === 'error' ? 'warn' : undefined}>{tr(`logEvidence.outcome.${event.outcome || 'unknown'}`)}</Tag></div>
          <p className="mt-1 break-all text-[var(--muted)]">{event.path || event.signature || `${event.source_name}:${event.line}`}</p>
          {event.signature && <p className="mt-1 break-all">{event.signature}</p>}
          <p className="mt-2 text-[11px] text-[var(--muted)]">{logEventTime(event) || tr('logEvidence.undated')} · {tr('logReview.sourceLines', { from: event.line, to: event.line_end })}</p>
        </div>
      </div>
    </div>
    {available && onFile && <div className="border-t border-[var(--line)] pt-3"><h3 className="mb-2 text-[11px] font-semibold uppercase text-[var(--muted)]">{tr('logReview.linkedEvidence')}</h3><div className="flex flex-wrap items-center gap-2"><IocTypeBadge type="file" /><span className="mono min-w-0 flex-1 break-all">{current.artifact.replace(/\\/g, '/').split('/').pop()}</span><Button variant="special" onClick={onFile}><FileText size={13} />{tr('review.openFile')}</Button></div><p className="mt-1 text-[11px] text-[var(--muted)]">{tr('logReview.verifiedFile')}</p></div>}
    {event.path && !available && !loading && <p role="status" className="text-[var(--muted)]">{tr('logEvidence.unmatchedPath')}</p>}
    {loading && <p role="status">{tr('common.loading')}</p>}
    {error && <div><p role="alert" className="text-[var(--review-text)]">{error.message}</p><p className="mt-2 text-[var(--muted)]">{tr('logEvidence.savedExcerpt')}</p><pre className="mono mt-2 whitespace-pre-wrap break-all rounded-lg bg-[var(--code-bg)] p-3 text-[11px]">{event.raw}</pre></div>}
    {!error && context && <details key={event.id} open={event.family === 'error' || event.family === 'text'} className="border-t border-[var(--line)] pt-3"><summary className="cursor-pointer text-[12px] text-[var(--muted)]">{tr('logReview.original')} · {event.source_name}:{event.line}</summary><div data-artifact-scroll="primary" tabIndex={0} role="region" aria-label={tr('logReview.original')} className="mono mt-2 max-h-80 overflow-auto rounded-lg bg-[var(--code-bg)] py-2 text-[11px] leading-relaxed">{context.lines.map(line => <div key={line.line} data-log-selected={line.selected || undefined} className={`flex gap-3 px-3 ${line.selected ? 'bg-[var(--review-soft)]' : ''}`}><span className="w-8 shrink-0 select-none text-right text-[var(--muted)]">{line.line}</span><pre className="min-w-0 whitespace-pre-wrap break-all">{line.text}</pre></div>)}</div></details>}
  </section>
}

export function LogEntryContext({ slug, event, onFile }: { slug: string; event: LogEvent; onFile?: (path: string, line: number | null) => void }) {
  const tr = useT()
  const query = useLogContext(slug, event)
  const shown = !query.isError && query.data ? query.data.event : event
  return <div className="space-y-4"><LogEventFacts event={shown} sourcePath={query.data?.source_path} compact /><LogEventEvidence event={shown} context={query.data} loading={query.isPending} error={query.error} onFile={onFile && query.data?.event.artifact_available ? () => onFile(query.data!.event.artifact, null) : undefined} /><a className="inline-block text-[12px] text-[var(--accent)] underline underline-offset-4" href={logSourceLink(slug, event)}>{tr('logEvidence.openLogs')}</a></div>
}
