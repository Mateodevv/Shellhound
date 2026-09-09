// Historical provider results are read locally; external enrichment lives in OpenCTI.
import { useQuery } from '@tanstack/react-query'
import { ExternalLink, ShieldQuestion } from 'lucide-react'
import clsx from 'clsx'
import { api, type Enrichment, type Ioc } from '../api'
import { useT } from '../i18n'
import { relativeTime } from '../format'
import { useOpenCti, safeCtiUrl } from '../opencti'
import { OpenCtiDetails } from './OpenCti'
import { CtiError } from './CaseProfile'
import { Tag } from './ui'
import { Tooltip } from './Tooltip'

export function EnrichPanel({ slug, kind, value }: {
  slug: string; kind: string; value: string; prominent?: boolean
}) {
  const tr = useT()
  const history = useQuery({ queryKey: ['enrichment', slug], queryFn: () => api<Enrichment[] | { entries: Enrichment[] }>(`/api/cases/${slug}/enrichment`) })
  const iocs = useQuery({ queryKey: ['iocs', slug], queryFn: () => api<Ioc[]>(`/api/cases/${slug}/iocs`) })
  const cti = useOpenCti(slug)
  const ioc = Array.isArray(iocs.data) ? iocs.data.find((entry) => entry.type === kind && entry.value === value) : undefined
  const entries = Array.isArray(history.data) ? history.data : history.data?.entries ?? []
  const results = entries.filter((entry) => entry.kind === kind && entry.value === value)
  const href = new URL(location.href)
  href.searchParams.set('case', slug)
  href.searchParams.set('view', 'iocbox')
  return <div className="flex flex-col gap-3">
    <p className="text-[12px] text-[var(--muted)]">{tr(cti.configured ? 'cti.historyHint' : 'cti.localHistoryHint')}</p>
    <a href={href.toString()} className="text-[12px] text-[var(--accent-text)] hover:underline">{tr('cti.toBox')}</a>
    <CtiError error={history.error || cti.error} />
    {cti.configured && ioc && <OpenCtiDetails lookup={cti.data?.lookups?.find((entry) => entry.ioc_id === ioc.id)} />}
    {!!results.length && <div className="flex flex-col gap-2"><h4 className="text-[12px] font-semibold">{tr('cti.history')}</h4>{results.map((entry) => <EnrichCard key={`${entry.service}:${entry.fetched}`} entry={entry} />)}</div>}
  </div>
}

/** The answer itself. Framed as a quotation, not as a result: the border and
 *  the "third party" line are there so nobody reads it as something this
 *  case measured. */
export function EnrichCard({ entry }: { entry: Enrichment }) {
  const tr = useT()
  const r = entry.result
  const score = r.score ?? 0
  const of = r.of ?? 0
  // Colour follows the number, but stays one step short of the severity
  // palette -- this is not a finding and must not look like one.
  const tone = score > 0 ? 'text-[var(--sev-low)]' : 'text-[var(--muted)]'

  return (
    <div className="rounded-lg border border-dashed border-[var(--line)] bg-[var(--panel-2)] px-3 py-2">
      <div className="mb-1 flex items-center gap-2 text-[10px] uppercase tracking-wider text-[var(--muted)]">
        <ShieldQuestion size={11} />
        {tr('enrich.foreign', { service: tr(`enrich.${entry.service}`) })}
      </div>

      {!r.known ? (
        <div className="text-[12.5px] text-[var(--muted)]">
          {tr('enrich.unknown')}
        </div>
      ) : (
        <div className="flex flex-col gap-1">
          <div className="flex items-baseline gap-1.5">
            <span className={clsx('text-[17px] font-bold leading-none tabular', tone)}>
              {score}
            </span>
            <span className="text-[12.5px] text-[var(--muted)]">
              {entry.service === 'virustotal'
                ? tr('enrich.vt.of', { n: of })
                : tr('enrich.ab.of')}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-[11.5px] text-[var(--muted)]">
            {r.label && <Tag>{r.label}</Tag>}
            {r.tor && <Tag tone="warn">Tor</Tag>}
            {r.isp && <span className="truncate">{r.isp}</span>}
            {r.usage && <span className="truncate">· {r.usage}</span>}
            {r.reports != null && r.reports > 0 && (
              <span>· {tr('enrich.ab.reports', {
                n: r.reports, users: r.distinct_reporters ?? 0,
              })}</span>
            )}
          </div>
          {!!r.names?.length && (
            <div className="mono truncate text-[11px] text-[var(--muted)]"
              title={r.names.join(', ')}>
              {r.names.join(', ')}
            </div>
          )}
        </div>
      )}

      <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-[var(--muted)]">
        <Tooltip hint={tr('enrich.fetched.hint')}>
          <span>{tr('enrich.fetched')} {relativeTime(entry.fetched)}</span>
        </Tooltip>
        {safeCtiUrl(r.permalink) && (
          <a href={safeCtiUrl(r.permalink)} target="_blank" rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-[var(--accent-text)] hover:underline">
            <ExternalLink size={11} /> {tr('enrich.open')}
          </a>
        )}
      </div>
    </div>
  )
}
