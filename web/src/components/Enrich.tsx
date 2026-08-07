// Enrich.tsx -- what a third party says about ONE indicator.
//
// A FOREIGN OPINION, and the component is built to keep saying so. It does
// not colour the artifact, it does not sit next to the severity, it carries
// no verdict of its own. It shows a number, what that number is out of, when
// it was fetched, and a link to the source -- so the analyst can weigh it
// instead of inheriting it.
//
// NOTHING HAPPENS WITHOUT A CLICK. There is no lookup on mount, no sweep, no
// background refresh: the request leaves the machine when the analyst asks
// for it, and the button says beforehand what will be sent.
import { useEffect, useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { ExternalLink, RefreshCw, Search, ShieldQuestion } from 'lucide-react'
import clsx from 'clsx'
import { api, post, type Enrichment, type SettingsInfo } from '../api'
import { useT } from '../i18n'
import { relativeTime } from '../format'
import { Button, Tag } from './ui'
import { Tooltip } from './Tooltip'

/** Which service answers for which kind of indicator. The server enforces
 *  this too -- here it only decides which button to offer. */
const SERVICE_FOR: Record<string, string> = { hash: 'virustotal', ip: 'abuseipdb' }

export function EnrichPanel({ slug, kind, value }: {
  slug: string
  /** 'hash' or 'ip' -- anything else offers no lookup. */
  kind: string
  value: string
}) {
  const tr = useT()
  const service = SERVICE_FOR[kind]
  const [result, setResult] = useState<Enrichment | null>(null)
  // THE VERDICT BELONGS TO ONE VALUE. The panel is re-rendered with a new
  // hash or address while staying mounted, and the previous artifact's
  // VirusTotal/AbuseIPDB answer stayed on screen next to it -- a third
  // party's opinion shown against the wrong thing.
  useEffect(() => { setResult(null) }, [kind, value])

  const { data: conf } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api<SettingsInfo>('/api/settings'),
  })
  const lookup = useMutation({
    mutationFn: (refresh: boolean) =>
      post<Enrichment>(`/api/cases/${slug}/enrich`, { service, value, refresh }),
    onSuccess: setResult,
  })

  if (!service || !value) return null
  const ready = conf?.enrichment_ack && conf.services[service]?.configured
  if (!ready) {
    // Deliberately quiet: an unconfigured service is not a problem to be
    // fixed here, and a banner in every artifact window would be noise.
    return (
      <Tooltip hint={tr('enrich.notReady.hint')}>
        <span className="inline-flex items-center gap-1 text-[11px] text-[var(--muted)] opacity-60">
          <ShieldQuestion size={12} /> {tr('enrich.notReady')}
        </span>
      </Tooltip>
    )
  }

  const shown = result
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip
          title={tr(`enrich.${service}`)}
          body={tr('enrich.sends', { what: tr(`settings.kind.${kind}`) })}
          hint={tr('enrich.opinion')}>
          <Button variant="ghost" disabled={lookup.isPending}
            onClick={() => lookup.mutate(false)}>
            <Search size={13} />
            {lookup.isPending ? tr('common.loading')
                              : tr('enrich.ask', { service: tr(`enrich.${service}`) })}
          </Button>
        </Tooltip>
        {shown && (
          <Tooltip hint={tr('enrich.refresh.hint')}>
            <Button variant="ghost" disabled={lookup.isPending}
              onClick={() => lookup.mutate(true)}>
              <RefreshCw size={12} />
            </Button>
          </Tooltip>
        )}
      </div>

      {lookup.isError && (
        <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-1.5 text-[12px] text-[var(--danger-text)]">
          {String((lookup.error as Error)?.message ?? lookup.error)}
        </div>
      )}

      {shown && <EnrichCard entry={shown} />}
    </div>
  )
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
        {r.permalink && (
          <a href={r.permalink} target="_blank" rel="noreferrer noopener"
            className="inline-flex items-center gap-1 text-[var(--accent-text)] hover:underline">
            <ExternalLink size={11} /> {tr('enrich.open')}
          </a>
        )}
      </div>
    </div>
  )
}
