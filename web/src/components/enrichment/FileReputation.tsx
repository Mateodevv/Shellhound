import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useRef } from 'react'
import { ExternalLink, LoaderCircle, RefreshCw, Search } from 'lucide-react'
import { api, post, type Enrichment } from '../../api'
import { useDirectSettings } from '../../directEnrichment'
import { absoluteTime, formatCount } from '../../format'
import { useT } from '../../i18n'
import { safeCtiUrl, useOpenCtiSettings } from '../../opencti'
import { Button } from '../ui/ui'
import { InfoDot } from '../ui/Tooltip'

type History = { entries: Enrichment[] } | Enrichment[]
const entriesOf = (history?: History) => Array.isArray(history) ? history : history?.entries ?? []

/** Remount requests with the subject so switching files cannot show an old error or result. */
export function FileReputation({ slug, sha256, boxUrl }: { slug: string; sha256: string; boxUrl: string }) {
  return <HashLookup key={JSON.stringify([slug, sha256.toLowerCase()])} slug={slug} sha256={sha256.toLowerCase()} boxUrl={boxUrl} />
}

function HashLookup({ slug, sha256, boxUrl }: { slug: string; sha256: string; boxUrl: string }) {
  const tr = useT()
  const qc = useQueryClient()
  const settings = useDirectSettings()
  const cti = useOpenCtiSettings()
  const validHash = /^[a-f0-9]{64}$/.test(sha256)
  const history = useQuery({ queryKey: ['enrichment', slug],
    queryFn: () => api<History>(`/api/cases/${slug}/enrichment`), enabled: validHash })
  const matches = (entry: Enrichment) => entry.service === 'virustotal' && entry.kind === 'hash' && entry.value.toLowerCase() === sha256
  const entry = entriesOf(history.data).find(matches)
  const ready = validHash && !settings.isError && !cti.isError
    && cti.data?.configured === false && settings.data?.services?.virustotal?.configured === true
  const lookupPending = useRef(false)
  const run = useMutation({
    onMutate: () => qc.cancelQueries({ queryKey: ['enrichment', slug] }),
    mutationFn: () => post<Enrichment>(`/api/cases/${slug}/enrich`, {
      service: 'virustotal', kind: 'hash', value: sha256, refresh: !!entry,
    }),
    onSuccess: result => {
      qc.setQueryData<History>(['enrichment', slug], previous => ({
        entries: [...entriesOf(previous).filter(item => !matches(item)), result],
      }))
    },
    onSettled: () => { lookupPending.current = false },
  })
  const lookup = () => {
    if (!ready || history.isPending || lookupPending.current) return
    lookupPending.current = true
    run.mutate()
  }
  const result = entry?.result
  const score = result?.known && Number.isInteger(result.score) && result.score! >= 0 ? result.score : undefined
  const tone = score == null ? 'var(--muted)' : score === 0 ? 'var(--ok)' : 'var(--danger-text)'
  const report = safeCtiUrl(result?.permalink)
  const configurationError = settings.isError || cti.isError

  return <section aria-label={tr('enrich.virustotal')} className="mt-3 space-y-2 border-t border-[var(--line)] pt-3 text-[11px]">
    <div className="flex items-center gap-1 font-semibold text-[12px]">{tr('fileReputation.title')}
      <InfoDot label={tr('fileReputation.help')} body={tr('fileReputation.sends')} hint={tr('fileReputation.meaning')} />
    </div>
    {cti.data?.configured ? <>
      <p className="text-[var(--muted)]">{tr('fileReputation.opencti')}</p>
      <a className="inline-flex items-center gap-1 rounded text-[var(--accent-text)] hover:underline" href={boxUrl}>{tr('cti.toBox')}<ExternalLink size={12} /></a>
    </> : <>
      <Button type="button" aria-keyshortcuts="V" className="w-full justify-center" disabled={!ready || history.isPending || run.isPending} onClick={lookup}>
        {run.isPending ? <LoaderCircle size={13} className="animate-spin" /> : entry ? <RefreshCw size={13} /> : <Search size={13} />}
        {tr(run.isPending ? 'direct.running' : entry ? 'fileReputation.refresh' : 'enrich.ask', { service: tr('enrich.virustotal') })}
        <kbd aria-hidden="true" className="ml-1 rounded border border-current/20 px-1 text-[10px] font-normal opacity-65">V</kbd>
      </Button>
      {!ready && !configurationError && !settings.isPending && !cti.isPending && <p className="text-[var(--muted)]">{tr(validHash ? 'fileReputation.setup' : 'fileReputation.noHash')}</p>}
    </>}
    {configurationError && <div role="alert" className="text-[var(--review-text)]">
      <p>{tr('fileReputation.settingsError')}</p>
      <Button onClick={() => { void settings.refetch(); void cti.refetch() }}>{tr('common.retry')}</Button>
    </div>}
    {history.isPending && validHash && <p role="status" className="text-[var(--muted)]">{tr('fileReputation.loading')}</p>}
    {history.isError && <div role="alert" className="text-[var(--review-text)]">
      <p>{tr('fileReputation.historyError')}</p>
      <Button onClick={() => void history.refetch()}>{tr('common.retry')}</Button>
    </div>}
    {run.isError && <p role="alert" className="break-words text-[var(--review-text)]">{run.error.message}</p>}
    {entry && <div role="status" className="space-y-1.5 rounded-lg border p-3" style={{ color: tone,
      borderColor: `color-mix(in srgb, ${tone} 40%, transparent)`, background: `color-mix(in srgb, ${tone} 9%, var(--panel))` }}>
      {score != null ? <>
        <p className="text-lg font-semibold tabular">{formatCount(score)}{result?.of != null && <> / {formatCount(result.of)}</>}</p>
        <p>{tr('fileReputation.detections')}</p>
      </> : <p>{tr(result?.known ? 'fileReputation.noCount' : 'fileReputation.unknown')}</p>}
      {!!result?.suspicious && <p>{tr('fileReputation.suspicious', { n: formatCount(result.suspicious) })}</p>}
      <p className="text-[var(--muted)]">{tr('direct.fetched', { at: absoluteTime(entry.fetched) })}</p>
      {report && <a className="inline-flex items-center gap-1 rounded font-medium hover:underline" href={report} target="_blank" rel="noreferrer noopener">{tr('direct.openReport')}<ExternalLink size={12} /></a>}
    </div>}
  </section>
}
