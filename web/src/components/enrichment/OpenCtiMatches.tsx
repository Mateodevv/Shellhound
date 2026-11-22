import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, post } from '../../api'
import { openCtiHost, safeCtiUrl, useOpenCtiSettings } from '../../opencti'
import { useT } from '../../i18n'
import { Button } from '../ui/ui'

type Match = { kind: 'ip' | 'hash'; value: string; known: boolean; cases: { id: string; name: string; url: string }[]; truncated: boolean; checked_at: string }

export function OpenCtiMatches({ slug, kind, value }: { slug: string; kind: 'ip' | 'hash'; value: string }) {
  const tr = useT()
  const qc = useQueryClient()
  const settings = useOpenCtiSettings()
  const enabled = settings.data?.lookup_configured === true
  const key = ['opencti-matches', slug, settings.data?.url, kind, value]
  const path = `/api/cases/${encodeURIComponent(slug)}/opencti/matches`
  const cached = useQuery({ queryKey: key, enabled, queryFn: () => api<{ result: Match | null }>(`${path}?${new URLSearchParams({ kind, value })}`) })
  const lookup = useMutation({ mutationFn: () => post<Match>(path, { kind, value, expected_url: settings.data?.url }), onSuccess: result => qc.setQueryData(key, { result }) })
  if (!enabled) return null
  const result = cached.data?.result
  return <section className="space-y-2 border-t border-[var(--line)] pt-3 text-[12px]" aria-label={tr('ctiMatches.title')}>
    <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">{tr('ctiMatches.title')}</h3><Button disabled={lookup.isPending} onClick={() => lookup.mutate()}>{tr('ctiMatches.check')}</Button></div>
    <p>{tr('ctiMatches.destination', { host: openCtiHost(settings.data?.url) })}</p>
    {(cached.isLoading || lookup.isPending) && <p role="status">{tr('ctiMatches.loading')}</p>}
    {(cached.error || lookup.error) && <p role="alert">{tr('ctiMatches.error')}: {String((lookup.error || cached.error)?.message)}</p>}
    {result && <div className="space-y-1">
      <p>{!result.known ? tr('ctiMatches.none') : result.cases.length ? tr('ctiMatches.found') : tr('ctiMatches.known')}</p>
      {result.cases.map(item => { const url = safeCtiUrl(item.url); return <p key={item.id}>{url ? <a className="text-[var(--accent-text)]" href={url} target="_blank" rel="noreferrer">{item.name || item.id}</a> : item.name || item.id}</p> })}
      {result.truncated && <p>{tr('ctiMatches.truncated')}</p>}
      <p className="text-[var(--muted)]">{tr('ctiMatches.checked', { time: result.checked_at })}</p>
    </div>}
  </section>
}
