import type { OpenCtiLookup } from '../opencti'
import { useT } from '../i18n'
import { Tag } from './ui'
import { InfoDot } from './Tooltip'

export function OpenCtiScore({ lookup, loading, error }: { lookup?: OpenCtiLookup; loading?: boolean; error?: boolean }) {
  const tr = useT()
  const scored = lookup?.entities?.filter(entity => typeof entity.score === 'number' && Number.isFinite(entity.score) && entity.score >= 0 && entity.score <= 100) ?? []
  return <div className="min-w-0 space-y-2 py-3">
    <div className="flex items-center gap-2 font-semibold">{tr('cti.scoreTitle')}<InfoDot body={<>{tr('cti.scoreDescription')}{lookup?.checked_at && <span className="mt-2 block">{tr('cti.cached', { at: lookup.checked_at })}</span>}</>} /></div>
    <div className="flex flex-wrap items-center gap-2">
      {scored.map(entity => <span key={entity.id} className="inline-flex items-center gap-2">
        {scored.length > 1 && <span className="break-all text-[12px]">{entity.name || entity.type}</span>}
        <span className="rounded px-2 py-1 text-[11px] font-medium tabular-nums" style={{ background: 'var(--review-soft)', color: 'var(--review-text)' }}>{entity.score} / 100</span>
      </span>)}
      {!scored.length && <span className="text-[var(--muted)]">{tr(loading ? 'common.loading' : error || lookup?.status === 'error' ? 'cti.scoreUnavailable' : !lookup ? 'cti.unchecked' : 'cti.noScore')}</span>}
      {lookup?.stale && <Tag tone="warn">{tr('cti.stale')}</Tag>}
      {(error || lookup?.status === 'error') && scored.length > 0 && <span className="text-[var(--danger-text)]">{tr('cti.scoreUnavailable')}</span>}
    </div>
  </div>
}
