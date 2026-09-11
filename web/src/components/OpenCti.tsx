import { useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, LoaderCircle, Network, Radar, Search } from 'lucide-react'
import { post, type Ioc } from '../api'
import { useT } from '../i18n'
import { useOpenCti, useOpenCtiSettings, openCtiKey, type OpenCtiLookup, type OpenCtiEnrichmentPreview } from '../opencti'
import { Button, Card, Modal, Tag, Tabs } from './ui'
import { CtiError } from './CaseProfile'
import { OpenCtiActivity } from './OpenCtiActivity'
import { ConnectorCapabilities } from './ConnectorCapabilities'
import { SelectColumn } from './OpenCtiSelection'
import { iocCategories, inIocCategory, selectBatch, selectionTable, selectionHead } from './ctiSelectionModel'

export { OpenCtiScore } from './OpenCtiScore'

export function OpenCtiStatus({ lookup, sync, onClick, value }: { lookup?: OpenCtiLookup; sync?: string; onClick: () => void; value: string }) {
  const tr = useT()
  return <button type="button" aria-label={tr('cti.inspect', { value })} onClick={onClick} className="flex shrink-0 cursor-pointer items-center gap-1 rounded border border-[var(--line)] px-1.5 py-1 text-[10px] text-[var(--muted)] hover:border-[var(--accent)]">
    <Radar size={12} />{tr(lookup?.stale ? 'cti.stale' : `cti.${lookup?.status ?? 'unchecked'}`)}{sync && <span> · {tr(`cti.${sync}`)}</span>}
  </button>
}
export { EnrichmentDetails as OpenCtiDetails } from './EnrichmentDetails'

export function GroupedActions({ children, busy = false, label, icon }: { children: ReactNode; busy?: boolean; label?: string; icon?: ReactNode }) {
  const tr = useT()
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const panelId = useId()
  useEffect(() => {
    if (!open) return
    const dismiss = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('pointerdown', dismiss)
    return () => document.removeEventListener('pointerdown', dismiss)
  }, [open])
  return <div ref={root} className="relative" onBlur={event => {
    if (!event.currentTarget.contains(event.relatedTarget as Node)) setOpen(false)
  }} onKeyDown={event => {
    if (event.key === 'Escape' && open) {
      event.stopPropagation()
      setOpen(false)
      root.current?.querySelector('button')?.focus()
    }
  }}>
    <Button type="button" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen(value => !value)}>
      {busy ? <LoaderCircle size={14} className="animate-spin" /> : icon || <Network size={14} />}
      {label || tr('cti.actions')}<ChevronDown size={14} />
    </Button>
    {open && <div id={panelId} className="absolute right-0 top-full z-50 mt-1 flex min-w-56 flex-col gap-1 rounded-lg border border-[var(--line-strong)] bg-[var(--panel)] p-1.5 shadow-xl animate-fade-in" onClick={event => {
      if ((event.target as HTMLElement).closest('button:not(:disabled)')) {
        setOpen(false)
        root.current?.querySelector('button')?.focus()
      }
    }}>{children}</div>}
  </div>
}

export function OpenCtiToolbar({ slug, iocs, selectedIds, onSelectAll, onClear, mode = 'full', actionScope = 'selection', leadingAction, trailingAction, grouped = false }: {
  slug: string; iocs: Ioc[]; selectedIds: number[]; onSelectAll: () => void; onClear: () => void; onSettings: () => void
  mode?: 'full' | 'actions' | 'activity' | 'inline'
  actionScope?: 'selection' | 'case'
  leadingAction?: ReactNode
  trailingAction?: ReactNode
  grouped?: boolean
}) {
  const tr = useT()
  const qc = useQueryClient()
  const conf = useOpenCtiSettings()
  const status = useOpenCti(slug)
  const actionIds = actionScope === 'case' ? iocs.map(ioc => ioc.id) : selectedIds
  const inline = mode === 'inline'
  const [enrichment, setEnrichment] = useState<{ data: OpenCtiEnrichmentPreview; ids: number[] } | null>(null)
  const [queued, setQueued] = useState(false)
  const refreshed = () => { setQueued(true); qc.invalidateQueries({ queryKey: openCtiKey(slug) }); qc.invalidateQueries({ queryKey: ['jobs', slug] }) }
  const lookup = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/lookup`, { ioc_ids: actionIds }), onSuccess: refreshed })
  const prepareEnrichment = useMutation({ mutationFn: async () => ({ ids: [...actionIds], data: await post<OpenCtiEnrichmentPreview>(`/api/cases/${slug}/opencti/enrichment/preview`, { ioc_ids: actionIds }) }), onSuccess: setEnrichment })
  const busy = lookup.isPending || prepareEnrichment.isPending
  const ready = !!conf.data?.configured && actionIds.length > 0 && !busy
  const scopeHint = actionScope === 'case' ? tr('cti.caseScope', { n: actionIds.length }) : undefined
  const checkLabel = tr(actionScope === 'case' ? 'cti.checkAll' : 'cti.check')
  const enrichLabel = tr(actionScope === 'case' ? 'cti.enrichAll' : 'cti.enrich')
  if (!conf.data?.configured) return <div className="flex flex-wrap items-center gap-2">{leadingAction}{trailingAction}</div>
  const actions = <>
    <Button variant={grouped ? 'ghost' : 'default'} type="button" disabled={!ready} aria-label={checkLabel} title={scopeHint} onClick={() => { setQueued(false); lookup.mutate() }}>{lookup.isPending ? <LoaderCircle size={13} className="animate-spin" /> : <Search size={13} />}{checkLabel}</Button>
    <Button variant={grouped ? 'ghost' : 'default'} type="button" disabled={!ready} aria-label={enrichLabel} title={scopeHint} onClick={() => prepareEnrichment.mutate()}>{prepareEnrichment.isPending ? <LoaderCircle size={13} className="animate-spin" /> : <Radar size={13} />}{enrichLabel}</Button>
  </>
  const Container = inline ? 'div' : Card
  return <Container className={inline ? 'flex min-w-0 max-w-full flex-col gap-2' : 'flex flex-col gap-3 border-[var(--accent)]/30 p-3'}>
    {mode !== 'activity' && <><div className="flex flex-wrap items-center gap-2">{leadingAction}{!inline && <strong className="mr-auto text-[13px]">{tr('cti.title')}</strong>}
      {grouped ? <GroupedActions busy={busy}>{actions}</GroupedActions> : actions}
      {trailingAction}
    </div>
    {!inline && <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--muted)]"><span>{actionIds.length} {tr('iocWorkspace.ioc_entries_in_this_action')}</span>
      {mode === 'full' && <><Button variant="ghost" onClick={onSelectAll} disabled={selectedIds.length === iocs.length}>{tr('cti.all')}</Button><Button variant="ghost" onClick={onClear} disabled={!selectedIds.length}>{tr('cti.clear')}</Button></>}
    </div>}</>}
    <CtiError error={conf.error || lookup.error || prepareEnrichment.error || status.error} />
    {queued && <p role="status" className="text-[12px] text-[var(--muted)]">{tr(inline ? 'cti.queuedActivity' : 'cti.queued')}</p>}
    {(mode === 'full' || mode === 'activity') && <OpenCtiActivity slug={slug} iocs={iocs} />}
    {enrichment && <EnrichmentDialog slug={slug} data={enrichment.data} ids={enrichment.ids} onClose={() => setEnrichment(null)} onQueued={() => { setEnrichment(null); refreshed() }} />}
  </Container>
}

function EnrichmentDialog({ slug, data, ids, onClose, onQueued }: { slug: string; data: OpenCtiEnrichmentPreview; ids: number[]; onClose: () => void; onQueued: () => void }) {
  const tr = useT()
  const [tab, setTab] = useState('all')
  const [selectedIds, setSelectedIds] = useState(() => data.entities.filter(entity => ids.includes(entity.ioc_id)).map(entity => entity.ioc_id))
  const [connectors, setConnectors] = useState<string[]>([])
  const [createMissing, setCreateMissing] = useState(false)
  const included = data.entities.filter(entity => selectedIds.includes(entity.ioc_id))
  const visible = data.entities.filter(entity => inIocCategory(entity.type, tab))
  const missing = included.filter(entity => entity.requires_creation)
  const needsTransfer = included.some((entity) => entity.requires_transfer)
  const available = data.connectors.filter((connector) => connector.active)
  const run = useMutation({ mutationFn: () => post(`/api/cases/${slug}/opencti/enrich`, { ioc_ids: selectedIds, connector_ids: connectors, create_missing: createMissing }), onSuccess: onQueued })
  return <Modal open title={tr('cti.enrichPreview')} onClose={onClose} contained bodyClassName="overflow-hidden px-5 py-4"><div className="flex h-full min-h-0 flex-col gap-3 text-[12px]">
    <p className="shrink-0">{tr('cti.enrichBody')}</p>
    <section aria-label={tr('cti.chooseConnectors')} className="shrink-0 rounded-lg border border-[var(--line-strong)] bg-[var(--panel-2)] p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div><h3 className="text-[14px] font-semibold">{tr('cti.chooseConnectors')}</h3>
          <p className="mt-1 text-[var(--muted)]">{tr(connectors.length ? 'cti.connectorsSelected' : 'cti.chooseConnectorsHint', { n: connectors.length })}</p></div>
        {!!available.length && <label className="flex cursor-pointer items-center gap-2"><SelectColumn label={tr('cti.connectors')} states={available.map(connector => connectors.includes(connector.id))} onChange={checked => setConnectors(selectBatch(connectors, available.map(connector => connector.id), checked))} />{tr('cti.all')}</label>}
      </div>
      <div className="grid max-h-[22vh] grid-cols-1 gap-2 overflow-y-auto sm:grid-cols-2 lg:grid-cols-3">
        {available.map(connector => <div key={connector.id} className={`flex items-start gap-3 rounded-md border p-3 ${connectors.includes(connector.id) ? 'border-[var(--accent)] bg-[var(--accent-soft)]' : 'border-[var(--line)] bg-[var(--panel)] hover:border-[var(--accent)]'}`}>
          <input type="checkbox" className="mt-0.5" aria-label={connector.name} checked={connectors.includes(connector.id)} onChange={e => setConnectors(selectBatch(connectors, [connector.id], e.target.checked))} />
          <div className="min-w-0 flex-1"><button type="button" className="block w-full cursor-pointer text-left font-semibold" onClick={() => setConnectors(selectBatch(connectors, [connector.id], !connectors.includes(connector.id)))}>{connector.name}</button>
            <ConnectorCapabilities connector={connector} />
            {connector.auto && <span className="block text-[var(--review-text)]">{tr('cti.automatic')}</span>}</div>
        </div>)}
      </div>
      {!available.length && <p className="text-[var(--review-text)]">{tr('cti.noConnectors')}</p>}
    </section>
    <div className="shrink-0 space-y-1 [&_[role=tab]]:shrink-0 [&_[role=tab]]:whitespace-nowrap">
    <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={iocCategories.map(id => ({ id, label: tr(`cti.category.${id}`), badge: <span className="ml-1 text-[10px]">{data.entities.filter(entity => inIocCategory(entity.type, id)).length}</span> }))} /></div>
    {data.warnings.length > 0 && <div className="overflow-x-auto"><Tabs active={tab} onChange={setTab} tabs={[{ id: 'notices', label: tr('cti.notices'), badge: <span className="ml-2">{data.warnings.length}</span> }]} /></div>}</div>
    <div className="min-h-0 flex-1 overflow-hidden">
    <div hidden={tab !== 'notices'} role="tabpanel" aria-label={tr('cti.notices')} className="h-full overflow-y-auto [scrollbar-gutter:stable] space-y-2">{data.warnings.map(warning => <p key={warning} className="rounded border border-[var(--line)] p-3 text-[var(--review-text)]">{warning}</p>)}</div>
    <div hidden={!iocCategories.includes(tab)} role="tabpanel" aria-label={tr('cti.iocs')} className="h-full overflow-auto [scrollbar-gutter:stable]">
      <table className={selectionTable}><colgroup><col style={{ width: 44 }} /><col /><col style={{ width: 110 }} /><col style={{ width: '35%' }} /></colgroup>
        <thead className={selectionHead}><tr><th><SelectColumn label={tr('cti.iocs')} states={visible.map(entity => selectedIds.includes(entity.ioc_id))} onChange={checked => setSelectedIds(selectBatch(selectedIds, visible.map(entity => entity.ioc_id), checked))} /></th><th>{tr('iocTable.object')}</th><th>{tr('iocTable.type')}</th><th>{tr('cti.enrichmentStatus')}</th></tr></thead>
        <tbody>{visible.map(entity => <tr key={entity.ioc_id}><td><input type="checkbox" aria-label={tr('cti.selectIoc', { value: entity.value })} checked={selectedIds.includes(entity.ioc_id)} onChange={e => setSelectedIds(selectBatch(selectedIds, [entity.ioc_id], e.target.checked))} /></td><td className="mono break-all">{entity.value}</td><td><Tag>{entity.type}</Tag></td><td>{tr(entity.requires_transfer ? 'cti.transferRequired' : entity.requires_creation ? 'cti.missingObservable' : 'cti.existingObservable')}</td></tr>)}{!visible.length && <tr><td colSpan={4}>{tr('iocWorkspace.no_matching_objects')}</td></tr>}</tbody>
      </table>
    </div>
    </div>
    <div className="shrink-0 space-y-2 border-t border-[var(--line)] pt-3">
    {!!missing.length && <div className="rounded-lg border border-[var(--line)] p-3"><p>{tr('cti.missingCount', { n: missing.length })}</p>
      <label className="mt-3 flex items-center gap-2"><input type="checkbox" checked={createMissing} onChange={(e) => setCreateMissing(e.target.checked)} />{tr('cti.createMissing')}</label>
    </div>}
    <CtiError error={run.error} />
    <div className="flex justify-end gap-2"><Button onClick={onClose}>{tr('common.cancel')}</Button><Button variant="primary" disabled={!selectedIds.length || needsTransfer || !connectors.length || (!!missing.length && !createMissing) || run.isPending} onClick={() => run.mutate()}>{tr('cti.startEnrich')}</Button></div>
    </div>
  </div></Modal>
}
