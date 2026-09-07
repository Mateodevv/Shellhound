import { useT } from '../i18n'
import { useEffect, useMemo, useRef, useState, type CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Activity, Box, ChevronLeft, ChevronRight, FileDigit, Globe, Plus, ShieldOff } from 'lucide-react'
import { api, post, downloadUrl, downloadSelection, type Ioc, type CrossCaseIocResponse } from '../api'
import type { Navigate } from '../App'
import { Button, Modal, SearchInput } from '../components/ui'
import { CaseProfileButton } from '../components/CaseProfile'
import { OpenCtiToolbar } from '../components/OpenCti'
import { IocDetails } from '../components/IocDetails'
import { assessmentTone, ctiLabel, iocName } from '../components/iocPresentation'
import { useOpenCti } from '../opencti'

const groups = [{ name: 'All', types: [] }, { name: 'IPs', types: ['ip'] }, { name: 'Files', types: ['file'] }, { name: 'Domains / URLs', types: ['domain', 'url'] }, { name: 'CVEs', types: ['vulnerability'] }, { name: 'Other', types: ['hash', 'path', 'user', 'email', 'other'] }]
const field = 'min-w-0 rounded-md border border-[var(--line)] bg-[var(--panel-2)] px-2 py-2 text-[12px]'
const defaults = { group: 'All', search: '', assessment: '', origin: '', status: '', type: '', sort: 'newest', page: 1, size: 50, width: 360, scroll: 0, active: null as number | null, tab: 'Overview' }
type Session = typeof defaults
function load(slug: string): Session {
  let saved = {}
  try { saved = JSON.parse(sessionStorage.getItem(`ioc-workspace:${slug}`) || '{}') } catch { /* Fresh workspace. */ }
  const q = new URLSearchParams(location.search)
  return { ...defaults, ...saved, ...(q.has('ioc') ? { active: Number(q.get('ioc')) || null } : {}), ...(q.has('iocTab') ? { tab: q.get('iocTab')! } : {}) }
}

export function IocBox({ slug, gotoView }: { slug: string; gotoView: Navigate }) {
  const tr = useT()
  const qc = useQueryClient()
  const { data: iocs = [], error, isPending } = useQuery({ queryKey: ['iocs', slug], queryFn: () => api<Ioc[]>(`/api/cases/${slug}/iocs`) })
  const { data: cross } = useQuery({ queryKey: ['iocs', 'cross-case', slug], queryFn: () => api<CrossCaseIocResponse>(`/api/cases/${slug}/iocs/cross-case`) })
  const cti = useOpenCti(slug)
  const [state, setState] = useState(() => load(slug))
  const listRef = useRef<HTMLDivElement>(null)
  const [selection, setSelection] = useState<Set<number>>(new Set())
  const [trail, setTrail] = useState<number[]>([])
  const [dirty, setDirty] = useState(false)
  const [filters, setFilters] = useState(false)
  const [addOpen, setAddOpen] = useState(false)
  const [activity, setActivity] = useState(false)
  const [value, setValue] = useState('')
  const [note, setNote] = useState('')
  const update = (patch: Partial<Session>) => setState(s => ({ ...s, ...patch }))
  const filter = (patch: Partial<Session>) => update({ ...patch, page: 1, scroll: 0 })
  useEffect(() => { sessionStorage.setItem(`ioc-workspace:${slug}`, JSON.stringify(state)) }, [slug, state])
  useEffect(() => {
    const restore = () => { const q = new URLSearchParams(location.search); update({ active: Number(q.get('ioc')) || null, tab: q.get('iocTab') || 'Overview' }) }
    window.addEventListener('popstate', restore)
    return () => window.removeEventListener('popstate', restore)
  }, [])
  useEffect(() => {
    const guard = (e: BeforeUnloadEvent) => { if (dirty) { e.preventDefault(); e.returnValue = '' } }
    window.addEventListener('beforeunload', guard)
    const beforeNavigate = (event: Event) => { if (dirty && !window.confirm('Discard unsaved changes?')) event.preventDefault() }
    window.addEventListener('shellhound:before-navigate', beforeNavigate)
    return () => { window.removeEventListener('beforeunload', guard); window.removeEventListener('shellhound:before-navigate', beforeNavigate) }
  }, [dirty])
  const canLeave = () => !dirty || window.confirm('Discard unsaved changes?')
  const navigate: Navigate = (view, params) => gotoView(view, params)
  function open(id: number | null, back = false) {
    if (id === state.active || !canLeave()) return false
    if (!back && state.active != null && id != null) setTrail(t => [...t, state.active!])
    setDirty(false); update({ active: id, tab: 'Overview' })
    const url = new URL(location.href)
    if (id != null) url.searchParams.set('ioc', String(id)); else url.searchParams.delete('ioc')
    url.searchParams.delete('iocTab'); history.replaceState(null, '', url)
    return true
  }
  const setTab = (tab: string) => { update({ tab }); const url = new URL(location.href); url.searchParams.set('iocTab', tab); history.replaceState(null, '', url) }
  const add = useMutation({
    mutationFn: () => post<{ id: number }>(`/api/cases/${slug}/iocs`, { value, note }), onSuccess: result => {
      setAddOpen(false); setValue(''); setNote(''); qc.invalidateQueries({ queryKey: ['iocs'] }); open(result.id)
    }
  })
  const download = useMutation({ mutationFn: ({ ids, format }: { ids: number[]; format: string }) => downloadSelection(`/api/cases/${slug}/iocs/export`, ids, format, `iocs_${slug}.${format === 'csv' ? 'csv' : 'json'}`) })
  const byId = useMemo(() => new Map(iocs.map(i => [i.id, i])), [iocs])
  const lookups = useMemo(() => new Map(cti.data?.lookups?.map(i => [i.ioc_id, i]) ?? []), [cti.data])
  const sync = useMemo(() => new Map(cti.data?.sync?.map(i => [i.ioc_id, i.status]) ?? []), [cti.data])
  const roots = useMemo(() => iocs.filter(i => i.type !== 'hash' || !i.file_ids?.some(id => byId.has(id))), [iocs, byId])
  const members = (id: number) => [id, ...iocs.filter(i => i.type === 'hash' && i.file_ids?.includes(id)).map(i => i.id)]
  const filtered = useMemo(() => {
    const types = groups.find(g => g.name === state.group)?.types ?? []
    const term = state.search.trim().toLowerCase()
    return roots.filter(i => (!types.length || types.includes(i.type)) && (!state.type || i.type === state.type)
      && (!state.assessment || i.assessment === state.assessment) && (!state.origin || i.tags.includes(state.origin))
      && (!state.status || (state.status.startsWith('sync:') ? sync.get(i.id) === state.status.slice(5) : state.status === 'unchecked' ? !lookups.has(i.id) : state.status === 'stale' ? lookups.get(i.id)?.stale : lookups.get(i.id)?.status === state.status))
      && (!term || [i.value, i.note, i.origin, i.summary, ...(i.file?.names ?? []), ...Object.values(i.file?.hashes ?? {})].some(v => v?.toLowerCase().includes(term))))
      .sort((a, b) => (state.sort === 'name' ? iocName(a).localeCompare(iocName(b)) : state.sort === 'assessment' ? (a.assessment || '').localeCompare(b.assessment || '') : state.sort === 'observed' ? (b.last_seen || '').localeCompare(a.last_seen || '') : b.added.localeCompare(a.added)) || b.id - a.id)
  }, [roots, state, sync, lookups])
  const pages = Math.max(1, Math.ceil(filtered.length / state.size)), page = Math.min(state.page, pages)
  const visible = filtered.slice((page - 1) * state.size, page * state.size)
  useEffect(() => { if (listRef.current && !isPending) listRef.current.scrollTop = state.scroll }, [state.scroll, isPending, state.page])
  const selected = roots.filter(i => selection.has(i.id))
  const selectedIds = [...new Set(selected.flatMap(i => members(i.id)))]
  const hiddenSelected = selected.filter(i => !filtered.some(f => f.id === i.id)).length
  const select = (rows: Ioc[]) => setSelection(previous => new Set([...previous, ...rows.map(i => i.id)]))
  const active = state.active == null ? null : byId.get(state.active)
  const jobs = cti.data?.jobs ?? [], running = jobs.filter(j => ['queued', 'running'].includes(j.state)).length, failures = jobs.filter(j => j.state === 'failed').length
  const filterCount = [state.assessment, state.origin, state.status, state.type].filter(Boolean).length
  const crossMatches = cross?.entries.find(i => i.id === state.active)?.matches ?? []
  const filterSelect = (label: string, key: 'assessment' | 'origin' | 'status' | 'type', choices: [string, string][]) => <select
    aria-label={label}
    className={field}
    value={state[key]}
    onChange={e => filter({ [key]: e.target.value })}>
    <option value="">{label}</option>
    {choices.map(([v, name]) => <option key={v} value={v}>{name}</option>)}
  </select>
  return <section className="ioc-workspace flex min-w-0 flex-col gap-3" aria-label="IOC workspace">

    <header className="flex flex-wrap items-center gap-2">
      <div className="mr-auto">
        <h1 className="text-xl font-semibold">{tr('iocWorkspace.ioc_box')}</h1>
        <p className="text-[12px] text-[var(--muted)]">{tr('iocWorkspace.objects_evidence_and_relationships')}</p>
      </div>
      <Button onClick={() => setActivity(true)}>
        <Activity size={14} />
        {tr('iocWorkspace.activity')}
        {running > 0 && `(${running} running)`}
        {failures > 0 && <span className="text-[var(--danger-text)]">{failures} {tr('iocWorkspace.failed')}</span>}
      </Button>
      <Button variant="primary" onClick={() => setAddOpen(true)}>
        <Plus size={14} />
        {tr('iocWorkspace.add_ioc')}
      </Button>
    </header>

    <nav aria-label="Object types" className="flex flex-wrap gap-1 border-b border-[var(--line)]">{groups.map(g => <button
      key={g.name}
      aria-pressed={state.group === g.name}
      onClick={() => filter({ group: g.name, type: '' })}
      className={`border-b-2 px-3 py-3 text-[13px] ${state.group === g.name ? 'border-[var(--accent)] text-[var(--accent-text)]' : 'border-transparent text-[var(--muted)]'}`}>
      {g.name}
      <span className="ml-1 text-[11px]">{roots.filter(i => !g.types.length || g.types.includes(i.type)).length}</span>
    </button>)}</nav>

    {selected.length > 0 && <div className="rounded-lg border border-[var(--accent)]/50 p-3" aria-label="Selection actions">
      <div className="mb-2 flex flex-wrap items-center gap-3 text-[12px]">
        <strong>{selected.length} {tr('iocWorkspace.objects_selected')}</strong>
        {hiddenSelected > 0 && <span>{hiddenSelected} {tr('iocWorkspace.outside_current_filters')}</span>}
        <Button onClick={() => setSelection(new Set())}>{tr('iocWorkspace.clear_selection')}</Button>
      </div>
      <OpenCtiToolbar
        mode="actions"
        slug={slug}
        iocs={iocs}
        selectedIds={selectedIds}
        onSelectAll={() => select(filtered)}
        onClear={() => setSelection(new Set())}
        onSettings={() => navigate('settings')} />
    </div>}

    {error && <p role="alert" className="text-[var(--danger-text)]">{error.message}</p>}

    <div
      className="ioc-split overflow-hidden rounded-lg border border-[var(--line)] bg-[var(--panel)]"
      style={{ '--ioc-list-width': `${state.width}px` } as CSSProperties}>

      <aside
        className={`ioc-list flex min-h-0 min-w-0 flex-col ${state.active != null ? 'ioc-list-hidden-mobile' : ''}`}
        aria-label="IOC objects">

        <div className="space-y-3 border-b border-[var(--line)] p-3">
          <SearchInput
            className="w-full"
            value={state.search}
            onChange={search => filter({ search })}
            placeholder="Search objects…" />
          <div className="flex gap-2">
            <Button onClick={() => setFilters(v => !v)} aria-expanded={filters}>{tr('iocWorkspace.filters')} {filterCount > 0 && `(${filterCount})`}</Button>
            <select
              aria-label="Sort objects"
              className={`${field} ml-auto`}
              value={state.sort}
              onChange={e => filter({ sort: e.target.value })}>
              <option value="newest">{tr('iocWorkspace.newest_first')}</option>
              <option value="name">{tr('iocWorkspace.name')}</option>
              <option value="assessment">{tr('iocWorkspace.assessment')}</option>
              <option value="observed">{tr('iocWorkspace.last_observed')}</option>
            </select>
          </div>

          {filters && <div className="grid grid-cols-2 gap-2">
            {filterSelect('Assessment filter', 'assessment', ['malicious', 'suspicious', 'benign', 'unassessed'].map(s => [s, s]))}
            {filterSelect('Origin / tag filter', 'origin', [...new Set(iocs.flatMap(i => i.tags))].sort().map(s => [s, s]))}
            {filterSelect('OpenCTI filter', 'status', [['known', 'Known'], ['own', 'Own exports only'], ['unknown', 'No visible match'], ['unchecked', 'Not checked'], ['stale', 'Outdated'], ['error', 'Check failed'], ['sync:new', 'New for transfer'], ['sync:changed', 'Changed'], ['sync:error', 'Transfer error'], ['sync:exported', 'Transferred']])}
            {filterSelect('Object type filter', 'type', [...new Set(roots.map(i => i.type))].sort().map(s => [s, s]))}
            <Button onClick={() => filter({ assessment: '', origin: '', status: '', type: '' })}>{tr('iocWorkspace.reset_filters')}</Button>
          </div>}

          <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--muted)]">
            <span>{filtered.length} {tr('iocWorkspace.objects')}</span>
            <button
              className="text-[var(--accent-text)]"
              disabled={isPending || !visible.length}
              onClick={() => select(visible)}>{tr('iocWorkspace.select_page')}</button>
            <button
              className="text-[var(--accent-text)]"
              disabled={isPending || !filtered.length}
              onClick={() => select(filtered)}>{tr('iocWorkspace.select_all_filtered')}</button>
          </div>

        </div>

        <div
          className="min-h-0 flex-1 overflow-y-auto"
          ref={listRef}
          onScroll={e => update({ scroll: e.currentTarget.scrollTop })}
          role="list"
          aria-label="Object list">{isPending && <p className="p-4" role="status">{tr('iocWorkspace.loading_objects')}</p>}{!isPending && !filtered.length && <p className="p-4 text-[13px] text-[var(--muted)]">{tr('iocWorkspace.no_matching_objects')}</p>}{visible.map(ioc => {
            const Icon = ioc.type === 'ip' ? Globe : ioc.type === 'file' ? FileDigit : ioc.type === 'vulnerability' ? ShieldOff : Box; return <div
              key={ioc.id}
              role="listitem"
              className={`flex items-center gap-2 border-b border-l-2 border-b-[var(--line)] px-3 ${state.active === ioc.id ? 'border-l-[var(--accent)] bg-[var(--accent-soft)]' : 'border-l-transparent'}`}>
              <input
                type="checkbox"
                aria-label={`Select ${iocName(ioc)}`}
                checked={selection.has(ioc.id)}
                onChange={() => setSelection(previous => { const next = new Set(previous); if (next.has(ioc.id)) next.delete(ioc.id); else next.add(ioc.id); return next })} />
              <button
                onClick={() => open(ioc.id)}
                aria-label={`Open ${iocName(ioc)}`}
                aria-current={state.active === ioc.id ? 'true' : undefined}
                className="flex min-w-0 flex-1 items-center gap-3 py-3 text-left">
                <Icon size={17} className="shrink-0 text-[var(--muted)]" />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[13px] font-medium" title={iocName(ioc)}>{iocName(ioc)}</span>
                  <span className="block truncate text-[11px] text-[var(--muted)]">
                    <span className={assessmentTone(ioc.assessment)}>{ioc.assessment || 'malicious'}</span>
                    {ioc.assessment_manual && ' ✎'} ·
                    {sync.get(ioc.id) === 'error' ? 'Transfer error' : sync.get(ioc.id) === 'changed' ? 'Changed' : ctiLabel(lookups.get(ioc.id))}
                  </span>
                </span>
              </button>
            </div>
          })}</div>

        <footer
          className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--line)] p-3 text-[11px]">
          <span>{filtered.length ? (page - 1) * state.size + 1 : 0}–{Math.min(page * state.size, filtered.length)} {tr('iocWorkspace.of')} {filtered.length}</span>
          <div className="flex items-center gap-2">
            <Button aria-label="Previous page" disabled={page <= 1} onClick={() => update({ page: page - 1, scroll: 0 })}>
              <ChevronLeft size={13} />
            </Button>
            <span>{page} / {pages}</span>
            <Button aria-label="Next page" disabled={page >= pages} onClick={() => update({ page: page + 1, scroll: 0 })}>
              <ChevronRight size={13} />
            </Button>
          </div>
          <select
            aria-label="Objects per page"
            className={field}
            value={state.size}
            onChange={e => filter({ size: Number(e.target.value) })}>{[25, 50, 100].map(n => <option key={n} value={n}>{n} {tr('iocWorkspace.page')}</option>)}</select>
        </footer>

      </aside>

      <div
        className="ioc-divider cursor-col-resize bg-[var(--line)]"
        role="separator"
        aria-label="Resize object list"
        aria-orientation="vertical"
        aria-valuenow={state.width}
        aria-valuemin={280}
        aria-valuemax={500}
        tabIndex={0}
        onKeyDown={e => { if (['ArrowLeft', 'ArrowRight'].includes(e.key)) { e.preventDefault(); update({ width: Math.min(500, Math.max(280, state.width + (e.key === 'ArrowRight' ? 20 : -20))) }) } }}
        onPointerDown={e => e.currentTarget.setPointerCapture(e.pointerId)}
        onPointerMove={e => { if (e.currentTarget.hasPointerCapture(e.pointerId)) { const bounds = e.currentTarget.parentElement!.getBoundingClientRect(); update({ width: Math.min(500, Math.max(280, e.clientX - bounds.left)) }) } }}
        onPointerUp={e => e.currentTarget.releasePointerCapture(e.pointerId)} />

      <div
        className={`ioc-detail min-h-0 min-w-0 overflow-y-auto ${state.active == null ? 'ioc-detail-hidden-mobile' : ''}`}>
        {state.active != null ? <><div className="flex flex-wrap items-center gap-2 border-b border-[var(--line)] px-4 py-2 text-[11px]">
          <Button
            onClick={() => { if (trail.length) { if (open(trail[trail.length - 1], true)) setTrail(t => t.slice(0, -1)) } else open(null) }}>
            <ChevronLeft size={13} />
            {tr('iocWorkspace.back')}
          </Button>
          <button className="text-[var(--accent-text)]" onClick={() => open(null)}>{tr('iocWorkspace.object_list')}</button>
          {active && !filtered.some(i => i.id === active.id) && <span className="text-[var(--muted)]">{tr('iocWorkspace.outside_current_filters')}</span>}
        </div>{active ? <IocDetails
          key={`${slug}:${state.active}`}
          embedded
          slug={slug}
          id={state.active}
          iocs={iocs}
          tab={state.tab}
          onTab={setTab}
          onClose={() => open(null)}
          onNavigate={open}
          gotoView={navigate}
          onDirtyChange={setDirty}
          crossMatches={crossMatches} /> : <p className="p-5">{tr('iocWorkspace.this_object_is_no_longer_available')}</p>}</> : <div className="flex h-full flex-col items-center justify-center gap-3 p-8 text-[var(--muted)]">
          <Box size={32} />
          <p>{tr('iocWorkspace.select_an_object_to_explore_its_evidence_and_relationships')}</p>
        </div>}
      </div>

    </div>

    <Modal
      open={addOpen}
      onClose={() => { if ((!value && !note) || window.confirm('Discard this new IOC?')) setAddOpen(false) }}
      title="Add IOC">
      <form className="space-y-4" onSubmit={e => { e.preventDefault(); add.mutate() }}>
        <label className="block text-[13px]">
          {tr('iocWorkspace.value')}
          <input
            className={`${field} mt-1 w-full`}
            required
            value={value}
            onChange={e => setValue(e.target.value)}
            placeholder="IP, domain, URL, hash, path or CVE…" />
        </label>
        <label className="block text-[13px]">
          {tr('iocWorkspace.note')}
          <textarea className={`${field} mt-1 w-full`} value={note} onChange={e => setNote(e.target.value)} />
        </label>
        <p className="text-[12px] text-[var(--muted)]">{tr('iocWorkspace.initial_assessment_malicious')}</p>
        {add.error && <p role="alert">{add.error.message}</p>}
        <Button disabled={!value.trim() || add.isPending}>{tr('iocWorkspace.add_ioc')}</Button>
      </form>
    </Modal>

    <Modal open={activity} onClose={() => setActivity(false)} title="IOC activity">
      <div className="space-y-4">
        <CaseProfileButton slug={slug} />
        <OpenCtiToolbar
          mode="activity"
          slug={slug}
          iocs={iocs}
          selectedIds={[]}
          onSelectAll={() => { }}
          onClear={() => { }}
          onSettings={() => navigate('settings')} />
        <p className="text-[12px]">{tr('iocWorkspace.download')} {filtered.length} {tr('iocWorkspace.filtered_objects')}</p>
        <div className="flex gap-2">{['csv', 'json', 'stix'].map(format => <Button
          key={format}
          disabled={download.isPending}
          onClick={() => download.mutate({ ids: [...new Set(filtered.flatMap(i => members(i.id)))], format })}>{format.toUpperCase()}</Button>)}</div>
        {download.error && <p role="alert">{download.error.message}</p>}
        <p className="text-[12px]">{tr('iocWorkspace.download_all')} {iocs.length} {tr('iocWorkspace.case_ioc_entries')}</p>
        <div className="flex gap-4">{['csv', 'json', 'stix'].map(fmt => <a
          key={fmt}
          className="text-[var(--accent-text)]"
          href={downloadUrl(`/api/cases/${slug}/iocs/export?format=${fmt}`)}>{fmt.toUpperCase()}</a>)}</div>
        {!!cross?.cases_skipped && <p>{cross.cases_skipped} {tr('iocWorkspace.cases_unavailable_for_cross_case_comparison')}</p>}
      </div>
    </Modal>

  </section>
}
