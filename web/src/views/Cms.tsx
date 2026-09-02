// Cms.tsx -- the inventory of the installations: which CMS, which version,
// which extensions -- and WHICH OF THEM IS COMPROMISED.
//
// ONE list per installation instead of a mosaic of tiles: every engine type
// used to become its own card table, and Joomla produces 10-15 of those
// ("Plugin (system)", "Plugin (content)" …) -- tiles of differing height
// without a reading direction. Now the types fold into 4-5 groups (the
// plugin group and site/admin are an addition on the row, not a type of
// their own), and one reads once from top to bottom.
//
// The tie to the case comes from the server: extensions with flagged files
// under them carry a badge and open the artifact window -- the page answers
// the question "which extension is it?" itself instead of leaving the path
// comparison to the analyst's head.
import { plural, useT } from '../i18n'
import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Bug, Check, ChevronDown, ChevronRight, FileSearch, PencilLine, Puzzle,
  RotateCcw, Server, TriangleAlert,
} from 'lucide-react'
import clsx from 'clsx'
import {
  api, patch, type CaseDetail, type CmsInstall, type CmsItem,
  type VersionFacts,
} from '../api'
import {
  SEVERITY_VAR, absoluteTime, baseName, formatCount, shortPath, type EvidenceRoot,
} from '../format'
import {
  Button, Card, Chip, EmptyState, Modal, SearchInput, SeverityBadge, Tag,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { explain, explainPluginGroup } from '../explain'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import type { ViewId } from '../App'

// "Plugin (system)" -> group Plugin, addition system; "Module (Admin)" ->
// group Module, scope Admin. The addition belongs on the row, not in the
// structure -- otherwise every plugin group becomes its own table.
const SCOPES = new Set(['Site', 'Admin'])

// WHERE THE ENGINE OMITS THE SCOPE IT IS STILL DETERMINED -- just,
// unfortunately, not uniformly: the engine takes components unlabelled from
// administrator/components (so, backend), but modules and templates
// unlabelled from modules/ resp. templates/ (so, frontend). An unlabelled
// "Component" next to an unlabelled "Module" therefore reads wrongly. Here
// the silent scope is spelled out; the type stored in the database stays
// untouched, because the key of the version corrections hangs on it.
const IMPLICIT_SCOPE: Record<string, string> = {
  Component: 'Admin',
  Module: 'Site',
  Template: 'Site',
}

function splitType(raw: string): { base: string; qualifier?: string; scope?: string } {
  const m = raw.match(/^(.*?)\s*\((.+)\)$/)
  if (!m) return { base: raw, scope: IMPLICIT_SCOPE[raw] }
  return SCOPES.has(m[2])
    ? { base: m[1], scope: m[2] }
    : { base: m[1], qualifier: m[2], scope: IMPLICIT_SCOPE[m[1]] }
}

// Reading order: what gets manipulated most often comes first.
const TYPE_ORDER: Record<string, number> = {
  Plugin: 1, Theme: 2, Template: 3, Component: 4, Module: 5,
}

/** What a version correction refers to -- installation or extension. The
 *  window is the same for both. */
interface VersionTarget extends VersionFacts {
  kind: 'install' | 'item'
  id: number
  label: string
}

export function Cms({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const { data } = useQuery({
    queryKey: ['cms', slug],
    queryFn: () => api<{ installs: CmsInstall[] }>(`/api/cases/${slug}/cms`),
  })
  const [search, setSearch] = useState('')
  // Hide switches as everywhere: types and version state.
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set())
  const [hiddenVersion, setHiddenVersion] = useState<Set<string>>(new Set())

  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // What the trace should mark red -- comes from the artifact window,
  // which knows what this is about (the file, or the client's alert).
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [versionTarget, setVersionTarget] = useState<VersionTarget | null>(null)
  const t = useTriage(slug)

  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))

  const installs = useMemo(() => data?.installs ?? [], [data])

  // Chip counters across ALL installs -- one filter bar for the page.
  const typeCounts = useMemo(() => {
    const out = new Map<string, number>()
    for (const inst of installs) {
      for (const i of inst.items) {
        const base = splitType(i.type).base
        out.set(base, (out.get(base) ?? 0) + 1)
      }
    }
    return [...out.entries()].sort(
      (a, b) => (TYPE_ORDER[a[0]] ?? 99) - (TYPE_ORDER[b[0]] ?? 99))
  }, [installs])

  const versionCounts = useMemo(() => {
    let known = 0, unknown = 0
    for (const inst of installs) {
      for (const i of inst.items) {
        if (i.version === '(unknown)') unknown += 1
        else known += 1
      }
    }
    return { known, unknown }
  }, [installs])

  const visible = (i: CmsItem) => {
    const base = splitType(i.type).base
    if (hiddenTypes.has(base)) return false
    if (hiddenVersion.has(i.version === '(unknown)' ? 'unknown' : 'known')) return false
    if (search && !i.name.toLowerCase().includes(search.toLowerCase()) &&
        !i.slug.toLowerCase().includes(search.toLowerCase())) return false
    return true
  }

  const toggle = (set: (fn: (prev: Set<string>) => Set<string>) => void, v: string) =>
    set((prev) => {
      const next = new Set(prev)
      if (next.has(v)) next.delete(v)
      else next.add(v)
      return next
    })

  return (
    <div className="flex flex-col gap-4">
      <header>
        <Tooltip title={tr('nav.cms')}
          body={tr('cms.title.body')}
          hint={tr('cms.title.hint')}>
          <h1 className="text-lg font-bold">{tr('nav.cms')}</h1>
        </Tooltip>
        <p className="mt-1 text-[12.5px] text-[var(--muted)]">{tr('cms.title.body')}</p>
      </header>
      <Card surface="raised" className="flex flex-wrap items-center gap-2 p-2.5">
        <span className="mr-1 text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">
          {tr('cms.filters.included')}
        </span>
        {typeCounts.map(([base, n]) => (
          <Tooltip key={base}
            hint={hiddenTypes.has(base)
              ? tr('cms.hidden')
              : tr('cms.type.hide')}>
            <Chip active={!hiddenTypes.has(base)} dimmed={hiddenTypes.has(base)}
              onClick={() => toggle(setHiddenTypes, base)} count={n}>
              {base}
            </Chip>
          </Tooltip>
        ))}
        {typeCounts.length > 0 && <span className="mx-1 h-4 w-px bg-[var(--line)]" />}
        <Tooltip hint={tr('cms.hideVersioned')}>
          <Chip active={!hiddenVersion.has('known')} dimmed={hiddenVersion.has('known')}
            onClick={() => toggle(setHiddenVersion, 'known')} count={versionCounts.known}>
            {tr('cms.withVersion')}
          </Chip>
        </Tooltip>
        <Tooltip hint={tr('field.unknown_version')}>
          <Chip active={!hiddenVersion.has('unknown')} dimmed={hiddenVersion.has('unknown')}
            onClick={() => toggle(setHiddenVersion, 'unknown')} count={versionCounts.unknown}>
            <TriangleAlert size={12} /> {tr('cms.withoutVersion')}
          </Chip>
        </Tooltip>
        <div className="ml-auto">
          <SearchInput value={search} onChange={setSearch} placeholder={tr('cms.search')} />
        </div>
      </Card>

      {installs.map((inst) => (
        <InstallCard key={inst.id} install={inst} visible={visible}
          filtering={Boolean(search || hiddenTypes.size || hiddenVersion.size)}
          onOpenArtifact={(stub) => { t.clearCollected(); setSelected(stub) }}
          onEditVersion={setVersionTarget} />
      ))}

      {data && !installs.length && (
        <EmptyState icon={<Puzzle size={36} />} title={tr('cms.empty.title')}
          sub={tr('cms.empty.sub')} />
      )}

      <VersionWindow
        slug={slug}
        target={versionTarget}
        onClose={() => setVersionTarget(null)}
        onView={(path) => setViewing({ path, line: null })}
      />

      <ArtifactWindow
        slug={slug}
        artifact={selected}
        roots={roots}
        collected={t.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips, m) => { setTraceMarks(m); setTraceIps(ips) }}
        onClose={() => { setSelected(null); t.clearCollected() }}
        onSave={(state, note) => {
          if (!selected) return Promise.reject(new Error('No artifact selected'))
          return t.decideAsync([selected.artifact], state, note)
        }}
      />
      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />
      <FileViewer slug={slug} path={viewing?.path ?? null}
        focusLine={viewing?.line} layer={2} onClose={() => setViewing(null)} />
      <TriageFollowUp t={t} roots={roots} />
    </div>
  )
}

function InstallCard({ install, visible, filtering, onOpenArtifact, onEditVersion }: {
  install: CmsInstall
  visible: (i: CmsItem) => boolean
  filtering: boolean
  onOpenArtifact: (stub: ArtifactStub) => void
  onEditVersion: (t: VersionTarget) => void
}) {
  const tr = useT()
  const unknown = install.items.filter((i) => i.version === '(unknown)').length
  const flagged = install.items.filter((i) => i.flagged > 0).length
  // Collapsed groups. A filter or a search expands everything -- otherwise
  // the hit sits behind a click one cannot see.
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())

  // One list, structured by base type -- the plugin group stands as an
  // addition on the row.
  const sections = useMemo(() => {
    const byBase = new Map<string, CmsItem[]>()
    for (const i of install.items) {
      if (!visible(i)) continue
      const base = splitType(i.type).base
      const list = byBase.get(base) ?? []
      list.push(i)
      byBase.set(base, list)
    }
    for (const list of byBase.values()) {
      // Flagged first -- that is what one is looking for here.
      list.sort((a, b) => (b.flagged - a.flagged) || a.name.localeCompare(b.name))
    }
    return [...byBase.entries()].sort(
      (a, b) => (TYPE_ORDER[a[0]] ?? 99) - (TYPE_ORDER[b[0]] ?? 99))
  }, [install.items, visible])

  const shown = sections.reduce((n, [, list]) => n + list.length, 0)

  return (
    <Card className="overflow-hidden">
      {/* ---- the head: the most important number on the page is the version ---- */}
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
          <Server size={18} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-[15px] font-semibold tracking-tight">
            {install.cms}
            {install.version === '(unknown)'
              ? <Tag tone="warn" hint={tr('cms.noCoreVersion')}>{tr('cms.versionUnknown')}</Tag>
              : <span className="mono text-[var(--accent-text)]">{install.version}</span>}
            {install.version_set && (
              <Tag tone="accent"
                hint={tr('cms.setByHand') + (install.version_parsed !== '(unknown)'
                  ? ` — ${tr('cms.measured')} ${install.version_parsed}` : '') + '.'}>
                {tr('cms.manual')}
              </Tag>
            )}
          </div>
          <div className="mono truncate text-[11.5px] text-[var(--muted)]" title={install.root}>
            {baseName(install.root)}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2 text-[12px] text-[var(--muted)]">
          {/* No `ghost`: on a head that is panel-2 coloured anyway, a button
              made of muted text would be invisible until hovered by accident.
              A border says "this can be clicked". */}
          <Tooltip hint={tr('cms.checkVersion.hint')}>
            <Button className="text-[var(--fg)]"
              style={{ background: 'var(--panel)' }}
              onClick={() => onEditVersion({
                kind: 'install', id: install.id, label: install.cms,
                version: install.version, version_parsed: install.version_parsed,
                version_source: install.version_source,
                version_set: install.version_set,
                version_note: install.version_note,
                version_set_at: install.version_set_at,
              })}>
              <PencilLine size={13} /> {tr('cms.checkVersion')}
            </Button>
          </Tooltip>
          <span>{plural(tr, install.items.length, 'cms.extension.one', 'cms.extension.many',
                        { n: formatCount(install.items.length) })}</span>
          {unknown > 0 && (
            <Tag tone="warn" hint={tr('field.unknown_version')}>
              {unknown} {tr('cms.withoutVersion')}
            </Tag>
          )}
          {flagged > 0 && (
            <Tag tone="danger"
              hint={tr('cms.flaggedExtensions')}>
              <Bug size={11} /> {flagged} {tr('database.withFindings')}
            </Tag>
          )}
        </div>
      </div>

      {/* ---- one list, groups as collapsible bands ---- */}
      {sections.map(([base, list]) => {
        const open = filtering || !collapsed.has(base)
        const groupFlagged = list.filter((i) => i.flagged > 0).length
        return (
        <div key={base}>
          <button
            onClick={() => setCollapsed((prev) => {
              const next = new Set(prev)
              if (next.has(base)) next.delete(base)
              else next.add(base)
              return next
            })}
            className="flex w-full cursor-pointer items-center gap-2 border-b border-[var(--line)] bg-[var(--panel-2)]/60 px-4 py-1.5 text-left text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)]">
            {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            {base} <span className="opacity-70">({list.length})</span>
            {groupFlagged > 0 && (
              <span className="ml-1 inline-flex items-center gap-1 rounded-md bg-[var(--danger-soft)] px-1.5 text-[10px] normal-case text-[var(--danger-text)]">
                <Bug size={10} /> {groupFlagged}
              </span>
            )}
          </button>
          {open && list.map((item) => {
            const { qualifier, scope } = splitType(item.type)
            const worstHit = item.artifacts[0]
            return (
              <div key={item.id}
                className={clsx(
                  'flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2 last:border-0',
                  'transition-colors hover:bg-[var(--panel-2)]')}>
                {/* A coloured edge only when something was found here. */}
                <span className="h-8 w-1 shrink-0 rounded-full"
                  style={{ background: worstHit ? SEVERITY_VAR[worstHit.worst] : 'transparent' }} />
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate text-[13px] font-medium">{item.name}</span>
                    {qualifier && (
                      <Tag explain={explainPluginGroup(tr, qualifier).what}
                        hint={explainPluginGroup(tr, qualifier).why}>
                        {qualifier}
                      </Tag>
                    )}
                    {scope && (
                      <Tag explain={explain(tr, `cmsScope.${scope}`)?.what}
                        hint={explain(tr, `cmsScope.${scope}`)?.why}>
                        {scope}
                      </Tag>
                    )}
                  </div>
                  <div className="mono truncate text-[11px] text-[var(--muted)]" title={item.path}>
                    {item.slug} · {shortPath(item.path, 60)}
                  </div>
                </div>
                {item.flagged > 0 && worstHit && (
                  <Tooltip
                    title={plural(tr, item.flagged, 'cms.flaggedHere.one', 'cms.flaggedHere.many',
                                  { n: item.flagged })}
                    body={item.artifacts.map((a) => a.artifact).join('\n')}
                    hint={tr('cms.openArtifact')}
                    wide>
                    <button
                      className={clsx(
                        'inline-flex shrink-0 cursor-pointer items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium',
                        item.artifacts.some((a) => a.triage === 'confirmed')
                          ? 'bg-[var(--danger-soft)] text-[var(--danger-text)]'
                          : 'bg-[rgba(250,178,25,0.12)] text-[var(--sev-low)]')}
                      onClick={() => onOpenArtifact({
                        artifact: worstHit.artifact, artifact_kind: 'file',
                        worst: worstHit.worst, triage: worstHit.triage,
                        triage_note: '',
                      })}>
                      <Bug size={11} /> {plural(tr, item.flagged, 'cms.artifact.one', 'cms.artifact.many',
                                                 { n: item.flagged })}
                    </button>
                  </Tooltip>
                )}
                {/* Keep the measured value visible, but name the action too:
                    an unlabeled pencil/version field is easy to mistake for
                    static metadata. */}
                <Tooltip
                  title={item.version_set ? tr('cms.setByHand') : tr('cms.checkVersion')}
                  body={item.version_source
                    ? tr('cms.readFrom', { src: item.version_source })
                    : tr('cms.noSource')}
                  hint={item.version_set
                    ? tr('cms.measuredWas', { v: item.version_parsed })
                    : tr('cms.versionSource.hint')}
                  wide>
                  <button
                    onClick={() => onEditVersion({
                      kind: 'item', id: item.id, label: item.name,
                      version: item.version, version_parsed: item.version_parsed,
                      version_source: item.version_source,
                      version_set: item.version_set,
                      version_note: item.version_note,
                      version_set_at: item.version_set_at,
                    })}
                    className={clsx(
                      'flex w-44 shrink-0 cursor-pointer items-center justify-between gap-2',
                      'rounded-lg border px-2 py-1 transition-colors',
                      'border-[var(--line)] bg-[var(--panel-2)] hover:border-[var(--accent)]/60',
                      item.version_set && 'border-[var(--accent)]/50')}>
                    <span className="inline-flex min-w-0 items-center gap-1.5 text-[11px] font-medium">
                      <PencilLine size={11}
                        className={clsx('shrink-0',
                          item.version_set ? 'text-[var(--accent)]' : 'text-[var(--muted)]')} />
                      {tr('cms.set')}
                    </span>
                    {item.version === '(unknown)'
                      ? <span className="truncate text-[11px] text-[var(--sev-low)]">{tr('cms.unknown')}</span>
                      : <span className="mono max-w-16 truncate text-[11px] text-[var(--muted)]">{item.version}</span>}
                  </button>
                </Tooltip>
                {worstHit && <SeverityBadge severity={worstHit.worst} plain />}
              </div>
            )
          })}
        </div>
        )
      })}

      {shown === 0 && (
        <div className="px-4 py-6 text-center text-[13px] text-[var(--muted)]">
          {tr('cms.noMatch')}
        </div>
      )}
    </Card>
  )
}

/** Check and set a version.
 *
 *  A version is a CLAIM made by the manifest -- and manifests can be forged
 *  or missing entirely. This window therefore first shows WHERE the number
 *  was read from, and makes that file openable. What the analyst then sets
 *  by hand does NOT replace the measured value, it overlays it: both stay
 *  visible side by side, and the correction survives any re-analysis. */
function VersionWindow({ slug, target, onClose, onView }: {
  slug: string
  target: VersionTarget | null
  onClose: () => void
  onView: (path: string) => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const [value, setValue] = useState('')
  const [note, setNote] = useState('')
  useEffect(() => {
    setValue(target?.version_set || (target?.version_parsed === '(unknown)'
      ? '' : target?.version_parsed ?? ''))
    setNote(target?.version_note ?? '')
  }, [target])

  const save = useMutation({
    mutationFn: (v: { version: string; note: string }) =>
      patch(`/api/cases/${slug}/cms/${target!.kind === 'install' ? 'installs' : 'items'}/${target!.id}`, v),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cms'] })
      onClose()
    },
  })

  if (!target) return null
  const source = target.version_source
  return (
    <Modal open onClose={onClose} layer={1}
      title={<span className="flex min-w-0 items-center gap-2">
        <PencilLine size={15} className="shrink-0 text-[var(--accent)]" />
        <span className="truncate">{tr('cms.checkVersion')} — {target.label}</span>
      </span>}>
      <div className="flex flex-col gap-4">
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-lg bg-[var(--panel-2)] px-3 py-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              {tr('cms.measured')}
            </div>
            <div className="mono mt-0.5 text-[13px]">
              {target.version_parsed === '(unknown)'
                ? <span className="text-[var(--sev-low)]">{tr('cms.notFound')}</span>
                : target.version_parsed}
            </div>
          </div>
          <div className="rounded-lg bg-[var(--panel-2)] px-3 py-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              {tr('cms.currentlyApplies')}
            </div>
            <div className="mono mt-0.5 flex items-center gap-2 text-[13px]">
              {target.version === '(unknown)' ? '—' : target.version}
              {target.version_set && <Tag tone="accent">{tr('cms.manual')}</Tag>}
            </div>
          </div>
        </div>

        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('cms.source')}
          </div>
          {source ? (
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono min-w-0 flex-1 truncate rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[11.5px]"
                title={source}>
                {source}
              </span>
              <Button onClick={() => onView(source)}>
                <FileSearch size={14} /> {tr('cms.viewFile')}
              </Button>
            </div>
          ) : (
            <p className="text-[12.5px] text-[var(--muted)]">
              {tr('cms.noSource.body')}
            </p>
          )}
        </div>

        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('cms.setManually')}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={tr('cms.versionExample')}
              className="mono w-40 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
            />
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder={tr('cms.versionNote')}
              className="min-w-56 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
            />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Button variant="primary" disabled={!value.trim() || save.isPending}
              onClick={() => save.mutate({ version: value.trim(), note })}>
              <Check size={14} /> {tr('cms.set')}
            </Button>
            {target.version_set && (
              <Button disabled={save.isPending}
                onClick={() => save.mutate({ version: '', note: '' })}>
                <RotateCcw size={14} /> {tr('cms.resetToMeasured')}
              </Button>
            )}
            <Button variant="ghost" onClick={onClose}>{tr('common.cancel')}</Button>
            {target.version_set_at && (
              <span className="text-[11px] text-[var(--muted)]">
                {tr('cms.setAt')}: {absoluteTime(target.version_set_at)}
              </span>
            )}
          </div>
          <p className="mt-2 text-[11px] text-[var(--muted)]">
            {tr('cms.setManually.note')}
          </p>
        </div>
      </div>
    </Modal>
  )
}
