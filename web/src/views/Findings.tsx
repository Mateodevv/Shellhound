// Findings.tsx -- the work list of the case. What gets worked through are
// ARTIFACTS, not individual findings.
//
// An artifact is the thing itself: this file, this client, this table. The
// findings are the rules that responded to it -- they are the REASON for the
// decision, not the decision itself. Eight rules on one dropped shell are
// eight observations about ONE file; the question ("does this belong to the
// incident?") is asked once.
//
// Hence: what gets checked, counted and decided as a true/false positive is
// the artifact. The list starts with the category ("Web shells &
// backdoors"); file artifacts keep their evidence-directory hierarchy below
// it, while non-file artifacts remain direct children. Individual findings
// expand below their artifact and in the detail window, which gathers everything
// needed for the assessment: metadata, file content, actor profile and every
// IP that hangs on it -- each of them openable directly as a trace.
//
// The row itself should SAY SO MUCH that one mostly does not have to open
// it: icon and colour for kind and severity, the rules as chips, a bar for
// the distribution of the findings, the state as a pill. A list of
// identical-looking rows forces one to read every single one.
import { useT } from '../i18n'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  BellOff, BookmarkPlus, Bug, Check, ChevronDown, ChevronRight, CircleDashed, Code,
  Crosshair, Database, DoorOpen, Eye, EyeOff, FileCog, FileSearch,
  Folder, FolderOpen, Keyboard, KeyRound, ListFilter, Radar, X,
} from 'lucide-react'
import clsx from 'clsx'
import { api, type ArtifactRow, type Finding, type FindingsResponse } from '../api'
import {
  SEVERITY_VAR, formatCount,
  relativeToRoot, shortPath, type EvidenceRoot,
} from '../format'
import {
  Button, Card, EmptyState, Modal, SearchInput, SeverityBadge,
  Toast, TriageBadge,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { FileViewer } from '../components/FileViewer'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import { ArtifactWindow } from '../components/ArtifactWindow'
import { KIND_ICON } from '../artifactKinds'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { artifactNoun, categorize, explainRule, type Category } from '../explain'
import { nextReviewArtifact } from '../reviewQueue'
import type { Navigate } from '../App'

// One icon per category. The category is the structure one starts from --
// it should be distinguishable at a glance and not stand as yet another line
// of text in a list of text.
const CATEGORY_ICON: Record<string, typeof Bug> = {
  webshell: Bug,
  obfuscation: EyeOff,
  htaccess: FileCog,
  db_injected: Database,
  db_markup: Code,
  shell_access: DoorOpen,
  bruteforce: KeyRound,
  probes: Crosshair,
  scanner: Radar,
  other: CircleDashed,
}

/** An artifact with everything the server aggregated for it, plus its
 *  findings. The category comes from the WORST finding -- when a file
 *  triggers both "obfuscation" and "executes commands", it stands where the
 *  stronger statement puts it. */
interface Artifact extends ArtifactRow {
  items: Finding[]
  cat: Category
}

interface CatGroup {
  cat: Category
  artifacts: Artifact[]
  findings: number
  worst: number
  confirmed: number
  dismissed: number
  kind: string          // predominant artifact kind, for "12 files"
}

interface SavedView {
  name: string
  hiddenSeverity: string[]
  hiddenTriage: string[]
  hiddenSource: string[]
  search: string
  showRetired: boolean
}

interface DirectoryNode {
  key: string
  name: string
  path: string
  artifacts: Artifact[]
  children: DirectoryNode[]
  count: number
  worst: number
}

// Row types of the virtualised list.
type Item =
  | { t: 'c'; c: CatGroup }
  | { t: 'd'; d: DirectoryNode; depth: number }
  | { t: 'a'; a: Artifact; c: CatGroup; depth: number }
  | { t: 'f'; f: Finding; a: Artifact; depth: number }

const isArtifactRow = (i?: Item) => i?.t === 'a'

/** Toggle a hide set: a click hides the class, the next click brings it
 *  back. */
function toggleHidden(set: Set<string>, value: string): Set<string> {
  const next = new Set(set)
  if (next.has(value)) next.delete(value)
  else next.add(value)
  return next
}

/** How many artifacts one request fetches. The count in the header
 *  describes the whole set, so anything above this has to be stated. */
const LIST_CAP = 2000
const ALL_SEVERITIES = ['0', '1', '2', '3']
const ALL_TRIAGE = ['new', 'reviewed', 'confirmed', 'dismissed']
const ALL_SOURCES = ['webshell', 'sqldb', 'logs', 'yara', 'analyst']

function hiddenFromUrl(key: string, all: string[], fallback: string[]): Set<string> {
  const raw = new URLSearchParams(location.search).get(key)
  if (raw == null) return new Set(fallback)
  const visible = new Set(raw.split(',').filter((value) => all.includes(value)))
  return new Set(all.filter((value) => !visible.has(value)))
}

/** Build the directory levels that are actually present in the evidence.
 *  The filename stays an artifact row; only its parent path becomes tree
 *  structure. Non-file findings remain directly below the category. */
function directoryForest(artifacts: Artifact[], roots: EvidenceRoot[], category: string) {
  const direct: Artifact[] = []
  const top: DirectoryNode[] = []
  const nodes = new Map<string, DirectoryNode>()

  for (const artifact of artifacts) {
    if (artifact.artifact_kind !== 'file') {
      direct.push(artifact)
      continue
    }
    const located = relativeToRoot(artifact.artifact, roots)
    const relative = located.rel.replace(/\\/g, '/')
    const parts = relative.split('/').filter(Boolean).slice(0, -1)
    if (!parts.length) {
      direct.push(artifact)
      continue
    }
    let parent: DirectoryNode | null = null
    let path = ''
    const windowsPath = /^[A-Za-z]:/.test(artifact.artifact) || artifact.artifact.includes('\\')
    const source = located.root?.path ?? 'unregistered-root'
    for (const name of parts) {
      path = path ? `${path}/${name}` : name
      const identity = `${source}:${path}`
      const key = `${category}:${windowsPath ? identity.toLowerCase() : identity}`
      let node = nodes.get(key)
      if (!node) {
        node = { key, name, path, artifacts: [], children: [], count: 0, worst: 3 }
        nodes.set(key, node)
        if (parent) parent.children.push(node)
        else top.push(node)
      }
      node.count += 1
      node.worst = Math.min(node.worst, artifact.worst)
      parent = node
    }
    parent!.artifacts.push(artifact)
  }

  const sort = (rows: DirectoryNode[]) => {
    rows.sort((a, b) => a.name.localeCompare(b.name))
    for (const row of rows) {
      row.artifacts.sort((a, b) => a.artifact.localeCompare(b.artifact))
      sort(row.children)
    }
  }
  sort(top)
  return { direct, directories: top }
}

/** Follow the exact category/directory order used by the queue, including
 * artifacts hidden behind a collapsed presentation group. Collapsing is a
 * reading preference, not another filter. */
function orderedQueue(categories: CatGroup[], roots: EvidenceRoot[]): Artifact[] {
  const ordered: Artifact[] = []
  const addDirectory = (directory: DirectoryNode) => {
    ordered.push(...directory.artifacts)
    for (const child of directory.children) addDirectory(child)
  }
  for (const category of categories) {
    const tree = directoryForest(category.artifacts, roots, category.cat.id)
    if (tree.directories.length) {
      ordered.push(...tree.direct.filter((artifact) => artifact.artifact_kind !== 'file'))
      for (const directory of tree.directories) addDirectory(directory)
      ordered.push(...tree.direct.filter((artifact) => artifact.artifact_kind === 'file'))
    } else {
      ordered.push(...tree.direct)
    }
  }
  return ordered
}

export function Findings({ slug, gotoView }: {
  slug: string
  gotoView: Navigate
}) {
  const tr = useT()
  // EVERY filter chip is a hide switch: a click hides its class, the next
  // click brings it back, several of them stack. Hidden by default: false
  // positives (they do not belong to the case) and info (context without a
  // statement about this system).
  const [hiddenSeverity, setHiddenSeverity] = useState<Set<string>>(
    () => hiddenFromUrl('severity', ALL_SEVERITIES, ['3']))
  const [hiddenTriage, setHiddenTriage] = useState<Set<string>>(
    () => hiddenFromUrl('triage', ALL_TRIAGE, ['dismissed']))
  const [hiddenSource, setHiddenSource] = useState<Set<string>>(
    () => hiddenFromUrl('source', ALL_SOURCES, []))
  // "Say AND show": the banner names how many artifacts the last completed
  // scan no longer reported -- this switch lets the analyst look at them,
  // greyed, instead of taking a number on faith.
  const [showRetired, setShowRetired] = useState(
    () => new URLSearchParams(location.search).get('retired') === '1')
  const [search, setSearch] = useState(
    () => new URLSearchParams(location.search).get('search') ?? '')
  const [selected, setSelected] = useState<Artifact | null>(null)
  const [cursor, setCursor] = useState(0)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  // Two sets instead of one: without a filter, categories are CLOSED
  // (overview) and `expandedCats` says what is open; with a filter they are
  // OPEN and `collapsedCats` says what is closed. That way each is the
  // exception the analyst set themselves.
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set())
  const [collapsedCats, setCollapsedCats] = useState<Set<string>>(new Set())
  const [collapsedDirs, setCollapsedDirs] = useState<Set<string>>(new Set())
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [bulkNote, setBulkNote] = useState('')
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [helpOpen, setHelpOpen] = useState(false)
  const [filtersOpen, setFiltersOpen] = useState(false)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // What the trace should mark red -- comes from the artifact window, which
  // knows what this is about (the file, or the client's alert).
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()
  const [queueComplete, setQueueComplete] = useState(false)
  const savedKey = `shellhound.saved-findings.${slug}`
  const [savedViews, setSavedViews] = useState<SavedView[]>(() => {
    try { return JSON.parse(localStorage.getItem(savedKey) || '[]') }
    catch { return [] }
  })

  // Decision plus follow-up (receipt, propagation message, suggestions) --
  // shared with Actors, so that it is the same decision everywhere.
  const t = useTriage(slug, () => { setChecked(new Set()); setBulkNote('') })

  const query = useMemo(() => {
    const p = new URLSearchParams()
    if (hiddenSeverity.size) p.set('hide_severity', [...hiddenSeverity].join(','))
    if (hiddenTriage.size) p.set('hide_triage', [...hiddenTriage].join(','))
    if (hiddenSource.size) {
      p.set('source', ALL_SOURCES.filter((value) => !hiddenSource.has(value)).join(','))
    }
    if (showRetired) p.set('show_retired', '1')
    if (search) p.set('search', search)
    p.set('limit', String(LIST_CAP))
    return p.toString()
  }, [hiddenSeverity, hiddenTriage, hiddenSource, showRetired, search])

  const { data } = useQuery({
    queryKey: ['findings', slug, query],
    queryFn: () => api<FindingsResponse>(`/api/cases/${slug}/findings?${query}`),
  })
  const roots: EvidenceRoot[] = useMemo(() => data?.roots ?? [], [data])

  // The work list is linkable: refresh, browser back and a copied URL keep
  // the exact queue instead of dropping the analyst on the dashboard.
  useEffect(() => {
    const url = new URL(location.href)
    const visible = (all: string[], hidden: Set<string>) =>
      all.filter((value) => !hidden.has(value)).join(',')
    url.searchParams.set('severity', visible(ALL_SEVERITIES, hiddenSeverity))
    url.searchParams.set('triage', visible(ALL_TRIAGE, hiddenTriage))
    const sources = visible(ALL_SOURCES, hiddenSource)
    if (sources === ALL_SOURCES.join(',')) url.searchParams.delete('source')
    else url.searchParams.set('source', sources)
    if (search) url.searchParams.set('search', search)
    else url.searchParams.delete('search')
    if (showRetired) url.searchParams.set('retired', '1')
    else url.searchParams.delete('retired')
    history.replaceState(null, '', url)
  }, [hiddenSeverity, hiddenTriage, hiddenSource, search, showRetired])

  useEffect(() => {
    const restore = () => {
      setHiddenSeverity(hiddenFromUrl('severity', ALL_SEVERITIES, ['3']))
      setHiddenTriage(hiddenFromUrl('triage', ALL_TRIAGE, ['dismissed']))
      setHiddenSource(hiddenFromUrl('source', ALL_SOURCES, []))
      const params = new URLSearchParams(location.search)
      setSearch(params.get('search') ?? '')
      setShowRetired(params.get('retired') === '1')
    }
    window.addEventListener('popstate', restore)
    return () => window.removeEventListener('popstate', restore)
  }, [])

  // Category -> evidence directory (for files) -> artifact -> observations.
  const categories = useMemo(() => {
    const byArtifact = new Map<string, Finding[]>()
    for (const f of data?.findings ?? []) {
      const list = byArtifact.get(f.artifact)
      if (list) list.push(f)
      else byArtifact.set(f.artifact, [f])
    }
    const byCat = new Map<string, CatGroup>()
    for (const row of data?.artifacts ?? []) {
      const items = byArtifact.get(row.artifact) ?? []
      const lead = items[0]
      const cat = categorize(tr, lead?.source ?? row.source, lead?.rule ?? '')
      const artifact: Artifact = { ...row, items, cat }
      let c = byCat.get(cat.id)
      if (!c) {
        c = { cat, artifacts: [], findings: 0, worst: 3, confirmed: 0,
              dismissed: 0, kind: row.artifact_kind }
        byCat.set(cat.id, c)
      }
      c.artifacts.push(artifact)
      c.findings += items.length || row.findings
      c.worst = Math.min(c.worst, row.worst)
      if (row.triage === 'confirmed') c.confirmed += 1
      if (row.triage === 'dismissed') c.dismissed += 1
    }
    return [...byCat.values()].sort((a, b) => a.cat.order - b.cat.order)
  }, [data, tr])
  const reviewQueue = useMemo(() => orderedQueue(categories, roots), [categories, roots])

  useEffect(() => {
    const requested = new URLSearchParams(location.search).get('artifact')
    if (!requested || selected?.artifact === requested) return
    const found = categories.flatMap((category) => category.artifacts)
      .find((artifact) => artifact.artifact === requested)
    if (found) setSelected(found)
  }, [categories, selected?.artifact])

  const openArtifact = (artifact: Artifact) => {
    t.clearCollected()
    setQueueComplete(false)
    setSelected(artifact)
    const url = new URL(location.href)
    url.searchParams.set('artifact', artifact.artifact)
    history.replaceState(null, '', url)
  }

  const closeArtifact = () => {
    setSelected(null)
    t.clearCollected()
    const url = new URL(location.href)
    url.searchParams.delete('artifact')
    history.replaceState(null, '', url)
  }

  const saveView = () => {
    const name = window.prompt(tr('findings.saved.prompt'))?.trim()
    if (!name) return
    const next = savedViews.filter((view) => view.name !== name)
    next.push({
      name,
      hiddenSeverity: [...hiddenSeverity],
      hiddenTriage: [...hiddenTriage],
      hiddenSource: [...hiddenSource],
      search,
      showRetired,
    })
    next.sort((a, b) => a.name.localeCompare(b.name))
    setSavedViews(next)
    localStorage.setItem(savedKey, JSON.stringify(next))
  }

  const applyView = (name: string) => {
    const view = savedViews.find((item) => item.name === name)
    if (!view) return
    setHiddenSeverity(new Set(view.hiddenSeverity))
    setHiddenTriage(new Set(view.hiddenTriage))
    setHiddenSource(new Set(view.hiddenSource))
    setSearch(view.search)
    setShowRetired(view.showRetired)
  }

  // An active filter means: the analyst is looking for something specific.
  // Then the categories stand open, otherwise the hit list would be hidden
  // behind clicks. Without a filter the overview is the purpose -- categories
  // closed. Only the SEARCH opens the categories automatically -- whoever
  // searches wants to see the hits. Hiding is not searching: the overview
  // stays closed.
  const filtering = Boolean(search)

  const items = useMemo(() => {
    const out: Item[] = []
    const addArtifact = (a: Artifact, c: CatGroup, depth: number) => {
      out.push({ t: 'a', a, c, depth })
      if (expanded.has(a.artifact)) {
        for (const f of a.items) out.push({ t: 'f', f, a, depth })
      }
    }
    const addDirectory = (directory: DirectoryNode, c: CatGroup, depth: number) => {
      out.push({ t: 'd', d: directory, depth })
      if (collapsedDirs.has(directory.key)) return
      for (const a of directory.artifacts) addArtifact(a, c, depth + 1)
      for (const child of directory.children) addDirectory(child, c, depth + 1)
    }
    for (const c of categories) {
      out.push({ t: 'c', c })
      const catOpen = filtering ? !collapsedCats.has(c.cat.id) : expandedCats.has(c.cat.id)
      if (!catOpen) continue
      const tree = directoryForest(c.artifacts, roots, c.cat.id)
      for (const a of tree.directories.length
        ? tree.direct.filter((artifact) => artifact.artifact_kind !== 'file')
        : tree.direct) addArtifact(a, c, 0)
      for (const directory of tree.directories) addDirectory(directory, c, 0)
      if (tree.directories.length) {
        for (const a of tree.direct.filter((artifact) => artifact.artifact_kind === 'file')) {
          addArtifact(a, c, 0)
        }
      }
    }
    return out
  }, [categories, roots, expanded, collapsedCats, collapsedDirs, expandedCats, filtering])


  /** Checked artifacts, otherwise the one under the cursor. */
  const bulkTriage = (state: string) => {
    const at = items[cursor]
    const names = checked.size
      ? [...checked]
      : (isArtifactRow(at) ? [(at as { a: Artifact }).a.artifact] : [])
    if (names.length) t.decide(names, state, bulkNote)
  }

  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (i) => {
      const kind = items[i]?.t
      return kind === 'c' ? 62 : kind === 'd' ? 42 : kind === 'a' ? 68 : 34
    },
    overscan: 20,
  })

  // Keyboard: j/k over artifact rows, x checks, c/d/r decide and move on,
  // ? shows the bindings
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (selected || viewing || traceIps || e.target instanceof HTMLInputElement ||
          e.target instanceof HTMLTextAreaElement) return
      if (e.key === '?') {
        setHelpOpen((v) => !v)
        e.preventDefault()
        return
      }
      if (helpOpen || !items.length) return
      const move = (dir: 1 | -1) => {
        let i = cursor + dir
        while (i >= 0 && i < items.length && !isArtifactRow(items[i])) i += dir
        if (i >= 0 && i < items.length) setCursor(i)
      }
      if (e.key === 'j') move(1)
      else if (e.key === 'k') move(-1)
      else if (e.key === 'Enter') {
        const it = items[cursor]
        if (isArtifactRow(it)) {
          t.clearCollected()
          openArtifact((it as { a: Artifact }).a)
        }
      } else if (e.key === 'x') {
        const it = items[cursor]
        if (isArtifactRow(it)) {
          const name = (it as { a: Artifact }).a.artifact
          const next = new Set(checked)
          if (next.has(name)) next.delete(name)
          else next.add(name)
          setChecked(next)
        }
      } else if (e.key === 'c' || e.key === 'd' || e.key === 'r') {
        bulkTriage(e.key === 'c' ? 'confirmed' : e.key === 'd' ? 'dismissed' : 'reviewed')
        // The hand stays on the keyboard: after the decision the cursor
        // moves on to the next artifact that still needs one. Only for the
        // single-row decision -- a bulk decision has no single "next".
        if (!checked.size) {
          let i = cursor + 1
          while (i < items.length) {
            const it = items[i]
            if (isArtifactRow(it)) {
              const triage = (it as { a: Artifact }).a.triage
              if (triage === 'new' || triage === 'reviewed') break
            }
            i += 1
          }
          if (i < items.length) setCursor(i)
        }
      } else return
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, cursor, selected, viewing, traceIps, checked, bulkNote, helpOpen])

  useEffect(() => { virtualizer.scrollToIndex(cursor) }, [cursor, virtualizer])

  const toggleArtifact = (a: Artifact) => {
    const next = new Set(expanded)
    if (next.has(a.artifact)) next.delete(a.artifact)
    else next.add(a.artifact)
    setExpanded(next)
  }

  const toggleCategory = (c: CatGroup) => {
    if (filtering) {
      const next = new Set(collapsedCats)
      if (next.has(c.cat.id)) next.delete(c.cat.id)
      else next.add(c.cat.id)
      setCollapsedCats(next)
    } else {
      const next = new Set(expandedCats)
      if (next.has(c.cat.id)) next.delete(c.cat.id)
      else next.add(c.cat.id)
      setExpandedCats(next)
    }
  }

  const toggleCategoryChecked = (c: CatGroup) => {
    const names = c.artifacts.map((a) => a.artifact)
    const all = names.every((n) => checked.has(n))
    const next = new Set(checked)
    for (const n of names) { if (all) next.delete(n); else next.add(n) }
    setChecked(next)
  }

  const counts = data?.counts
  const filterCount = hiddenSeverity.size + hiddenTriage.size + hiddenSource.size + (showRetired ? 1 : 0)

  return (
    <div className="flex h-[calc(100vh-150px)] flex-col gap-3 md:h-[calc(100vh-110px)]">
      <div className="flex flex-wrap items-center gap-3">
        <div className="mr-auto min-w-48">
          <Tooltip title={tr('dashboard.artifacts')}
            body={tr('findings.title.body')}
            hint={tr('findings.title.hint')}>
            <h1 className="text-lg font-bold">{tr('nav.findings')}</h1>
          </Tooltip>
          <div className="mt-0.5 text-[11px] text-[var(--muted)]">
            {tr('findings.count', {
              artifacts: formatCount(data?.total ?? 0),
              findings: formatCount(data?.findings_total ?? 0),
              categories: formatCount(categories.length),
            })}
          </div>
        </div>
        <div className="min-w-[16rem] flex-1 sm:max-w-md">
          <SearchInput value={search} onChange={setSearch} placeholder={tr('findings.search')} />
        </div>
        <Button onClick={() => setFiltersOpen((open) => !open)}
          aria-expanded={filtersOpen} aria-controls="findings-filter-panel">
          <ListFilter size={14} /> {tr('findings.filters', { n: filterCount })}
        </Button>
        <div className="flex items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel)] p-1">
          <span className="pl-2 text-[11px] font-semibold text-[var(--muted)]">{tr('findings.views')}</span>
          {savedViews.length > 0 && (
            <select defaultValue="" aria-label={tr('findings.saved.views')}
              onChange={(event) => { applyView(event.target.value); event.target.value = '' }}
              className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-2 py-1.5 text-[12px] text-[var(--muted)] outline-none">
              <option value="" disabled>{tr('findings.saved.views')}</option>
              {savedViews.map((view) => <option key={view.name} value={view.name}>{view.name}</option>)}
            </select>
          )}
          <Button variant="ghost" onClick={saveView} title={tr('findings.saved.save')}>
            <BookmarkPlus size={14} /> {tr('findings.saved.save')}
          </Button>
        </div>
        <Button variant="ghost" onClick={() => setHelpOpen(true)}>
          <Keyboard size={14} /> {tr('findings.shortcuts')}
        </Button>
      </div>

      {filtersOpen && (
        <Card id="findings-filter-panel" surface="raised" className="grid gap-4 p-4 sm:grid-cols-3 animate-fade-up">
          <FilterGroup title={tr('findings.filter.severity')}>
            {([['0', 'High', 'var(--sev-high)'], ['1', 'Medium', 'var(--sev-medium)'],
               ['2', 'Low', 'var(--sev-low)'], ['3', 'Info', 'var(--muted)']] as const
            ).map(([value, label, color]) => (
              <FilterCheck key={value} checked={!hiddenSeverity.has(value)} label={label}
                count={counts?.severity[value] ?? 0} color={color}
                onChange={() => setHiddenSeverity((previous) => toggleHidden(previous, value))} />
            ))}
          </FilterGroup>
          <FilterGroup title={tr('findings.filter.decision')}>
            {ALL_TRIAGE.map((state) => (
              <FilterCheck key={state} checked={!hiddenTriage.has(state)}
                label={tr(`triage.${state}`)} count={counts?.triage[state] ?? 0}
                onChange={() => setHiddenTriage((previous) => toggleHidden(previous, state))} />
            ))}
          </FilterGroup>
          <FilterGroup title={tr('findings.filter.source')}>
            {ALL_SOURCES.map((source) => (
              <FilterCheck key={source} checked={!hiddenSource.has(source)}
                label={tr(`source.${source}`)} count={counts?.source[source] ?? 0}
                onChange={() => setHiddenSource((previous) => toggleHidden(previous, source))} />
            ))}
            <FilterCheck checked={showRetired} label={tr('findings.filter.retired')}
              onChange={() => setShowRetired((shown) => !shown)} />
          </FilterGroup>
          <div className="flex flex-wrap items-center gap-3 border-t border-[var(--line-soft)] pt-3 sm:col-span-3">
            <span className="text-[11px] text-[var(--muted)]">{tr('findings.filterMeaning')}</span>
            <button className="cursor-pointer font-semibold text-[var(--accent-text)] hover:underline"
              onClick={() => {
                setHiddenSeverity(new Set())
                setHiddenTriage(new Set())
                setHiddenSource(new Set())
              }}>
              {tr('findings.showAll')}
            </button>
            <button className="cursor-pointer font-semibold text-[var(--accent-text)] hover:underline"
              onClick={() => {
                setHiddenSeverity(new Set(['3']))
                setHiddenTriage(new Set(['dismissed']))
                setHiddenSource(new Set())
                setSearch('')
                setShowRetired(false)
              }}>
              {tr('findings.resetFilters')}
            </button>
          </div>
        </Card>
      )}

      {/* A rule that was switched off takes artifacts with it. That has to
          be said: the analyst who muted a rule three cases ago will not
          remember, and a work list that is quietly short reads like a clean
          system. */}
      {data && data.muted_hidden > 0 && (
        <Card className="flex items-center gap-2.5 border-[var(--sev-low)]/40 bg-[var(--panel-2)] px-4 py-2.5 text-[12.5px]">
          <BellOff size={14} className="shrink-0 text-[var(--sev-low)]" />
          <span className="min-w-0 flex-1">
            {tr('findings.muted', {
              n: formatCount(data.muted_hidden),
              rules: formatCount(data.muted_rules),
            })}
          </span>
          <button
            className="shrink-0 cursor-pointer font-semibold text-[var(--accent-text)] hover:underline"
            onClick={() => gotoView('settings')}>
            {tr('findings.muted.cta')}
          </button>
        </Card>
      )}

      {/* The same duty for the other way an artifact leaves this list: the
          last completed scan did not reproduce any of its findings and
          nobody had decided about it. Different sentence than the muted one
          on purpose -- a switch and a disappearance send the analyst to
          different places. */}
      {data && data.retired_hidden > 0 && (
        <Card className="flex items-center gap-2.5 border-[var(--sev-low)]/40 bg-[var(--panel-2)] px-4 py-2.5 text-[12.5px]">
          <CircleDashed size={14} className="shrink-0 text-[var(--muted)]" />
          <span className="min-w-0 flex-1">
            {showRetired
              ? tr('findings.retiredShown', { n: formatCount(data.retired_hidden) })
              : tr('findings.retiredHidden', { n: formatCount(data.retired_hidden) })}
          </span>
          <button
            className="shrink-0 cursor-pointer font-semibold text-[var(--accent-text)] hover:underline"
            onClick={() => setShowRetired((v) => !v)}>
            {showRetired ? tr('findings.retired.hide') : tr('findings.retired.show')}
          </button>
        </Card>
      )}

      {!search && data && counts != null && counts.total > data.total && (
        <div className="flex flex-wrap items-center gap-2 text-[12px] text-[var(--muted)]">
          <span className="opacity-70">
            {tr('findings.hidden', { n: formatCount(counts.total - data.total) })}
          </span>
        </div>
      )}

      {checked.size > 0 ? (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-4 py-2 animate-fade-up">
          <span className="text-[13px] font-semibold">
            {tr('findings.selected', { n: formatCount(checked.size) })}
          </span>
          <Button variant="incident" onClick={() => bulkTriage('confirmed')}>
            <Check size={14} /> {tr('artifact.truePositiveCollect')}
          </Button>
          <Button variant="review" onClick={() => bulkTriage('reviewed')}>
            <Eye size={14} /> {tr('triage.reviewed')}
          </Button>
          <Button variant="outline" onClick={() => bulkTriage('dismissed')}>
            <X size={14} /> {tr('triage.dismissed')}
          </Button>
          <input
            value={bulkNote}
            onChange={(e) => setBulkNote(e.target.value)}
            placeholder={tr('findings.bulkNote')}
            className="min-w-56 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
          <Button variant="ghost" onClick={() => setChecked(new Set())}>{tr('common.clearSelection')}</Button>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--muted)]">
          {/* A LIST THAT QUIETLY SHRINKS IS A LIST NOBODY CAN TRUST. The
              request is capped at 2000 while the count beside it describes
              the whole set, so above that the header stated a number the
              list did not contain and said nothing about it. */}
          {data && data.total > LIST_CAP && (
            <span className="rounded-md bg-[var(--sev-low)]/15 px-1.5 py-0.5
                             text-[var(--sev-low)]">
              {tr('findings.capped', { n: formatCount(LIST_CAP) })}
            </span>
          )}
          <button
            className="cursor-pointer rounded px-1.5 py-0.5 hover:bg-[var(--panel-2)] hover:text-[var(--fg)]"
            onClick={() => {
              const allIds = categories.map((c) => c.cat.id)
              const allOpen = filtering
                ? collapsedCats.size === 0
                : expandedCats.size === allIds.length
              if (filtering) setCollapsedCats(allOpen ? new Set(allIds) : new Set())
              else setExpandedCats(allOpen ? new Set() : new Set(allIds))
            }}>
            {tr('findings.toggleAll')}
          </button>
        </div>
      )}

      {/* No `flex-1`: the box is as tall as its content and only shrinks
          when the list grows longer than the space. Stretched to the full
          height, an empty area used to stand below the last row that looked
          as if something were missing there. */}
      <div ref={parentRef}
        className="min-h-0 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--panel)]">
        {items.length === 0 && (
          <EmptyState icon={<Bug size={36} />} title={tr('findings.empty.title')}
            sub={data ? tr('findings.empty') : tr('common.loading')} />
        )}
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {virtualizer.getVirtualItems().map((vi) => {
            const item = items[vi.index]
            const style = { height: vi.size, transform: `translateY(${vi.start}px)` }

            // ---- Ebene 1: Kategorie ----
            if (item.t === 'c') {
              const c = item.c
              const names = c.artifacts.map((a) => a.artifact)
              const allChecked = names.length > 0 && names.every((n) => checked.has(n))
              const someChecked = !allChecked && names.some((n) => checked.has(n))
              const open = filtering
                ? !collapsedCats.has(c.cat.id)
                : expandedCats.has(c.cat.id)
              const decided = c.confirmed + c.dismissed
              const tint = SEVERITY_VAR[c.worst]
              const CatIcon = CATEGORY_ICON[c.cat.id] ?? Bug
              return (
                <div key={'c' + c.cat.id}
                  className={clsx(
                    'absolute left-0 top-0 flex w-full items-center gap-2 pr-2 sm:gap-3 sm:pr-4',
                    'border-y border-[var(--line)]',
                    // The rule above only when a category is currently
                    // CLOSED -- when open it flows into its artifacts.
                    open ? 'border-b-transparent' : '')}
                  style={{
                    ...style,
                    // A hint of the severity running off to the right: the
                    // category stands out from the rest without a full
                    // colour field drowning the names below it.
                    background:
                      `linear-gradient(90deg, color-mix(in srgb, ${tint} 13%, var(--panel-2)) 0%,` +
                      ' var(--panel-2) 55%)',
                  }}>
                  <span className="h-full w-1 shrink-0" style={{ background: tint }} />
                  <input type="checkbox" className="ml-1 cursor-pointer accent-[var(--accent)]"
                    checked={allChecked}
                    ref={(el) => { if (el) el.indeterminate = someChecked }}
                    onChange={() => toggleCategoryChecked(c)}
                    title={tr('findings.checkCategory')} />
                  <button onClick={() => toggleCategory(c)}
                    aria-label={open ? tr('findings.collapse') : tr('findings.expand')}
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-1.5 text-left sm:gap-3">
                    {open
                      ? <ChevronDown size={16} className="shrink-0 text-[var(--muted)]" />
                      : <ChevronRight size={16} className="shrink-0 text-[var(--muted)]" />}
                    <span className="hidden h-9 w-9 shrink-0 items-center justify-center rounded-xl sm:flex"
                      style={{ background: `color-mix(in srgb, ${tint} 20%, transparent)`,
                               color: tint }}>
                      <CatIcon size={17} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-[14.5px] font-semibold tracking-tight">
                          {c.cat.label}
                        </span>
                        <InfoDot body={c.cat.what} wide />
                      </div>
                      <div className="truncate text-[11.5px] text-[var(--muted)]">
                        <span className="font-medium text-[var(--fg)]">
                          {formatCount(c.artifacts.length)}{' '}
                          {artifactNoun(tr, c.kind, c.artifacts.length)}
                        </span>
                        {' '}{tr('findings.fromN', { n: formatCount(c.findings) })}
                        {decided > 0 && ` · ${tr('findings.decided', { n: decided })}`}
                      </div>
                    </div>
                  </button>
                  <SeverityBadge severity={c.worst} />
                  {/* Progress: how much of this category is decided? */}
                  <Tooltip
                    title={tr('findings.progress', { decided, total: c.artifacts.length })}
                    hint={`${c.confirmed} True Positive · ${c.dismissed} False Positive · ${tr('findings.open', { n: c.artifacts.length - decided })}`}>
                    <div className="flex w-auto shrink-0 items-center gap-2 sm:w-24">
                      <span className="hidden h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--panel)] sm:flex">
                        {c.confirmed > 0 && (
                          <span style={{ width: `${(c.confirmed / c.artifacts.length) * 100}%`,
                                         background: 'var(--sev-high)' }} />
                        )}
                        {c.dismissed > 0 && (
                          <span style={{ width: `${(c.dismissed / c.artifacts.length) * 100}%`,
                                         background: 'var(--muted)' }} />
                        )}
                      </span>
                      <span className="shrink-0 text-[11px] text-[var(--muted)] tabular">
                        {decided}/{c.artifacts.length}
                      </span>
                    </div>
                  </Tooltip>
                </div>
              )
            }

            // ---- level 2: evidence directory ----
            if (item.t === 'd') {
              const open = !collapsedDirs.has(item.d.key)
              const tint = SEVERITY_VAR[item.d.worst]
              return (
                <div key={'d' + item.d.key}
                  className="absolute left-0 top-0 flex w-full items-center gap-2 border-b border-[var(--line-soft)] pr-2 text-[12px] hover:bg-[var(--panel-2)] sm:pr-4"
                  style={style}>
                  <span className="h-full w-1 shrink-0 opacity-25" style={{ background: tint }} />
                  <span className="hidden shrink-0 sm:block"
                    style={{ width: `${item.depth * 18 + 32}px` }} />
                  <span className="w-1 shrink-0 sm:hidden" />
                  <button
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 rounded py-1 text-left"
                    aria-label={open
                      ? tr('findings.folder.collapse', { name: item.d.name })
                      : tr('findings.folder.expand', { name: item.d.name })}
                    onClick={() => setCollapsedDirs((previous) => {
                      const next = new Set(previous)
                      if (next.has(item.d.key)) next.delete(item.d.key)
                      else next.add(item.d.key)
                      return next
                    })}>
                    {open ? <ChevronDown size={13} className="shrink-0 text-[var(--muted)]" />
                      : <ChevronRight size={13} className="shrink-0 text-[var(--muted)]" />}
                    {open ? <FolderOpen size={15} className="shrink-0 text-[var(--accent)]" />
                      : <Folder size={15} className="shrink-0 text-[var(--muted)]" />}
                    <span className="mono truncate font-medium">{item.d.name}</span>
                    {item.d.path !== item.d.name && (
                      <span className="hidden truncate text-[10.5px] text-[var(--muted)] sm:inline">
                        {item.d.path}
                      </span>
                    )}
                    <span className="ml-auto shrink-0 text-[10.5px] text-[var(--muted)] tabular">
                      {tr('findings.folder.files', { n: formatCount(item.d.count) })}
                    </span>
                  </button>
                </div>
              )
            }

            // ---- next level: the artifact -- the unit decisions are about ----
            if (item.t === 'a') {
              const a = item.a
              const Icon = KIND_ICON[a.artifact_kind] ?? Bug
              const open = expanded.has(a.artifact)
              const tint = SEVERITY_VAR[a.worst]
              return (
                <div key={'a' + a.artifact}
                  className={clsx(
                    'group absolute left-0 top-0 flex w-full items-center gap-2.5 border-b border-[var(--line-soft)] pr-3',
                    'transition-colors hover:bg-[var(--panel-2)]',
                    vi.index === cursor && 'bg-[var(--accent-soft)]',
                    // Dimmed means DONE, not unimportant: a confirmed
                    // artifact stays but recedes visually, so that what is
                    // still open leads the list.
                    a.triage === 'confirmed' && 'opacity-45',
                    // Greyer still: nothing here was seen again by the last
                    // completed scan. The row is a record, not work.
                    a.findings === 0 && a.retired > 0 && 'opacity-35')}
                  style={style}>
                  <span className="h-full w-1 shrink-0 opacity-40" style={{ background: tint }} />
                  <span className="hidden shrink-0 sm:block" style={{ width: `${item.depth * 18}px` }} />
                  <input type="checkbox" className="ml-1 cursor-pointer accent-[var(--accent)] sm:ml-4"
                    checked={checked.has(a.artifact)}
                    onChange={(e) => {
                      const next = new Set(checked)
                      if (e.target.checked) next.add(a.artifact)
                      else next.delete(a.artifact)
                      setChecked(next)
                    }} />
                  <Tooltip hint={open ? tr('findings.collapse') : tr('findings.expand')}>
                    <button onClick={() => toggleArtifact(a)}
                      aria-label={open ? tr('findings.collapse') : tr('findings.expand')}
                      className="shrink-0 cursor-pointer rounded p-0.5 text-[var(--muted)] hover:text-[var(--fg)]">
                      {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </button>
                  </Tooltip>
                  <button
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-3 text-left"
                    onClick={() => {
                      setCursor(vi.index)
                      // The collect result belongs to THE action that produced
                      // it -- opening another artifact expires it, otherwise it
                      // reads as a result for this one.
                      openArtifact(a)
                    }}>
                    {/* The artifact kind as an icon, tinted by severity: a file
                        looks different from a client, and red stands out of a
                        list. */}
                    <span className="hidden h-8 w-8 shrink-0 items-center justify-center rounded-lg sm:flex"
                      style={{ background: `color-mix(in srgb, ${tint} 16%, transparent)`,
                               color: tint }}>
                      <Icon size={15} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 items-center gap-2">
                        <ArtifactName artifact={a.artifact} kind={a.artifact_kind} roots={roots} />
                        <TriageBadge state={a.triage} label={tr(`triage.${a.triage}`)} />
                        {/* A decided thing that was then not seen again must
                            say so right here -- a confirmed shell that is no
                            longer on disk looking identical to one that is
                            was the measured hole. */}
                        {a.findings === 0 && a.retired > 0 && (
                          <span className="shrink-0 rounded border border-[var(--border)] px-1.5 py-0.5 text-[10.5px] text-[var(--muted)]">
                            {tr('findings.retiredBadge')}
                          </span>
                        )}
                      </div>
                      <RuleChips items={a.items} />
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <SeverityBadge severity={a.worst} />
                      <span className="hidden text-[10.5px] text-[var(--muted)] tabular sm:inline">
                        {tr(a.findings === 1 ? 'findings.observation.one' : 'findings.observation.many', {
                          n: formatCount(a.findings),
                        })}
                      </span>
                    </div>
                  </button>
                  <div className="hidden shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100 sm:flex">
                    {a.artifact_kind === 'file' && (
                      <Tooltip hint={tr('findings.viewFile.hint')}>
                        <button
                          aria-label={tr('findings.viewFile.hint')}
                          className="cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel)] hover:text-[var(--accent)]"
                          onClick={() => setViewing({ path: a.artifact, line: a.items[0]?.line ?? null })}>
                          <FileSearch size={15} />
                        </button>
                      </Tooltip>
                    )}
                    {a.artifact_kind === 'client' && (
                      <Tooltip hint={tr('findings.trace.hint')}>
                        <button
                          aria-label={tr('findings.trace.hint')}
                          className="cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel)] hover:text-[var(--accent)]"
                          onClick={() => setTraceIps([a.artifact])}>
                          <Crosshair size={15} />
                        </button>
                      </Tooltip>
                    )}
                  </div>
                </div>
              )
            }

            // ---- final level: a finding as REASONING, not as a decision ----
            const f = item.f
            return (
              <div key={f.fingerprint}
                className={clsx(
                  'absolute left-0 top-0 flex w-full items-center gap-2.5 border-b border-[var(--line-soft)] pr-4',
                  item.a.triage === 'confirmed' && 'opacity-45')}
                style={style}>
                {/* The guide line keeps the findings visibly attached to
                    their artifact -- indented text alone loses the tie. */}
                <span className="shrink-0" style={{ width: `${item.depth * 18}px` }} />
                <span className="ml-[3.25rem] h-full w-px shrink-0 bg-[var(--line)]" />
                <span className="h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ background: SEVERITY_VAR[f.severity] }} />
                <RuleName rule={f.rule} className="w-[30%] min-w-0 shrink-0" />
                {f.line != null && f.line !== 0 && (
                  <span className="shrink-0 text-[11px] text-[var(--muted)] tabular">Z. {f.line}</span>
                )}
                <span className="mono min-w-0 flex-1 truncate text-[11.5px] text-[var(--muted)]"
                  title={f.evidence}>
                  {f.evidence}
                </span>
              </div>
            )
          })}
        </div>
      </div>

      {/* All three are centred windows; the level says what lies in front.
          Trace and file viewer are opened FROM the artifact window and are
          one step smaller -- one sees at the edge where one comes back
          to. */}
      <ArtifactWindow
        slug={slug}
        artifact={selected}
        roots={roots}
        collected={t.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips, m) => { setTraceMarks(m); setTraceIps(ips) }}
        onClose={closeArtifact}
        onSave={(state, note) => {
          if (!selected) return Promise.reject(new Error('No artifact selected'))
          return t.decideAsync([selected.artifact], state, note)
        }}
        onSavedNext={(result) => {
          if (!selected || result.updated === 0) return
          const next = nextReviewArtifact(
            reviewQueue, selected.artifact, result.linked.map((link) => link.artifact))
          if (next) openArtifact(next)
          else {
            closeArtifact()
            setQueueComplete(true)
          }
        }}
      />

      <Toast open={queueComplete} onClose={() => setQueueComplete(false)} tone="ok"
        title={tr('findings.queueComplete.title')}>
        {tr('findings.queueComplete.body')}
      </Toast>

      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />

      <FileViewer
        slug={slug}
        path={viewing?.path ?? null}
        focusLine={viewing?.line}
        layer={2}
        onClose={() => setViewing(null)}
      />

      <TriageFollowUp t={t} roots={roots} onOpenIocs={() => gotoView('iocbox')} />

      {/* The bindings on demand -- the footer names them, but a footer
          under 2000 rows is off-screen exactly when one wonders what `r`
          did. `?` is the convention every list tool shares. */}
      <Modal open={helpOpen} onClose={() => setHelpOpen(false)}
        title={tr('findings.help.title')}>
        <div className="flex flex-col gap-1.5 text-[13px]">
          {([
            ['j / k', tr('findings.help.navigate')],
            ['Enter', tr('findings.help.open')],
            ['x', tr('findings.help.check')],
            ['c', tr('triage.confirmed')],
            ['d', tr('triage.dismissed')],
            ['r', tr('triage.reviewed')],
            ['?', tr('findings.help.this')],
            ['Esc', tr('findings.help.close')],
          ] as const).map(([key, what]) => (
            <div key={key} className="flex items-baseline gap-3">
              <kbd className="w-16 shrink-0 rounded bg-[var(--panel-2)] px-1.5 py-0.5 text-center text-[12px]">
                {key}
              </kbd>
              <span>{what}</span>
            </div>
          ))}
          <p className="mt-2 text-[12px] text-[var(--muted)]">
            {tr('findings.help.decide')}
          </p>
        </div>
      </Modal>
    </div>
  )
}

function FilterGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <fieldset className="min-w-0">
      <legend className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
        {title}
      </legend>
      <div className="flex flex-col gap-1">{children}</div>
    </fieldset>
  )
}

function FilterCheck({ checked, label, count, color, onChange }: {
  checked: boolean
  label: string
  count?: number
  color?: string
  onChange: () => void
}) {
  return (
    <label className={clsx(
      'flex cursor-pointer items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[12px] transition-colors',
      checked
        ? 'border-[var(--line-strong)] bg-[var(--panel)] text-[var(--fg)]'
        : 'border-transparent text-[var(--muted)] hover:bg-[var(--panel)]',
    )}>
      <input type="checkbox" checked={checked} onChange={onChange}
        className="h-3.5 w-3.5 cursor-pointer accent-[var(--accent)]" />
      {color && <span className="h-2 w-2 rounded-full" style={{ background: color }} />}
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {count != null && <span className="tabular text-[10.5px] text-[var(--muted)]">{formatCount(count)}</span>}
    </label>
  )
}

/** The leading reason explains why the artifact is here. Supporting reasons
 *  remain available in the expanded row and detail window. */
function RuleChips({ items }: { items: Finding[] }) {
  const tr = useT()
  if (!items.length) return null
  const shown = items.slice(0, 1)
  const rest = items.length - shown.length
  return (
    <div className="mt-0.5 flex min-w-0 items-center gap-1 overflow-hidden">
      {shown.map((f) => {
        const e = explainRule(tr, f.rule)
        return (
          <Tooltip key={f.fingerprint} title={f.rule} body={e?.what} hint={e?.why} wide>
            <span className="max-w-[15rem] truncate rounded bg-[var(--panel-2)] px-1.5 py-px text-[10.5px] text-[var(--muted)]"
              style={{ boxShadow: `inset 2px 0 0 ${SEVERITY_VAR[f.severity]}` }}>
              {f.rule}
            </span>
          </Tooltip>
        )
      })}
      {rest > 0 && (
        <span className="shrink-0 text-[10.5px] text-[var(--muted)]">
          {tr(rest === 1 ? 'findings.moreObservation.one' : 'findings.moreObservation.many', {
            n: formatCount(rest),
          })}
        </span>
      )}
    </div>
  )
}

/** The rule name with its plain-language explanation in the tooltip. */
function RuleName({ rule, className }: { rule: string; className?: string }) {
  const tr = useT()
  const e = explainRule(tr, rule)
  return (
    <Tooltip title={rule} body={e?.what} hint={e?.why} wide
      className={clsx('truncate text-[12.5px] font-medium', className)}>
      <span className="truncate">{rule}</span>
    </Tooltip>
  )
}

/** An artifact named the way a human thinks of it: for files ONLY the path
 *  below the evidence (`images/shell.php`) -- that is the fact that goes into
 *  the report and that one finds again on the server. The full path and the
 *  evidence the file sits under stand in the tooltip. */
function ArtifactName({ artifact, kind, roots }: {
  artifact: string; kind: string; roots: EvidenceRoot[]
}) {
  const tr = useT()
  if (kind !== 'file') {
    return (
      <span className="mono min-w-0 truncate text-[13px] font-semibold">{artifact}</span>
    )
  }
  const { root, rel } = relativeToRoot(artifact, roots)
  const rootName = root
    ? (root.label?.trim() ||
       root.path.replace(/\\/g, '/').replace(/\/+$/, '').split('/').pop())
    : null
  const displayName = root ? rel : shortPath(artifact, 80)
  const leafName = displayName.replace(/\\/g, '/').split('/').pop() || displayName
  return (
    <Tooltip wide className="min-w-0"
      title={rootName ? tr('findings.under', { root: rootName }) : tr('findings.fullPath')}
      body={<span className="mono break-all">{artifact}</span>}>
      <span className="mono min-w-0 truncate text-[13px] font-semibold">
        <span className="sm:hidden">{leafName}</span>
        <span className="hidden sm:inline">{displayName}</span>
      </span>
    </Tooltip>
  )
}
