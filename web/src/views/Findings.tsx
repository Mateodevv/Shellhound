// Findings.tsx — jedes Finding jeder Engine, GRUPPIERT nach Artefakt:
// eine Datei/Tabelle/Client ist EINE Gruppe, ihre Findings hängen darunter.
// Gruppen und Zeilen sind markierbar; Bulk-Triage über die Aktionsleiste.
// Der Drawer holt sich den vollen Kontext (Datei-Preview um die Fundzeile,
// Hash/Guard/Upload-Dir, Actor-Profil, Geschwister-Findings), damit ein
// Finding an Ort und Stelle eingeschätzt werden kann.
import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  Bug, Check, ChevronDown, ChevronRight, Copy, Crosshair, Eye, FileCode2,
  FileSearch, ServerCog, ShieldCheck, ShieldOff, Table2, Users, X,
} from 'lucide-react'
import clsx from 'clsx'
import {
  api, downloadUrl, post, type Finding, type FindingContext,
  type FindingsResponse, type TraceRow,
} from '../api'
import {
  SOURCE_LABEL, TRIAGE_LABEL, absoluteTime, formatBytes, formatCount, formatDay,
  formatLogTime, relativeTime, relativeToRoot, shortPath, type EvidenceRoot,
} from '../format'
import {
  Button, Chip, Drawer, EmptyState, SearchInput, SeverityBadge, Tag, TriageBadge,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { FileViewer } from '../components/FileViewer'
import {
  FIELD_EXPLAIN, artifactNoun, categorize, explainRule, type Category,
} from '../explain'
import type { ViewId } from '../App'

const KIND_ICON: Record<string, typeof Bug> = {
  file: FileCode2, table: Table2, client: Users, dump: ServerCog,
}

const KIND_LABEL: Record<string, string> = {
  file: 'Datei', table: 'Tabelle', client: 'Client', dump: 'Dump',
}

interface Group {
  artifact: string
  kind: string
  findings: Finding[]
  worst: number
}

interface CatGroup {
  cat: Category
  groups: Group[]
  findings: number
  worst: number
  confirmed: number
  dismissed: number
  kind: string          // vorherrschende Artefakt-Art, für "12 Dateien"
}

// Zeilentypen der virtualisierten Liste. `single` ist ein Artefakt mit genau
// EINEM Finding: zwei Zeilen für eine Aussage wären nur Höhe ohne Inhalt.
type Item =
  | { t: 'c'; c: CatGroup }
  | { t: 'g'; g: Group; c: CatGroup }
  | { t: 'f'; f: Finding; g: Group }
  | { t: 'single'; f: Finding; g: Group; c: CatGroup }

const isFindingRow = (i?: Item) => i?.t === 'f' || i?.t === 'single'

interface TriageResult {
  updated: number
  collected: { value: string; type: string; hits?: number; ok_hits?: number }[]
}

export function Findings({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const qc = useQueryClient()
  const [severity, setSeverity] = useState('')
  const [triage, setTriage] = useState('')
  const [source, setSource] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [cursor, setCursor] = useState(0)
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  // Zwei Mengen statt einer: ohne Filter sind Kategorien ZU (Übersicht) und
  // `expandedCats` sagt, was offen ist; mit Filter sind sie AUF und
  // `collapsedCats` sagt, was zu ist. So bleibt beides jeweils die Ausnahme,
  // die der Analyst selbst gesetzt hat.
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set())
  const [collapsedCats, setCollapsedCats] = useState<Set<string>>(new Set())
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [bulkNote, setBulkNote] = useState('')
  const [lastCollected, setLastCollected] = useState<TriageResult['collected']>([])
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [hideConfirmed, setHideConfirmed] = useState(true)
  const [hideInfo, setHideInfo] = useState(true)

  const query = useMemo(() => {
    const p = new URLSearchParams()
    if (severity !== '') p.set('severity', severity)
    if (triage) p.set('triage', triage)
    if (source) p.set('source', source)
    if (search) p.set('search', search)
    // Die Liste zeigt standardmäßig, was noch ARBEIT ist: Entschiedenes und
    // reiner Kontext fallen raus, bis man sie anfordert. Ein gesetzter Chip
    // hebt das jeweils auf — wer "Bestätigt" filtert, will sie sehen.
    if (hideConfirmed && !triage) p.set('hide_confirmed', '1')
    if (hideInfo && severity === '') p.set('hide_info', '1')
    p.set('limit', '2000')
    return p.toString()
  }, [severity, triage, source, search, hideConfirmed, hideInfo])

  const { data } = useQuery({
    queryKey: ['findings', slug, query],
    queryFn: () => api<FindingsResponse>(`/api/cases/${slug}/findings?${query}`),
  })
  const rows = useMemo(() => data?.findings ?? [], [data])
  const roots: EvidenceRoot[] = useMemo(() => data?.roots ?? [], [data])

  // fingerprint -> Finding, damit Geschwister im Drawer anklickbar sind
  const byFp = useMemo(() => {
    const m = new Map<string, Finding>()
    for (const f of rows) m.set(f.fingerprint, f)
    return m
  }, [rows])

  // Zwei Ebenen: Kategorie ("Webshells & Backdoors") -> Artefakt (die Datei,
  // der Client) -> die einzelnen Findings.
  const categories = useMemo(() => {
    const byCat = new Map<string, CatGroup>()
    for (const f of rows) {
      const cat = categorize(f.source, f.rule)
      let c = byCat.get(cat.id)
      if (!c) {
        c = { cat, groups: [], findings: 0, worst: 2, confirmed: 0, dismissed: 0,
              kind: f.artifact_kind }
        byCat.set(cat.id, c)
      }
      let g = c.groups.find((x) => x.artifact === f.artifact)
      if (!g) {
        g = { artifact: f.artifact, kind: f.artifact_kind, findings: [], worst: 2 }
        c.groups.push(g)
      }
      g.findings.push(f)
      g.worst = Math.min(g.worst, f.severity)
      c.findings += 1
      c.worst = Math.min(c.worst, f.severity)
      if (f.triage === 'confirmed') c.confirmed += 1
      if (f.triage === 'dismissed') c.dismissed += 1
    }
    const list = [...byCat.values()]
    for (const c of list) {
      c.groups.sort((a, b) => a.worst - b.worst || a.artifact.localeCompare(b.artifact))
    }
    return list.sort((a, b) => a.cat.order - b.cat.order)
  }, [rows])

  // Ein aktiver Filter bedeutet: der Analyst sucht etwas Bestimmtes. Dann
  // stehen die Kategorien offen, sonst wäre die Trefferliste hinter Klicks
  // versteckt. Ohne Filter ist die Übersicht der Zweck — Kategorien zu.
  const filtering = Boolean(severity !== '' || triage || source || search)

  const items = useMemo(() => {
    const out: Item[] = []
    for (const c of categories) {
      out.push({ t: 'c', c })
      const catOpen = filtering ? !collapsedCats.has(c.cat.id) : expandedCats.has(c.cat.id)
      if (!catOpen) continue
      for (const g of c.groups) {
        if (g.findings.length === 1) {
          out.push({ t: 'single', f: g.findings[0], g, c })
          continue
        }
        out.push({ t: 'g', g, c })
        if (!collapsed.has(g.artifact)) {
          for (const f of g.findings) out.push({ t: 'f', f, g })
        }
      }
    }
    return out
  }, [categories, collapsed, collapsedCats, expandedCats, filtering])

  const setTriageState = useMutation({
    mutationFn: (v: { fingerprints: string[]; state: string; note?: string }) =>
      post<TriageResult>(`/api/cases/${slug}/triage`, v),
    onSuccess: (result) => {
      setLastCollected(result.collected)
      setChecked(new Set())
      setBulkNote('')
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
    },
  })

  const bulkTriage = (state: string) => {
    const at = items[cursor]
    const fps = checked.size
      ? [...checked]
      : (isFindingRow(at) ? [(at as { f: Finding }).f.fingerprint] : [])
    if (fps.length) setTriageState.mutate({ fingerprints: fps, state, note: bulkNote })
  }

  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (i) => {
      const t = items[i]?.t
      return t === 'c' ? 56 : t === 'g' ? 40 : 46
    },
    overscan: 20,
  })

  // Tastatur: j/k über Finding-Zeilen, x markieren, c/d/r triagieren
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (selected || e.target instanceof HTMLInputElement ||
          e.target instanceof HTMLTextAreaElement) return
      if (!items.length) return
      const move = (dir: 1 | -1) => {
        let i = cursor + dir
        while (i >= 0 && i < items.length && !isFindingRow(items[i])) i += dir
        if (i >= 0 && i < items.length) setCursor(i)
      }
      if (e.key === 'j') move(1)
      else if (e.key === 'k') move(-1)
      else if (e.key === 'Enter') {
        const it = items[cursor]
        if (isFindingRow(it)) {
          setLastCollected([])
          setSelected((it as { f: Finding }).f)
        }
      } else if (e.key === 'x') {
        const it = items[cursor]
        if (isFindingRow(it)) {
          const fp = (it as { f: Finding }).f.fingerprint
          const next = new Set(checked)
          if (next.has(fp)) next.delete(fp)
          else next.add(fp)
          setChecked(next)
        }
      } else if (e.key === 'c' || e.key === 'd' || e.key === 'r') {
        bulkTriage(e.key === 'c' ? 'confirmed' : e.key === 'd' ? 'dismissed' : 'reviewed')
      } else return
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, cursor, selected, checked, bulkNote])

  useEffect(() => { virtualizer.scrollToIndex(cursor) }, [cursor, virtualizer])

  const toggleGroup = (g: Group) => {
    const next = new Set(collapsed)
    if (next.has(g.artifact)) next.delete(g.artifact)
    else next.add(g.artifact)
    setCollapsed(next)
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

  const catFingerprints = (c: CatGroup) =>
    c.groups.flatMap((g) => g.findings.map((f) => f.fingerprint))

  const toggleCategoryChecked = (c: CatGroup) => {
    const fps = catFingerprints(c)
    const all = fps.every((fp) => checked.has(fp))
    const next = new Set(checked)
    for (const fp of fps) { if (all) next.delete(fp); else next.add(fp) }
    setChecked(next)
  }

  const toggleGroupChecked = (g: Group) => {
    const fps = g.findings.map((f) => f.fingerprint)
    const all = fps.every((fp) => checked.has(fp))
    const next = new Set(checked)
    for (const fp of fps) { if (all) next.delete(fp); else next.add(fp) }
    setChecked(next)
  }

  const counts = data?.counts

  return (
    <div className="flex h-[calc(100vh-40px)] flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-2 text-lg font-bold">Findings</h1>
        <Chip active={severity === '0'} onClick={() => setSeverity(severity === '0' ? '' : '0')}
          count={counts?.severity['0'] ?? 0}>
          <span className="h-2 w-2 rounded-full" style={{ background: 'var(--sev-high)' }} /> High
        </Chip>
        <Chip active={severity === '1'} onClick={() => setSeverity(severity === '1' ? '' : '1')}
          count={counts?.severity['1'] ?? 0}>
          <span className="h-2 w-2 rounded-full" style={{ background: 'var(--sev-medium)' }} /> Medium
        </Chip>
        <Chip active={severity === '2'} onClick={() => setSeverity(severity === '2' ? '' : '2')}
          count={counts?.severity['2'] ?? 0}>
          <span className="h-2 w-2 rounded-full" style={{ background: 'var(--sev-low)' }} /> Low
        </Chip>
        <Tooltip hint="Kontext, keine Aussage über dieses System — z.B. Scanner-Besuche. Standardmäßig ausgeblendet.">
          <Chip active={severity === '3'} onClick={() => setSeverity(severity === '3' ? '' : '3')}
            count={counts?.severity['3'] ?? 0}>
            <span className="h-2 w-2 rounded-full" style={{ background: 'var(--muted)' }} /> Info
          </Chip>
        </Tooltip>
        <span className="mx-1 h-4 w-px bg-[var(--line)]" />
        {(['new', 'confirmed', 'dismissed'] as const).map((t) => (
          <Chip key={t} active={triage === t} onClick={() => setTriage(triage === t ? '' : t)}
            count={counts?.triage[t] ?? 0}>
            {TRIAGE_LABEL[t]}
          </Chip>
        ))}
        <span className="mx-1 h-4 w-px bg-[var(--line)]" />
        {Object.entries(SOURCE_LABEL).map(([key, label]) => (
          <Chip key={key} active={source === key} onClick={() => setSource(source === key ? '' : key)}
            count={counts?.source[key] ?? 0}>
            {label}
          </Chip>
        ))}
        <div className="ml-auto">
          <SearchInput value={search} onChange={setSearch} placeholder="Regel, Pfad, Evidence…" />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-3 text-[12px] text-[var(--muted)]">
        <Tooltip hint="Bestätigte Findings sind abgearbeitet — sie verschwinden aus der Liste, bleiben aber im Fall und im Bericht.">
          <label className="flex cursor-pointer items-center gap-1.5">
            <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
              checked={hideConfirmed} onChange={(e) => setHideConfirmed(e.target.checked)} />
            Bestätigte ausblenden
          </label>
        </Tooltip>
        <Tooltip hint="Blendet Kontext ohne Aussage über dieses System aus (Scanner-Besuche).">
          <label className="flex cursor-pointer items-center gap-1.5">
            <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
              checked={hideInfo} onChange={(e) => setHideInfo(e.target.checked)} />
            Info ausblenden
          </label>
        </Tooltip>
        {(hideConfirmed || hideInfo) && data && (
          <span className="opacity-70">
            {formatCount(
              (hideConfirmed && !triage ? (counts?.triage['confirmed'] ?? 0) : 0) +
              (hideInfo && severity === '' ? (counts?.severity['3'] ?? 0) : 0))}
            {' '}ausgeblendet
          </span>
        )}
      </div>

      {checked.size > 0 ? (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[var(--accent)]/50 bg-[var(--accent-soft)] px-4 py-2 animate-fade-up">
          <span className="text-[13px] font-semibold">{checked.size} Finding{checked.size > 1 ? 's' : ''} markiert</span>
          <Button variant="primary" onClick={() => bulkTriage('confirmed')}>
            <Check size={14} /> Bestätigen &amp; sammeln
          </Button>
          <Button onClick={() => bulkTriage('reviewed')}>
            <Eye size={14} /> Gesichtet
          </Button>
          <Button variant="danger" onClick={() => bulkTriage('dismissed')}>
            <X size={14} /> False Positive
          </Button>
          <input
            value={bulkNote}
            onChange={(e) => setBulkNote(e.target.value)}
            placeholder="Notiz für alle markierten (optional)"
            className="min-w-56 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
          <Button variant="ghost" onClick={() => setChecked(new Set())}>Auswahl leeren</Button>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2 text-[11px] text-[var(--muted)]">
          <span>
            {formatCount(data?.total ?? 0)} Findings in {formatCount(categories.length)}{' '}
            Kategorie{categories.length === 1 ? '' : 'n'}
          </span>
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
            alle auf-/zuklappen
          </button>
          <span className="opacity-60">·</span>
          <span>
            Tastatur: <kbd className="rounded bg-[var(--panel-2)] px-1">j</kbd>/<kbd className="rounded bg-[var(--panel-2)] px-1">k</kbd> navigieren,{' '}
            <kbd className="rounded bg-[var(--panel-2)] px-1">x</kbd> markieren,{' '}
            <kbd className="rounded bg-[var(--panel-2)] px-1">c</kbd> bestätigen,{' '}
            <kbd className="rounded bg-[var(--panel-2)] px-1">d</kbd> False Positive,{' '}
            <kbd className="rounded bg-[var(--panel-2)] px-1">Enter</kbd> Details
          </span>
        </div>
      )}

      <div ref={parentRef}
        className="min-h-0 flex-1 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--panel)]">
        {items.length === 0 && (
          <EmptyState icon={<Bug size={36} />} title="Keine Findings"
            sub={data ? 'Kein Treffer für die aktuellen Filter — oder die Analyse lief noch nicht.' : 'Lade…'} />
        )}
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative' }}>
          {virtualizer.getVirtualItems().map((vi) => {
            const item = items[vi.index]
            const style = { height: vi.size, transform: `translateY(${vi.start}px)` }

            // ---- Ebene 1: Kategorie ----
            if (item.t === 'c') {
              const c = item.c
              const fps = catFingerprints(c)
              const allChecked = fps.length > 0 && fps.every((fp) => checked.has(fp))
              const someChecked = !allChecked && fps.some((fp) => checked.has(fp))
              const open = filtering
                ? !collapsedCats.has(c.cat.id)
                : expandedCats.has(c.cat.id)
              return (
                <div key={'c' + c.cat.id}
                  className="absolute left-0 top-0 flex w-full items-center gap-2.5 border-b border-[var(--line)] bg-[var(--panel-2)] px-3"
                  style={style}>
                  <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                    checked={allChecked}
                    ref={(el) => { if (el) el.indeterminate = someChecked }}
                    onChange={() => toggleCategoryChecked(c)}
                    title="Alle Findings dieser Kategorie markieren" />
                  <button onClick={() => toggleCategory(c)}
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-2.5 text-left">
                    {open
                      ? <ChevronDown size={16} className="shrink-0 text-[var(--muted)]" />
                      : <ChevronRight size={16} className="shrink-0 text-[var(--muted)]" />}
                    <SeverityBadge severity={c.worst} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-[14px] font-semibold">{c.cat.label}</span>
                        <InfoDot body={c.cat.what} wide />
                      </div>
                      <div className="truncate text-[11.5px] text-[var(--muted)]">
                        {formatCount(c.findings)} Finding{c.findings === 1 ? '' : 's'}
                        {' in '}
                        {formatCount(c.groups.length)} {artifactNoun(c.kind, c.groups.length)}
                      </div>
                    </div>
                    {c.confirmed > 0 && <Tag tone="danger">{c.confirmed} bestätigt</Tag>}
                    {c.dismissed > 0 && <Tag>{c.dismissed} FP</Tag>}
                  </button>
                </div>
              )
            }

            // ---- Ebene 2: Artefakt mit mehreren Findings ----
            if (item.t === 'g') {
              const g = item.g
              const Icon = KIND_ICON[g.kind] ?? Bug
              const fps = g.findings.map((f) => f.fingerprint)
              const allChecked = fps.every((fp) => checked.has(fp))
              const isCollapsed = collapsed.has(g.artifact)
              const confirmed = g.findings.filter((f) => f.triage === 'confirmed').length
              return (
                <div key={'g' + g.artifact}
                  className="absolute left-0 top-0 flex w-full items-center gap-2.5 border-b border-[var(--line-soft)] bg-[var(--panel)] pl-8 pr-3"
                  style={style}>
                  <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                    checked={allChecked && fps.length > 0}
                    onChange={() => toggleGroupChecked(g)} />
                  <button onClick={() => toggleGroup(g)}
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left">
                    {isCollapsed
                      ? <ChevronRight size={13} className="shrink-0 text-[var(--muted)]" />
                      : <ChevronDown size={13} className="shrink-0 text-[var(--muted)]" />}
                    <Icon size={13} className="shrink-0 text-[var(--muted)]" />
                    <ArtifactName artifact={g.artifact} kind={g.kind} roots={roots} />
                    <span className="shrink-0 rounded-full bg-[var(--panel-2)] px-2 py-0.5 text-[11px] text-[var(--muted)] tabular">
                      {g.findings.length} Regeln
                    </span>
                    {confirmed > 0 && <Tag tone="danger">{confirmed} bestätigt</Tag>}
                  </button>
                  {g.kind === 'file' && (
                    <Tooltip hint="Die Datei im Original ansehen — als Text und als Hex-Dump.">
                      <button
                        className="shrink-0 cursor-pointer rounded p-1 text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)] hover:text-[var(--accent)]"
                        onClick={() => setViewing({ path: g.artifact, line: g.findings[0]?.line ?? null })}>
                        <FileSearch size={14} />
                      </button>
                    </Tooltip>
                  )}
                </div>
              )
            }

            // ---- Ebene 3: das einzelne Finding ----
            // `single` ist ein Artefakt mit genau einem Finding: Artefakt und
            // Regel stehen in EINER Zeile statt in zweien.
            const f = item.f
            const single = item.t === 'single'
            return (
              <div key={f.fingerprint}
                className={clsx(
                  'absolute left-0 top-0 flex w-full items-center gap-3 border-b border-[var(--line-soft)] pr-4',
                  single ? 'pl-8' : 'pl-14',
                  'transition-colors hover:bg-[var(--panel-2)]',
                  vi.index === cursor && 'bg-[var(--accent-soft)]',
                  f.triage === 'dismissed' && 'opacity-45')}
                style={style}>
                <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                  checked={checked.has(f.fingerprint)}
                  onChange={(e) => {
                    const next = new Set(checked)
                    if (e.target.checked) next.add(f.fingerprint)
                    else next.delete(f.fingerprint)
                    setChecked(next)
                  }} />
                <button
                  className="flex min-w-0 flex-1 cursor-pointer items-center gap-3 py-0 text-left"
                  onClick={() => {
                    setCursor(vi.index)
                    // Das Sammel-Ergebnis gehört zu DER Aktion, die es erzeugt
                    // hat -- beim Öffnen eines anderen Findings verfällt es,
                    // sonst liest es sich als Ergebnis für dieses hier.
                    setLastCollected([])
                    setSelected(f)
                  }}>
                  <SeverityBadge severity={f.severity} />
                  {single ? (
                    <>
                      <ArtifactName artifact={f.artifact} kind={f.artifact_kind} roots={roots} />
                      <RuleName rule={f.rule} className="min-w-0 flex-1" />
                    </>
                  ) : (
                    <>
                      <RuleName rule={f.rule} className="w-[34%] min-w-0 shrink-0" />
                      <span className="mono min-w-0 flex-1 truncate text-[12px] text-[var(--muted)]">
                        {f.line != null && f.line !== 0 ? `Zeile ${f.line} — ` : ''}{f.evidence}
                      </span>
                    </>
                  )}
                  <TriageBadge state={f.triage} label={TRIAGE_LABEL[f.triage]} />
                </button>
              </div>
            )
          })}
        </div>
      </div>

      <FileViewer
        slug={slug}
        path={viewing?.path ?? null}
        focusLine={viewing?.line}
        onClose={() => setViewing(null)}
      />

      <FindingDrawer
        slug={slug}
        finding={selected}
        collected={lastCollected}
        onView={(path, line) => setViewing({ path, line })}
        onClose={() => { setSelected(null); setLastCollected([]) }}
        onSelectSibling={(fp) => {
          const f = byFp.get(fp)
          if (f) { setLastCollected([]); setSelected(f) }
        }}
        onTriage={(state, note) => {
          if (selected) setTriageState.mutate({ fingerprints: [selected.fingerprint], state, note })
        }}
      />
    </div>
  )
}

/** Der Regelname mit seiner Klartext-Erklärung im Tooltip. */
function RuleName({ rule, className }: { rule: string; className?: string }) {
  const e = explainRule(rule)
  return (
    <Tooltip title={rule} body={e?.what} hint={e?.why} wide
      className={clsx('truncate text-[13px] font-medium', className)}>
      <span className="truncate">{rule}</span>
    </Tooltip>
  )
}

/** Ein Artefakt so benannt, wie ein Mensch es denkt: bei Dateien NUR der Pfad
 *  unterhalb der Evidence (`images/shell.php`) — das ist die Angabe, die im
 *  Bericht steht und die man auf dem Server wiederfindet. Der vollständige
 *  Pfad und die Evidence, unter der die Datei liegt, stehen im Tooltip. */
function ArtifactName({ artifact, kind, roots }: {
  artifact: string; kind: string; roots: EvidenceRoot[]
}) {
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
  return (
    <Tooltip wide className="min-w-0"
      title={rootName ? `unter: ${rootName}` : 'Vollständiger Pfad'}
      body={<span className="mono break-all">{artifact}</span>}>
      <span className="mono min-w-0 truncate text-[13px] font-semibold">
        {root ? rel : shortPath(artifact, 80)}
      </span>
    </Tooltip>
  )
}

function MetaCell({ label, children, explain }: {
  label: string; children: React.ReactNode; explain?: string
}) {
  return (
    <div className="rounded-lg bg-[var(--panel-2)] px-3 py-2">
      <div className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
        {label}
        {explain && <InfoDot body={explain} />}
      </div>
      <div className="mt-0.5 text-[12px]">{children}</div>
    </div>
  )
}

function FindingDrawer({ slug, finding, collected, onClose, onTriage, onSelectSibling, onView }: {
  slug: string
  finding: Finding | null
  collected: TriageResult['collected']
  onClose: () => void
  onTriage: (state: string, note?: string) => void
  onSelectSibling: (fingerprint: string) => void
  onView: (path: string, line: number | null) => void
}) {
  const [note, setNote] = useState('')
  useEffect(() => { setNote(finding?.triage_note ?? '') }, [finding])

  const { data: ctx } = useQuery({
    queryKey: ['finding-context', slug, finding?.fingerprint],
    queryFn: () => api<FindingContext>(
      `/api/cases/${slug}/findings/${finding!.fingerprint}/context`),
    enabled: !!finding,
  })

  // Bei einem Client-Finding ist die erste Frage immer "was hat der gemacht?".
  // Der Trace steht also direkt hier, nicht einen Umweg über Actors entfernt.
  const isClient = finding?.artifact_kind === 'client'
  const { data: trace } = useQuery({
    queryKey: ['trace', slug, finding?.artifact, 'drawer'],
    queryFn: () => post<{ total: number; rows: TraceRow[] }>(
      `/api/cases/${slug}/trace`, { ips: [finding!.artifact], limit: 40 }),
    enabled: !!finding && isClient,
  })

  if (!finding) return null
  const file = ctx?.file
  const preview = file?.preview
  const actor = ctx?.actor

  return (
    <Drawer open onClose={onClose} wide
      title={<span className="flex items-center gap-2">
        <SeverityBadge severity={finding.severity} /> {finding.rule}
      </span>}>
      <div className="flex flex-col gap-4">
        {/* Was dieser Fund bedeutet -- vor allen Details, weil das die Frage
            ist, mit der man den Drawer öffnet. */}
        {(() => {
          const e = explainRule(finding.rule)
          if (!e) return null
          return (
            <div className="rounded-lg border-l-2 border-[var(--accent)] bg-[var(--panel-2)] px-3 py-2">
              <div className="text-[12.5px] leading-snug">{e.what}</div>
              {e.why && (
                <div className="mt-1 text-[12px] leading-snug text-[var(--muted)]">{e.why}</div>
              )}
            </div>
          )
        })()}

        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {KIND_LABEL[finding.artifact_kind] ?? 'Artefakt'}
          </div>
          <div className="mono flex items-center gap-2 break-all rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[12px]">
            <span className="min-w-0 flex-1">
              {finding.artifact}{finding.line != null && finding.line !== 0 && `:${finding.line}`}
            </span>
            <button className="shrink-0 cursor-pointer text-[var(--muted)] hover:text-[var(--fg)]"
              title="Pfad kopieren"
              onClick={() => navigator.clipboard.writeText(finding.artifact)}>
              <Copy size={13} />
            </button>
          </div>
          {finding.artifact_kind === 'file' && file?.exists && (
            <div className="mt-2">
              <Button onClick={() => onView(finding.artifact, finding.line)}>
                <FileSearch size={14} /> Datei ansehen (Raw &amp; Hex)
              </Button>
            </div>
          )}
        </div>

        {/* ---- Datei-Kontext ---- */}
        {file && (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            <MetaCell label="Größe">{file.exists ? formatBytes(file.size) : 'Datei fehlt!'}</MetaCell>
            <MetaCell label="Geändert"
              explain="Änderungszeitpunkt laut Dateisystem — mit Vorsicht: Angreifer können ihn fälschen (Timestomping).">
              <Tooltip title={absoluteTime(file.mtime)}>
                <span>{relativeTime(file.mtime)}</span>
              </Tooltip>
            </MetaCell>
            <MetaCell label="CMS-Guard" explain={FIELD_EXPLAIN.cms_guard}>
              {file.cms_guard == null ? '—' : file.cms_guard ? (
                <span className="flex items-center gap-1 text-[var(--ok)]">
                  <ShieldCheck size={12} /> vorhanden
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[var(--sev-high)]">
                  <ShieldOff size={12} /> fehlt
                </span>
              )}
            </MetaCell>
            <MetaCell label="Upload-Ordner" explain={FIELD_EXPLAIN.upload_dir}>
              {file.in_upload_dir
                ? <span className="text-[var(--sev-medium)]">ja — PHP gehört hier nicht hin</span>
                : 'nein'}
            </MetaCell>
            {file.sha256 && (
              <div className="col-span-2 md:col-span-4">
                <MetaCell label="SHA-256" explain={FIELD_EXPLAIN.sha256}>
                  <span className="mono flex items-center gap-2 break-all text-[11px]">
                    <span className="min-w-0 flex-1">{file.sha256}</span>
                    <button className="shrink-0 cursor-pointer text-[var(--muted)] hover:text-[var(--fg)]"
                      title="Hash kopieren"
                      onClick={() => navigator.clipboard.writeText(file.sha256!)}>
                      <Copy size={12} />
                    </button>
                  </span>
                </MetaCell>
              </div>
            )}
          </div>
        )}

        {preview && !preview.error && !preview.binary && preview.lines && (
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              Dateiinhalt {preview.focus ? `um Zeile ${preview.focus}` : '(Anfang)'}
              {preview.truncated && ' — Datei gekürzt gelesen'}
            </div>
            <pre className="mono max-h-72 overflow-auto rounded-lg bg-[#0d1117] px-0 py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
              {preview.lines.map((l, i) => {
                const n = (preview.from_line ?? 1) + i
                const hit = n === preview.focus
                return (
                  <div key={n} className={clsx('flex px-3', hit && 'bg-[rgba(208,59,59,0.18)]')}>
                    <span className={clsx('w-10 shrink-0 select-none pr-3 text-right',
                      hit ? 'text-[#ff8b8b]' : 'text-[#4b5566]')}>{n}</span>
                    <span className="whitespace-pre-wrap break-all">{l || ' '}</span>
                  </div>
                )
              })}
            </pre>
          </div>
        )}
        {preview?.binary && (
          <div className="text-[12px] text-[var(--muted)]">
            Binärdatei — kein Text-Preview. {finding.evidence && 'Evidence unten.'}
          </div>
        )}

        {/* ---- Actor-Kontext ---- */}
        {finding.artifact_kind === 'client' && actor && (
          <div className="flex flex-col gap-2">
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
              <MetaCell label="Requests">{formatCount(actor.actor.requests)}</MetaCell>
              <MetaCell label="Zeitraum">
                {formatDay(actor.actor.first_epoch, actor.actor.tz)} → {formatDay(actor.actor.last_epoch, actor.actor.tz)}
              </MetaCell>
              <MetaCell label="Fehler 4xx/5xx">
                {formatCount(actor.actor.err4 + actor.actor.err5)}
              </MetaCell>
              <MetaCell label="Login-POSTs">
                {formatCount(actor.actor.login_posts)}
                {actor.actor.login_redirects > 0 &&
                  <span className="text-[var(--sev-high)]"> · {actor.actor.login_redirects} Redirects!</span>}
              </MetaCell>
            </div>
            {actor.alerts.length > 0 && (
              <div className="flex flex-col gap-1">
                {actor.alerts.map((a, i) => (
                  <div key={i} className="rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[12px]">
                    <SeverityBadge severity={a.severity} />{' '}
                    <span className="ml-1">{a.detail}</span>
                    {a.example && <div className="mono mt-0.5 truncate text-[11px] text-[var(--muted)]">{a.example}</div>}
                  </div>
                ))}
              </div>
            )}
            <div>
              <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                Meistaufgerufene URIs
              </div>
              <div className="flex flex-col gap-0.5">
                {actor.top_paths.map((p) => (
                  <div key={p.uri} className="flex items-center gap-2 text-[12px]">
                    <span className="mono min-w-0 flex-1 truncate" title={p.uri}>{p.uri}</span>
                    <span className="shrink-0 text-[var(--muted)] tabular">{p.n}× · {p.ok}× 2xx</span>
                  </div>
                ))}
              </div>
            </div>
            {actor.top_agents.length > 0 && (
              <div className="text-[11px] text-[var(--muted)]">
                User-Agents: {actor.top_agents.map((a) => `${a.agent || '(leer)'} (${a.n}×)`).join(' · ')}
              </div>
            )}
          </div>
        )}

        {/* ---- der Trace, direkt hier ---- */}
        {isClient && trace && (
          <div>
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                Trace — was dieser Client getan hat
              </span>
              <span className="text-[11px] text-[var(--muted)] tabular">
                {trace.rows.length} von {formatCount(trace.total)} Requests
                {' · '}
                <a className="text-[#bcd7f7] hover:underline"
                  href={downloadUrl(`/api/cases/${slug}/trace.csv?ips=${encodeURIComponent(finding.artifact)}`)}>
                  vollständig als CSV
                </a>
              </span>
            </div>
            <div className="max-h-64 overflow-auto rounded-lg border border-[var(--line)]">
              <table className="w-full border-collapse text-[11.5px]">
                <thead className="sticky top-0 bg-[var(--panel-2)]">
                  <tr className="text-left text-[10px] uppercase tracking-wider text-[var(--muted)]">
                    <th className="px-2 py-1.5">Zeit</th>
                    <th className="px-2 py-1.5">Methode</th>
                    <th className="px-2 py-1.5">URI</th>
                    <th className="px-2 py-1.5 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="mono">
                  {trace.rows.map((r, i) => (
                    <tr key={i} className="border-t border-[var(--line-soft)] hover:bg-[var(--panel-2)]">
                      <td className="whitespace-nowrap px-2 py-1 text-[var(--muted)]">
                        {formatLogTime(r.epoch, r.tz)}
                      </td>
                      <td className="px-2 py-1">{r.method}</td>
                      <td className="max-w-[300px] truncate px-2 py-1" title={r.uri}>{r.uri}</td>
                      <td className={clsx('px-2 py-1 text-right tabular',
                        r.status >= 500 ? 'text-[var(--sev-high)]'
                          : r.status >= 400 ? 'text-[var(--sev-medium)]'
                            : r.status >= 300 ? 'text-[var(--sev-low)]' : 'text-[var(--ok)]')}>
                        {r.status}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!trace.rows.length && (
                <div className="px-3 py-4 text-center text-[12px] text-[var(--muted)]">
                  Keine Requests im Index für diese Adresse.
                </div>
              )}
            </div>
          </div>
        )}

        {/* ---- Tabellen-Kontext ---- */}
        {ctx?.table && (
          <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
            <MetaCell label="Zeilen im Dump">{formatCount(ctx.table.rows)}</MetaCell>
            <MetaCell label="Spalten">{ctx.table.columns}</MetaCell>
            <MetaCell label="Dump-Bytes">{formatBytes(ctx.table.bytes)}</MetaCell>
            <MetaCell label="CMS">{ctx.table.cms || '—'}</MetaCell>
          </div>
        )}

        {finding.evidence && (
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              Evidence
            </div>
            <pre className="mono max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-[#0d1117] px-3 py-2 text-[12px] leading-relaxed text-[#e6edf3]">
              {finding.evidence}
            </pre>
          </div>
        )}

        {/* ---- Geschwister-Findings ---- */}
        {ctx && ctx.siblings.length > 0 && (
          <div>
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              Weitere Findings an diesem Artefakt ({ctx.siblings.length})
            </div>
            <div className="flex flex-col gap-1">
              {ctx.siblings.map((s) => (
                <button key={s.fingerprint}
                  onClick={() => onSelectSibling(s.fingerprint)}
                  className="flex cursor-pointer items-center gap-2 rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-left text-[12px] transition-colors hover:bg-[var(--accent-soft)]">
                  <SeverityBadge severity={s.severity} />
                  <span className="min-w-0 flex-1 truncate">{s.rule}</span>
                  {s.line != null && s.line !== 0 &&
                    <span className="text-[var(--muted)]">Z. {s.line}</span>}
                  <TriageBadge state={s.triage} label={TRIAGE_LABEL[s.triage] ?? s.triage} />
                </button>
              ))}
            </div>
          </div>
        )}

        {/* ---- Hunt (Datei-Findings) ---- */}
        {ctx?.hunt && (
          <div>
            <div className="mb-1 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              <Crosshair size={12} /> Wer hat diese Datei angefragt? (aus dem Log-Index)
            </div>
            {ctx.hunt.length ? (
              <div className="flex flex-col gap-1">
                {ctx.hunt.slice(0, 8).map((h) => (
                  <div key={h.ip + h.name}
                    className="flex items-center justify-between rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[12px]">
                    <span className="mono">{h.ip}</span>
                    <span className="text-[var(--muted)] tabular">
                      {h.hits}× · {h.ok_hits}× 2xx
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-[12px] text-[var(--muted)]">
                Kein Request auf diese Datei im Index.
              </div>
            )}
          </div>
        )}

        {collected.length > 0 && (
          <div className="rounded-lg border border-[var(--ok)]/40 bg-[rgba(12,163,12,0.08)] px-3 py-2 animate-fade-up">
            <div className="mb-1 text-[12px] font-semibold text-[var(--ok)]">
              In die IOC Box übernommen:
            </div>
            <div className="flex flex-wrap gap-1.5">
              {collected.map((c, i) => (
                <Tag key={i} tone="accent">
                  {c.type}: {c.value.length > 40 ? `…${c.value.slice(-38)}` : c.value}
                  {c.hits != null && ` (${c.hits}×)`}
                </Tag>
              ))}
            </div>
          </div>
        )}

        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            Triage-Notiz
          </div>
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={2}
            placeholder="Warum bestätigt / verworfen?"
            className="w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[13px] outline-none focus:border-[var(--accent)]/70"
          />
        </div>

        <div className="flex flex-wrap gap-2">
          <Button variant="primary" onClick={() => onTriage('confirmed', note)}>
            <Check size={14} /> Bestätigen &amp; sammeln
          </Button>
          <Button onClick={() => onTriage('reviewed', note)}>
            <Eye size={14} /> Gesichtet
          </Button>
          <Button variant="danger" onClick={() => onTriage('dismissed', note)}>
            <X size={14} /> False Positive
          </Button>
        </div>
        <p className="text-[11px] text-[var(--muted)]">
          Verworfene Findings werden nie gelöscht — sie bleiben sichtbar und filterbar,
          mit der Notiz warum. Bestätigen legt Artefakt (+ SHA-256 bei Dateien) in die
          IOC Box und sammelt die anfragenden Clients aus dem Log-Index ein.
        </p>
      </div>
    </Drawer>
  )
}
