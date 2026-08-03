// Findings.tsx — die Arbeitsliste des Falls. Durchgearbeitet werden
// ARTEFAKTE, nicht einzelne Findings.
//
// Ein Artefakt ist die Sache selbst: diese Datei, dieser Client, diese
// Tabelle. Die Findings sind die Regeln, die darauf angesprochen haben —
// sie sind der GRUND für die Entscheidung, nicht die Entscheidung selbst.
// Acht Regeln auf einer abgelegten Shell sind acht Beobachtungen über EINE
// Datei; die Frage („gehört das zum Vorfall?") stellt sich einmal.
//
// Deshalb: markiert, gezählt und als True/False Positive entschieden wird
// das Artefakt. Die Liste hat zwei Ebenen — Kategorie („Webshells &
// Backdoors") und darunter die Artefakte. Die Findings eines Artefakts
// stehen aufgeklappt darunter und im Detail-Fenster, das alles zusammenholt,
// was zur Beurteilung nötig ist: Metadaten, Dateiinhalt, Actor-Profil und
// jede IP, die daran hängt — jede davon direkt als Trace zu öffnen.
//
// Die Zeile selbst soll SO VIEL SAGEN, dass man sie meistens nicht öffnen
// muss: Symbol und Farbe für Art und Schweregrad, die Regeln als Chips, ein
// Balken für die Verteilung der Findings, der Zustand als Pille. Eine Liste
// aus lauter gleich aussehenden Zeilen zwingt zum Lesen jeder einzelnen.
import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  Bug, Check, ChevronDown, ChevronRight, Copy, Crosshair, Eye, FileCode2,
  FileSearch, ServerCog, ShieldCheck, ShieldOff, Table2, Users, X,
} from 'lucide-react'
import clsx from 'clsx'
import {
  api, post, type ArtifactContext, type ArtifactRow, type Finding,
  type FindingsResponse, type TriageState,
} from '../api'
import {
  SEVERITY_LABEL, SEVERITY_VAR, SOURCE_LABEL, TRIAGE_LABEL, absoluteTime,
  formatBytes, formatCount, formatDay, relativeTime, relativeToRoot, shortPath,
  type EvidenceRoot,
} from '../format'
import {
  Button, Chip, EmptyState, Modal, SearchInput, SeverityBadge, Tag, TriageBadge,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { FileViewer } from '../components/FileViewer'
import { TraceWindow } from '../components/TraceWindow'
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

// Mit Artikel, für die Frage im Detail-Fenster: „Ist dieses Datei" liest
// sich wie eine Maschine, und der Satz ist die wichtigste Zeile darin.
const KIND_THIS: Record<string, string> = {
  file: 'diese Datei', table: 'diese Tabelle',
  client: 'dieser Client', dump: 'dieser Dump',
}

/** Ein Artefakt mit allem, was der Server dazu aggregiert hat, plus seinen
 *  Findings. Die Kategorie kommt vom SCHWERSTEN Finding — wenn eine Datei
 *  sowohl „Verschleierung" als auch „führt Befehle aus" auslöst, steht sie
 *  dort, wo die stärkere Aussage sie hinstellt. */
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
  kind: string          // vorherrschende Artefakt-Art, für "12 Dateien"
}

// Zeilentypen der virtualisierten Liste.
type Item =
  | { t: 'c'; c: CatGroup }
  | { t: 'a'; a: Artifact; c: CatGroup }
  | { t: 'f'; f: Finding; a: Artifact }

const isArtifactRow = (i?: Item) => i?.t === 'a'

interface TriageResult {
  updated: number
  artifacts: number
  collected: { value: string; type: string; hits?: number; ok_hits?: number }[]
}

export function Findings({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const qc = useQueryClient()
  const [severity, setSeverity] = useState('')
  const [triage, setTriage] = useState('')
  const [source, setSource] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Artifact | null>(null)
  const [cursor, setCursor] = useState(0)
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
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
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
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
  const roots: EvidenceRoot[] = useMemo(() => data?.roots ?? [], [data])

  // Zwei Ebenen: Kategorie ("Webshells & Backdoors") -> die Artefakte darin.
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
      const cat = categorize(lead?.source ?? row.source, lead?.rule ?? '')
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
  }, [data])

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
      for (const a of c.artifacts) {
        out.push({ t: 'a', a, c })
        if (expanded.has(a.artifact)) {
          for (const f of a.items) out.push({ t: 'f', f, a })
        }
      }
    }
    return out
  }, [categories, expanded, collapsedCats, expandedCats, filtering])

  const setTriageState = useMutation({
    mutationFn: (v: { artifacts: string[]; state: string; note?: string }) =>
      post<TriageResult>(`/api/cases/${slug}/triage`, v),
    onSuccess: (result) => {
      setLastCollected(result.collected)
      setChecked(new Set())
      setBulkNote('')
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['artifact'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
    },
  })

  /** Markierte Artefakte, sonst das unter dem Cursor. */
  const bulkTriage = (state: string) => {
    const at = items[cursor]
    const names = checked.size
      ? [...checked]
      : (isArtifactRow(at) ? [(at as { a: Artifact }).a.artifact] : [])
    if (names.length) setTriageState.mutate({ artifacts: names, state, note: bulkNote })
  }

  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (i) => {
      const t = items[i]?.t
      return t === 'c' ? 62 : t === 'a' ? 68 : 34
    },
    overscan: 20,
  })

  // Tastatur: j/k über Artefakt-Zeilen, x markieren, c/d/r entscheiden
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (selected || viewing || traceIps || e.target instanceof HTMLInputElement ||
          e.target instanceof HTMLTextAreaElement) return
      if (!items.length) return
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
          setLastCollected([])
          setSelected((it as { a: Artifact }).a)
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
      } else return
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, cursor, selected, viewing, traceIps, checked, bulkNote])

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

  return (
    <div className="flex h-[calc(100vh-40px)] flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title="Artefakte"
          body="Die Dinge selbst: diese Datei, dieser Client, diese Tabelle. Geflaggt wurden sie von den Findings — entschieden wird über das Artefakt."
          hint="Die Zahlen auf den Chips sind Artefakte, nicht einzelne Regeltreffer.">
          <h1 className="mr-2 text-lg font-bold">Artefakte</h1>
        </Tooltip>
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
        <Tooltip hint="Bestätigte Artefakte sind abgearbeitet — sie verschwinden aus der Liste, bleiben aber im Fall und im Bericht.">
          <label className="flex cursor-pointer items-center gap-1.5">
            <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
              checked={hideConfirmed} onChange={(e) => setHideConfirmed(e.target.checked)} />
            Bestätigte ausblenden
          </label>
        </Tooltip>
        <Tooltip hint="Blendet Artefakte aus, deren stärkster Fund reiner Kontext ist (Scanner-Besuche).">
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
          <span className="text-[13px] font-semibold">
            {checked.size} Artefakt{checked.size > 1 ? 'e' : ''} markiert
          </span>
          <Button variant="primary" onClick={() => bulkTriage('confirmed')}>
            <Check size={14} /> True Positive &amp; sammeln
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
            {formatCount(data?.total ?? 0)} Artefakt{(data?.total ?? 0) === 1 ? '' : 'e'}
            {' aus '}{formatCount(data?.findings_total ?? 0)} Findings
            {' in '}{formatCount(categories.length)}{' '}
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
            <kbd className="rounded bg-[var(--panel-2)] px-1">c</kbd> True Positive,{' '}
            <kbd className="rounded bg-[var(--panel-2)] px-1">d</kbd> False Positive,{' '}
            <kbd className="rounded bg-[var(--panel-2)] px-1">Enter</kbd> Details
          </span>
        </div>
      )}

      <div ref={parentRef}
        className="min-h-0 flex-1 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--panel)]">
        {items.length === 0 && (
          <EmptyState icon={<Bug size={36} />} title="Keine Artefakte"
            sub={data ? 'Kein Treffer für die aktuellen Filter — oder die Analyse lief noch nicht.' : 'Lade…'} />
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
              return (
                <div key={'c' + c.cat.id}
                  className="absolute left-0 top-0 flex w-full items-center gap-2.5 border-b border-[var(--line)] bg-[var(--panel-2)] pr-4"
                  style={style}>
                  {/* Der Farbbalken ist der Schweregrad der Kategorie — beim
                      Scrollen erkennt man die schweren Blöcke am Rand, ohne
                      eine Zeile zu lesen. */}
                  <span className="h-full w-1 shrink-0"
                    style={{ background: SEVERITY_VAR[c.worst] }} />
                  <input type="checkbox" className="ml-1.5 cursor-pointer accent-[var(--accent)]"
                    checked={allChecked}
                    ref={(el) => { if (el) el.indeterminate = someChecked }}
                    onChange={() => toggleCategoryChecked(c)}
                    title="Alle Artefakte dieser Kategorie markieren" />
                  <button onClick={() => toggleCategory(c)}
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-2.5 text-left">
                    {open
                      ? <ChevronDown size={16} className="shrink-0 text-[var(--muted)]" />
                      : <ChevronRight size={16} className="shrink-0 text-[var(--muted)]" />}
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="truncate text-[14px] font-semibold">{c.cat.label}</span>
                        <InfoDot body={c.cat.what} wide />
                        <SeverityBadge severity={c.worst} />
                      </div>
                      <div className="truncate text-[11.5px] text-[var(--muted)]">
                        {formatCount(c.artifacts.length)}{' '}
                        {artifactNoun(c.kind, c.artifacts.length)}
                        {' · '}
                        {formatCount(c.findings)} Finding{c.findings === 1 ? '' : 's'}
                      </div>
                    </div>
                  </button>
                  {/* Fortschritt: wie viel dieser Kategorie ist entschieden? */}
                  <Tooltip
                    title={`${decided} von ${c.artifacts.length} entschieden`}
                    hint={`${c.confirmed} True Positive · ${c.dismissed} False Positive · ${c.artifacts.length - decided} offen`}>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="hidden text-[11px] text-[var(--muted)] tabular sm:inline">
                        {decided}/{c.artifacts.length}
                      </span>
                      <span className="flex h-1.5 w-20 overflow-hidden rounded-full bg-[var(--panel)]">
                        {c.confirmed > 0 && (
                          <span style={{ width: `${(c.confirmed / c.artifacts.length) * 100}%`,
                                         background: 'var(--sev-high)' }} />
                        )}
                        {c.dismissed > 0 && (
                          <span style={{ width: `${(c.dismissed / c.artifacts.length) * 100}%`,
                                         background: 'var(--muted)' }} />
                        )}
                      </span>
                    </div>
                  </Tooltip>
                </div>
              )
            }

            // ---- Ebene 2: das Artefakt — die Einheit, über die entschieden wird ----
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
                    a.triage === 'dismissed' && 'opacity-45')}
                  style={style}>
                  <span className="h-full w-1 shrink-0 opacity-40" style={{ background: tint }} />
                  <input type="checkbox" className="ml-4 cursor-pointer accent-[var(--accent)]"
                    checked={checked.has(a.artifact)}
                    onChange={(e) => {
                      const next = new Set(checked)
                      if (e.target.checked) next.add(a.artifact)
                      else next.delete(a.artifact)
                      setChecked(next)
                    }} />
                  <Tooltip hint={open ? 'Findings zuklappen' : 'Zeigt die Regeln, die auf dieses Artefakt angesprochen haben.'}>
                    <button onClick={() => toggleArtifact(a)}
                      className="shrink-0 cursor-pointer rounded p-0.5 text-[var(--muted)] hover:text-[var(--fg)]">
                      {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </button>
                  </Tooltip>
                  <button
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-3 text-left"
                    onClick={() => {
                      setCursor(vi.index)
                      // Das Sammel-Ergebnis gehört zu DER Aktion, die es
                      // erzeugt hat -- beim Öffnen eines anderen Artefakts
                      // verfällt es, sonst liest es sich als Ergebnis für
                      // dieses hier.
                      setLastCollected([])
                      setSelected(a)
                    }}>
                    {/* Die Art des Artefakts als Symbol, eingefärbt nach dem
                        Schweregrad: eine Datei sieht anders aus als ein
                        Client, und Rot sticht aus einer Liste heraus. */}
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg"
                      style={{ background: `color-mix(in srgb, ${tint} 16%, transparent)`,
                               color: tint }}>
                      <Icon size={15} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex min-w-0 items-center gap-2">
                        <ArtifactName artifact={a.artifact} kind={a.artifact_kind} roots={roots} />
                        <TriageBadge state={a.triage} label={TRIAGE_LABEL[a.triage]} />
                      </div>
                      <RuleChips items={a.items} />
                    </div>
                    <SeverityMeter items={a.items} total={a.findings} />
                  </button>
                  <div className="flex shrink-0 items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
                    {a.artifact_kind === 'file' && (
                      <Tooltip hint="Die Datei im Original ansehen — als Text und als Hex-Dump.">
                        <button
                          className="cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel)] hover:text-[var(--accent)]"
                          onClick={() => setViewing({ path: a.artifact, line: a.items[0]?.line ?? null })}>
                          <FileSearch size={15} />
                        </button>
                      </Tooltip>
                    )}
                    {a.artifact_kind === 'client' && (
                      <Tooltip hint="Jeden Request dieses Clients ansehen.">
                        <button
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

            // ---- Ebene 3: ein Finding als BEGRÜNDUNG, nicht als Entscheidung ----
            const f = item.f
            return (
              <div key={f.fingerprint}
                className={clsx(
                  'absolute left-0 top-0 flex w-full items-center gap-2.5 border-b border-[var(--line-soft)] pr-4',
                  item.a.triage === 'dismissed' && 'opacity-45')}
                style={style}>
                {/* Die Führungslinie hält die Findings sichtbar an ihrem
                    Artefakt — eingerückter Text allein verliert den Bezug. */}
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

      {/* Alle drei sind zentrierte Fenster; die Ebene sagt, was davor liegt.
          Trace und Datei-Viewer werden AUS dem Artefakt-Fenster geöffnet und
          sind eine Stufe kleiner — man sieht am Rand, wohin man zurückkommt. */}
      <ArtifactWindow
        slug={slug}
        artifact={selected}
        roots={roots}
        collected={lastCollected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips) => setTraceIps(ips)}
        onClose={() => { setSelected(null); setLastCollected([]) }}
        onTriage={(state, note) => {
          if (selected) setTriageState.mutate({ artifacts: [selected.artifact], state, note })
        }}
      />

      <TraceWindow slug={slug} ips={traceIps} layer={1}
        onClose={() => setTraceIps(null)} />

      <FileViewer
        slug={slug}
        path={viewing?.path ?? null}
        focusLine={viewing?.line}
        layer={2}
        onClose={() => setViewing(null)}
      />
    </div>
  )
}

/** Die Regeln eines Artefakts als Chips unter seinem Namen — man sieht in
 *  der Liste, WORUM es geht, ohne aufzuklappen oder zu öffnen. Mehr als drei
 *  wären eine zweite Liste in der Liste; der Rest steht als Zahl daneben. */
function RuleChips({ items }: { items: Finding[] }) {
  if (!items.length) return null
  const shown = items.slice(0, 3)
  const rest = items.length - shown.length
  return (
    <div className="mt-0.5 flex min-w-0 items-center gap-1 overflow-hidden">
      {shown.map((f) => {
        const e = explainRule(f.rule)
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
        <span className="shrink-0 text-[10.5px] text-[var(--muted)]">+{rest}</span>
      )}
    </div>
  )
}

/** Wie sich die Findings eines Artefakts auf die Schweregrade verteilen.
 *  Zwei Artefakte mit „4 Findings" sind nicht dasselbe: viermal LOW ist ein
 *  anderes Bild als zweimal HIGH — und genau das soll man sehen, ohne die
 *  Zeile aufzuklappen. */
function SeverityMeter({ items, total }: { items: Finding[]; total: number }) {
  const counts = [0, 1, 2, 3].map((s) => items.filter((f) => f.severity === s).length)
  const sum = counts.reduce((a, b) => a + b, 0)
  if (!sum) {
    return (
      <span className="shrink-0 text-[11px] text-[var(--muted)] tabular">
        {formatCount(total)}
      </span>
    )
  }
  return (
    <Tooltip
      title={`${formatCount(sum)} Finding${sum === 1 ? '' : 's'} auf diesem Artefakt`}
      hint={counts
        .map((n, s) => (n ? `${n}× ${SEVERITY_LABEL[s]}` : null))
        .filter(Boolean).join(' · ')}>
      <div className="flex shrink-0 items-center gap-2">
        <span className="flex h-1.5 w-16 overflow-hidden rounded-full bg-[var(--panel-2)]">
          {counts.map((n, s) => n > 0 && (
            <span key={s} style={{ width: `${(n / sum) * 100}%`, background: SEVERITY_VAR[s] }} />
          ))}
        </span>
        <span className="w-4 text-right text-[11px] text-[var(--muted)] tabular">{sum}</span>
      </div>
    </Tooltip>
  )
}

/** Der Regelname mit seiner Klartext-Erklärung im Tooltip. */
function RuleName({ rule, className }: { rule: string; className?: string }) {
  const e = explainRule(rule)
  return (
    <Tooltip title={rule} body={e?.what} hint={e?.why} wide
      className={clsx('truncate text-[12.5px] font-medium', className)}>
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

function Block({ title, children, right }: {
  title: React.ReactNode; children: React.ReactNode; right?: React.ReactNode
}) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
          {title}
        </div>
        {right}
      </div>
      {children}
    </div>
  )
}

/** Das Detail-FENSTER eines Artefakts: alles, was zur Entscheidung nötig
 *  ist, in einer Ansicht.
 *
 *  Zentriert und breit statt als Streifen am Rand — beurteilt wird aus dem
 *  ZUSAMMENHANG, und der entsteht erst, wenn Begründung, Dateiinhalt und die
 *  Clients daran nebeneinander liegen statt hintereinander zu scrollen.
 *  Links steht, was man entscheidet und warum; rechts, was man dafür ansieht.
 *  Die Entscheidung selbst zuoberst, weil sie der Grund ist, aus dem das
 *  Fenster offen ist. */
function ArtifactWindow({ slug, artifact, roots, collected, onClose, onTriage,
                          onView, onTrace }: {
  slug: string
  artifact: Artifact | null
  roots: EvidenceRoot[]
  collected: TriageResult['collected']
  onClose: () => void
  onTriage: (state: string, note?: string) => void
  onView: (path: string, line: number | null) => void
  onTrace: (ips: string[]) => void
}) {
  const [note, setNote] = useState('')
  useEffect(() => { setNote(artifact?.triage_note ?? '') }, [artifact])

  const { data: ctx } = useQuery({
    queryKey: ['artifact', slug, artifact?.artifact],
    queryFn: () => api<ArtifactContext>(
      `/api/cases/${slug}/artifact?artifact=${encodeURIComponent(artifact!.artifact)}`),
    enabled: !!artifact,
  })

  if (!artifact) return null
  const kind = artifact.artifact_kind
  const file = ctx?.file
  const preview = file?.preview
  const actor = ctx?.actor
  const findings = ctx?.findings ?? artifact.items
  const state: TriageState = ctx?.triage ?? artifact.triage
  const ips = ctx?.related_ips ?? []
  const { root, rel } = relativeToRoot(artifact.artifact, roots)
  const Icon = KIND_ICON[kind] ?? Bug

  return (
    <Modal open onClose={onClose}
      title={<span className="flex min-w-0 items-center gap-2">
        <SeverityBadge severity={artifact.worst} />
        <Icon size={15} className="shrink-0 text-[var(--muted)]" />
        <span className="mono truncate">{kind === 'file' && root ? rel : artifact.artifact}</span>
        <TriageBadge state={state} label={TRIAGE_LABEL[state]} />
      </span>}>
      <div className="flex flex-col gap-4">
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

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] lg:items-start">
          {/* ================= links: entscheiden und warum ================= */}
          <div className="flex flex-col gap-4">
            {/* ---- die Entscheidung ---- */}
            <div className="rounded-xl border border-[var(--line)] bg-[var(--panel-2)] px-3 py-3">
              <div className="mb-2 text-[12.5px]">
                Ist {KIND_THIS[kind] ?? 'dieses Artefakt'}{' '}
                <span className="font-semibold">Teil des Vorfalls?</span>{' '}
                <span className="text-[var(--muted)]">
                  Die Entscheidung gilt für das ganze Artefakt — alle{' '}
                  {formatCount(findings.length)} Finding{findings.length === 1 ? '' : 's'}{' '}
                  darunter sind die Begründung dafür.
                </span>
              </div>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={2}
                placeholder="Begründung (wandert mit ins Fall-Archiv)"
                className="mb-2 w-full rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-2 text-[13px] outline-none focus:border-[var(--accent)]/70"
              />
              <div className="flex flex-wrap gap-2">
                <Button variant="primary" onClick={() => onTriage('confirmed', note)}>
                  <Check size={14} /> True Positive &amp; sammeln
                </Button>
                <Button onClick={() => onTriage('reviewed', note)}>
                  <Eye size={14} /> Gesichtet
                </Button>
                <Button variant="danger" onClick={() => onTriage('dismissed', note)}>
                  <X size={14} /> False Positive
                </Button>
                {ctx?.triaged_at && (
                  <span className="self-center text-[11px] text-[var(--muted)]">
                    zuletzt entschieden: {absoluteTime(ctx.triaged_at)}
                  </span>
                )}
              </div>
              <p className="mt-2 text-[11px] text-[var(--muted)]">
                Nichts wird gelöscht: ein False Positive bleibt mit deiner Notiz sichtbar
                und filterbar. True Positive legt das Artefakt (+ SHA-256 bei Dateien) in
                die IOC Box und sammelt die anfragenden Clients aus dem Log-Index ein.
              </p>
            </div>

            {/* ---- was das Artefakt IST ---- */}
            <Block title={KIND_LABEL[kind] ?? 'Artefakt'}>
              <div className="mono flex items-center gap-2 break-all rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[12px]">
                <span className="min-w-0 flex-1">{artifact.artifact}</span>
                <button className="shrink-0 cursor-pointer text-[var(--muted)] hover:text-[var(--fg)]"
                  title="Kopieren"
                  onClick={() => navigator.clipboard.writeText(artifact.artifact)}>
                  <Copy size={13} />
                </button>
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {kind === 'file' && file?.exists && (
                  <Button onClick={() => onView(artifact.artifact,
                                                findings.find((f) => f.line)?.line ?? null)}>
                    <FileSearch size={14} /> Datei ansehen (Raw &amp; Hex)
                  </Button>
                )}
                {kind === 'client' && (
                  <Button onClick={() => onTrace([artifact.artifact])}>
                    <Crosshair size={14} /> Trace öffnen
                  </Button>
                )}
              </div>
            </Block>

            {/* ---- Datei-Kontext ---- */}
            {file && (
              <div className="grid grid-cols-2 gap-2">
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
                  <div className="col-span-2">
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

            {/* ---- WARUM es hier steht: jedes Finding auf diesem Artefakt ---- */}
            <Block title={`Warum dieses Artefakt geflaggt wurde (${formatCount(findings.length)})`}>
              <div className="flex flex-col gap-1.5">
                {findings.map((f) => {
                  const e = explainRule(f.rule)
                  return (
                    <div key={f.fingerprint}
                      className="rounded-lg border-l-2 bg-[var(--panel-2)] px-3 py-2"
                      style={{ borderLeftColor: SEVERITY_VAR[f.severity] }}>
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-[12.5px] font-semibold">{f.rule}</span>
                        {f.line != null && f.line !== 0 && (
                          <button
                            className="cursor-pointer text-[11px] text-[var(--accent-text)] hover:underline"
                            onClick={() => onView(artifact.artifact, f.line)}>
                            Zeile {f.line}
                          </button>
                        )}
                      </div>
                      {e && (
                        <div className="mt-1 text-[12px] leading-snug">
                          {e.what}
                          {e.why && <span className="text-[var(--muted)]"> {e.why}</span>}
                        </div>
                      )}
                      {f.evidence && (
                        <pre className="mono mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-[var(--code-bg)] px-2 py-1 text-[11px] leading-relaxed text-[#e6edf3]">
                          {f.evidence}
                        </pre>
                      )}
                    </div>
                  )
                })}
              </div>
            </Block>
          </div>

          {/* ================= rechts: was man dafür ansieht ================= */}
          <div className="flex flex-col gap-4">
            {preview && !preview.error && !preview.binary && preview.lines && (
              <Block title={<>
                Dateiinhalt {preview.focus ? `um Zeile ${preview.focus}` : '(Anfang)'}
                {preview.truncated && ' — Datei gekürzt gelesen'}
              </>}>
                <pre className="mono max-h-[26rem] overflow-auto rounded-lg bg-[var(--code-bg)] px-0 py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
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
              </Block>
            )}
            {preview?.binary && (
              <div className="text-[12px] text-[var(--muted)]">
                Binärdatei — kein Text-Preview. Die Hex-Ansicht zeigt sie unverfälscht.
              </div>
            )}

            {/* ---- Actor-Kontext ---- */}
            {kind === 'client' && actor && (
              <div className="flex flex-col gap-2">
                <div className="grid grid-cols-2 gap-2">
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
                <Block title="Meistaufgerufene URIs">
                  <div className="flex flex-col gap-0.5">
                    {actor.top_paths.map((p) => (
                      <div key={p.uri} className="flex items-center gap-2 text-[12px]">
                        <span className="mono min-w-0 flex-1 truncate" title={p.uri}>{p.uri}</span>
                        <span className="shrink-0 text-[var(--muted)] tabular">{p.n}× · {p.ok}× 2xx</span>
                      </div>
                    ))}
                  </div>
                </Block>
                {actor.top_agents.length > 0 && (
                  <div className="text-[11px] text-[var(--muted)]">
                    User-Agents: {actor.top_agents.map((a) => `${a.agent || '(leer)'} (${a.n}×)`).join(' · ')}
                  </div>
                )}
              </div>
            )}

            {/* ---- die IPs an diesem Artefakt, jede sofort als Trace ---- */}
            <Block
              title={<span className="flex items-center gap-1.5">
                <Crosshair size={12} /> Clients an diesem Artefakt ({ips.length})
              </span>}
              right={ips.length > 1 && (
                <button
                  className="cursor-pointer text-[11px] text-[var(--accent-text)] hover:underline"
                  onClick={() => onTrace(ips.map((i) => i.ip))}>
                  alle zusammen tracen
                </button>
              )}>
              {ips.length ? (
                <div className="flex max-h-80 flex-col gap-1 overflow-y-auto">
                  {ips.map((h) => (
                    <div key={h.ip}
                      className="flex items-center gap-2 rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[12px]">
                      <span className="mono font-medium">{h.ip}</span>
                      {h.in_box && <Tag tone="accent" explain="Diese Adresse liegt bereits in der IOC Box.">IOC</Tag>}
                      <span className="min-w-0 flex-1 truncate text-[11.5px] text-[var(--muted)]"
                        title={h.why}>
                        {h.why}
                      </span>
                      {h.hits != null && (
                        <span className="shrink-0 text-[var(--muted)] tabular">
                          {formatCount(h.hits)}× · {formatCount(h.ok_hits)}× 2xx
                        </span>
                      )}
                      <Button variant="ghost" className="shrink-0"
                        onClick={() => onTrace([h.ip])}>
                        <Crosshair size={12} /> Trace
                      </Button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-[12px] text-[var(--muted)]">
                  Keine Adresse im Log-Index, die auf dieses Artefakt zeigt.
                </div>
              )}
            </Block>

            {/* ---- Tabellen-/Dump-Kontext ---- */}
            {ctx?.table && (
              <div className="grid grid-cols-2 gap-2">
                <MetaCell label="Zeilen im Dump">{formatCount(ctx.table.rows)}</MetaCell>
                <MetaCell label="Spalten">{ctx.table.columns}</MetaCell>
                <MetaCell label="Dump-Bytes">{formatBytes(ctx.table.bytes)}</MetaCell>
                <MetaCell label="CMS">{ctx.table.cms || '—'}</MetaCell>
                {ctx.table.col_list && (
                  <div className="col-span-2">
                    <MetaCell label="Spalten im Dump">
                      <span className="mono break-all text-[11px]">{ctx.table.col_list}</span>
                    </MetaCell>
                  </div>
                )}
              </div>
            )}
            {ctx?.dump && (
              <div className="grid grid-cols-2 gap-2">
                <MetaCell label="Statements">{formatCount(ctx.dump.statements)}</MetaCell>
                <MetaCell label="Größe">{formatBytes(ctx.dump.size)}</MetaCell>
                <MetaCell label="CMS">{ctx.dump.cms || '—'}</MetaCell>
                <MetaCell label="Erstellt">{ctx.dump.meta?.created || '—'}</MetaCell>
              </div>
            )}
          </div>
        </div>
      </div>
    </Modal>
  )
}
