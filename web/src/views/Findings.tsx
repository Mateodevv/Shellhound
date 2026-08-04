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
import { useT } from '../i18n'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useVirtualizer } from '@tanstack/react-virtual'
import {
  Bug, Check, ChevronDown, ChevronRight, CircleDashed, Code, Crosshair,
  Database, DoorOpen, Eye, EyeOff, FileCog, FileSearch, KeyRound, Radar, X,
} from 'lucide-react'
import clsx from 'clsx'
import {
  api, type ArtifactRow, type Finding, type FindingsResponse,
} from '../api'
import {
  SEVERITY_LABEL, SEVERITY_VAR, formatCount,
  relativeToRoot, shortPath, type EvidenceRoot,
} from '../format'
import {
  Button, Chip, EmptyState, SearchInput, SeverityBadge, TriageBadge,
} from '../components/ui'
import { InfoDot, Tooltip } from '../components/Tooltip'
import { FileViewer } from '../components/FileViewer'
import { TraceWindow, type TraceMarks } from '../components/TraceWindow'
import { ArtifactWindow } from '../components/ArtifactWindow'
import { KIND_ICON } from '../artifactKinds'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { artifactNoun, categorize, explainRule, type Category } from '../explain'
import type { ViewId } from '../App'

// Ein Symbol je Kategorie. Die Kategorie ist die Gliederung, mit der man
// anfängt — sie soll auf einen Blick unterscheidbar sein und nicht als
// weitere Textzeile in einer Textliste stehen.
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

/** Ein Ausblende-Set umschalten: Klick versteckt die Klasse, der nächste
 *  Klick holt sie zurück. */
function toggleHidden(set: Set<string>, value: string): Set<string> {
  const next = new Set(set)
  if (next.has(value)) next.delete(value)
  else next.add(value)
  return next
}

export function Findings({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  // JEDER Filter-Chip ist ein Ausblende-Schalter: Klick versteckt seine
  // Klasse, der nächste Klick bringt sie zurück, mehrere stapeln sich.
  // Standardmäßig ausgeblendet: False Positives (gehören nicht zum Fall)
  // und Info (Kontext ohne Aussage über dieses System).
  const [hiddenSeverity, setHiddenSeverity] = useState<Set<string>>(new Set(['3']))
  const [hiddenTriage, setHiddenTriage] = useState<Set<string>>(new Set(['dismissed']))
  const [hiddenSource, setHiddenSource] = useState<Set<string>>(new Set())
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
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  // Was der Trace rot markieren soll — kommt aus dem Artefakt-Fenster,
  // das weiß, worum es geht (die Datei bzw. der Alarm des Clients).
  const [traceMarks, setTraceMarks] = useState<TraceMarks | undefined>()

  // Entscheidung + Nachsorge (Quittung, Übernahme-Meldung, Vorschläge) —
  // geteilt mit Actors, damit es überall dieselbe Entscheidung ist.
  const t = useTriage(slug, () => { setChecked(new Set()); setBulkNote('') })

  const query = useMemo(() => {
    const p = new URLSearchParams()
    if (hiddenSeverity.size) p.set('hide_severity', [...hiddenSeverity].join(','))
    if (hiddenTriage.size) p.set('hide_triage', [...hiddenTriage].join(','))
    if (hiddenSource.size) p.set('hide_source', [...hiddenSource].join(','))
    if (search) p.set('search', search)
    p.set('limit', '2000')
    return p.toString()
  }, [hiddenSeverity, hiddenTriage, hiddenSource, search])

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

  // Ein aktiver Filter bedeutet: der Analyst sucht etwas Bestimmtes. Dann
  // stehen die Kategorien offen, sonst wäre die Trefferliste hinter Klicks
  // versteckt. Ohne Filter ist die Übersicht der Zweck — Kategorien zu.
  // Nur die SUCHE öffnet die Kategorien automatisch — wer sucht, will die
  // Treffer sehen. Ausblenden ist keine Suche: die Übersicht bleibt zu.
  const filtering = Boolean(search)

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


  /** Markierte Artefakte, sonst das unter dem Cursor. */
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
      return kind === 'c' ? 62 : kind === 'a' ? 68 : 34
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
          t.clearCollected()
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
          hint="Jeder Chip ist ein Ausblende-Schalter: Klick versteckt seine Einträge, der nächste Klick holt sie zurück. False Positives und Info starten ausgeblendet.">
          <h1 className="mr-2 text-lg font-bold">Artefakte</h1>
        </Tooltip>
        {([['0', 'High', 'var(--sev-high)'], ['1', 'Medium', 'var(--sev-medium)'],
           ['2', 'Low', 'var(--sev-low)'], ['3', 'Info', 'var(--muted)']] as const
        ).map(([s, label, color]) => (
          <Tooltip key={s}
            hint={hiddenSeverity.has(s)
              ? `${label}-Artefakte sind ausgeblendet — Klick holt sie zurück.`
              : `Klick blendet ${label}-Artefakte aus.`}>
            <Chip active={false} dimmed={hiddenSeverity.has(s)}
              onClick={() => setHiddenSeverity((prev) => toggleHidden(prev, s))}
              count={counts?.severity[s] ?? 0}>
              <span className="h-2 w-2 rounded-full" style={{ background: color }} /> {label}
            </Chip>
          </Tooltip>
        ))}
        <span className="mx-1 h-4 w-px bg-[var(--line)]" />
        {(['new', 'confirmed', 'dismissed'] as const).map((state) => (
          <Tooltip key={state}
            hint={hiddenTriage.has(state)
              ? `${tr(`triage.${state}`)} ist ausgeblendet — Klick holt sie zurück.`
              : `Klick blendet »${tr(`triage.${state}`)}« aus.`}>
            <Chip active={false} dimmed={hiddenTriage.has(state)}
              onClick={() => setHiddenTriage((prev) => toggleHidden(prev, state))}
              count={counts?.triage[state] ?? 0}>
              {tr(`triage.${state}`)}
            </Chip>
          </Tooltip>
        ))}
        <span className="mx-1 h-4 w-px bg-[var(--line)]" />
        {['webshell', 'sqldb', 'logs'].map((key) => {
          const label = tr(`source.${key}`)
          return (
          <Tooltip key={key}
            hint={hiddenSource.has(key)
              ? `${label} ist ausgeblendet — Klick holt die Artefakte zurück.`
              : `Klick blendet Artefakte aus dieser Quelle aus.`}>
            <Chip active={false} dimmed={hiddenSource.has(key)}
              onClick={() => setHiddenSource((prev) => toggleHidden(prev, key))}
              count={counts?.source[key] ?? 0}>
              {label}
            </Chip>
          </Tooltip>
        )})}
        <div className="ml-auto">
          <SearchInput value={search} onChange={setSearch} placeholder="Regel, Pfad, Evidence…" />
        </div>
      </div>

      {!search && data && counts != null && counts.total > data.total && (
        <div className="flex flex-wrap items-center gap-2 text-[12px] text-[var(--muted)]">
          <span className="opacity-70">
            {formatCount(counts.total - data.total)} Artefakt{counts.total - data.total === 1 ? '' : 'e'} ausgeblendet
          </span>
          <button
            className="cursor-pointer rounded px-1.5 py-0.5 hover:bg-[var(--panel-2)] hover:text-[var(--fg)]"
            onClick={() => {
              setHiddenSeverity(new Set())
              setHiddenTriage(new Set())
              setHiddenSource(new Set())
            }}>
            alles einblenden
          </button>
        </div>
      )}

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

      {/* Kein `flex-1`: die Box ist so hoch wie ihr Inhalt und schrumpft
          erst, wenn die Liste länger wird als der Platz. Gestreckt auf die
          volle Höhe stand unter der letzten Zeile sonst eine leere Fläche,
          die aussah, als fehle da etwas. */}
      <div ref={parentRef}
        className="min-h-0 overflow-y-auto rounded-xl border border-[var(--line)] bg-[var(--panel)]">
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
              const tint = SEVERITY_VAR[c.worst]
              const CatIcon = CATEGORY_ICON[c.cat.id] ?? Bug
              return (
                <div key={'c' + c.cat.id}
                  className={clsx(
                    'absolute left-0 top-0 flex w-full items-center gap-3 pr-4',
                    'border-y border-[var(--line)]',
                    // Der Trennstrich nach oben nur, wenn eine Kategorie
                    // gerade ZU ist -- offen geht sie in ihre Artefakte über.
                    open ? 'border-b-transparent' : '')}
                  style={{
                    ...style,
                    // Ein Hauch des Schweregrads, der nach rechts ausläuft:
                    // die Kategorie hebt sich vom Rest ab, ohne dass eine
                    // volle Farbfläche die Namen darunter erschlägt.
                    background:
                      `linear-gradient(90deg, color-mix(in srgb, ${tint} 13%, var(--panel-2)) 0%,` +
                      ' var(--panel-2) 55%)',
                  }}>
                  <span className="h-full w-1 shrink-0" style={{ background: tint }} />
                  <input type="checkbox" className="ml-1 cursor-pointer accent-[var(--accent)]"
                    checked={allChecked}
                    ref={(el) => { if (el) el.indeterminate = someChecked }}
                    onChange={() => toggleCategoryChecked(c)}
                    title="Alle Artefakte dieser Kategorie markieren" />
                  <button onClick={() => toggleCategory(c)}
                    className="flex min-w-0 flex-1 cursor-pointer items-center gap-3 text-left">
                    {open
                      ? <ChevronDown size={16} className="shrink-0 text-[var(--muted)]" />
                      : <ChevronRight size={16} className="shrink-0 text-[var(--muted)]" />}
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl"
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
                        {' aus '}
                        {formatCount(c.findings)} Finding{c.findings === 1 ? '' : 's'}
                        {decided > 0 && ` · ${decided} entschieden`}
                      </div>
                    </div>
                  </button>
                  <SeverityBadge severity={c.worst} />
                  {/* Fortschritt: wie viel dieser Kategorie ist entschieden? */}
                  <Tooltip
                    title={`${decided} von ${c.artifacts.length} entschieden`}
                    hint={`${c.confirmed} True Positive · ${c.dismissed} False Positive · ${c.artifacts.length - decided} offen`}>
                    <div className="flex w-24 shrink-0 items-center gap-2">
                      <span className="flex h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--panel)]">
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
                    // Abgeblendet heißt ABGEARBEITET, nicht unwichtig: ein
                    // bestätigtes Artefakt bleibt stehen, tritt aber optisch
                    // zurück, damit das Offene die Liste führt.
                    a.triage === 'confirmed' && 'opacity-45')}
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
                      t.clearCollected()
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
                        <TriageBadge state={a.triage} label={tr(`triage.${a.triage}`)} />
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
                  item.a.triage === 'confirmed' && 'opacity-45')}
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
        collected={t.collected}
        onView={(path, line) => setViewing({ path, line })}
        onTrace={(ips, m) => { setTraceMarks(m); setTraceIps(ips) }}
        onClose={() => { setSelected(null); t.clearCollected() }}
        onTriage={(state, note) => {
          if (selected) t.decide([selected.artifact], state, note)
        }}
      />

      <TraceWindow slug={slug} ips={traceIps} layer={1} marks={traceMarks}
        onClose={() => setTraceIps(null)} />

      <FileViewer
        slug={slug}
        path={viewing?.path ?? null}
        focusLine={viewing?.line}
        layer={2}
        onClose={() => setViewing(null)}
      />

      <TriageFollowUp t={t} roots={roots} />
    </div>
  )
}

/** Die Regeln eines Artefakts als Chips unter seinem Namen — man sieht in
 *  der Liste, WORUM es geht, ohne aufzuklappen oder zu öffnen. Mehr als drei
 *  wären eine zweite Liste in der Liste; der Rest steht als Zahl daneben. */
function RuleChips({ items }: { items: Finding[] }) {
  const tr = useT()
  if (!items.length) return null
  const shown = items.slice(0, 3)
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
  const tr = useT()
  const e = explainRule(tr, rule)
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

