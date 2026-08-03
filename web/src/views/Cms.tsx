// Cms.tsx — das Inventar der Installationen: welches CMS, welche Version,
// welche Erweiterungen — und WELCHE DAVON KOMPROMITTIERT IST.
//
// EINE Liste pro Installation statt eines Kachel-Mosaiks: früher wurde jeder
// Engine-Typ eine eigene Karten-Tabelle, und Joomla produziert davon 10-15
// („Plugin (system)", „Plugin (content)" …) — unterschiedlich hohe Kacheln
// ohne Leserichtung. Jetzt falten sich die Typen auf 4-5 Gruppen zusammen
// (die Plugin-Gruppe und Site/Admin sind ein Zusatz an der Zeile, kein
// eigener Typ), und man liest einmal von oben nach unten.
//
// Der Fall-Bezug kommt vom Server: Erweiterungen mit geflaggten Dateien
// darunter tragen ein Badge und öffnen das Artefakt-Fenster — die Frage
// „welche Erweiterung ist es?" beantwortet die Seite selbst, statt den
// Pfad-Abgleich dem Kopf des Analysten zu überlassen.
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
  SEVERITY_VAR, absoluteTime, formatCount, shortPath, type EvidenceRoot,
} from '../format'
import {
  Button, Card, Chip, EmptyState, Modal, SearchInput, SeverityBadge, Tag,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { CMS_SCOPE_EXPLAIN, FIELD_EXPLAIN, explainPluginGroup } from '../explain'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp, useTriage } from '../components/triage'
import { TraceWindow } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import type { ViewId } from '../App'

// „Plugin (system)" -> Gruppe Plugin, Zusatz system; „Module (Admin)" ->
// Gruppe Module, Bereich Admin. Der Zusatz gehört an die Zeile, nicht in
// die Gliederung — sonst wird jede Plugin-Gruppe eine eigene Tabelle.
const SCOPES = new Set(['Site', 'Admin'])

// WO DIE ENGINE DEN BEREICH WEGLÄSST, IST ER TROTZDEM FESTGELEGT — nur
// leider nicht einheitlich: die Engine holt Komponenten unbenannt aus
// administrator/components (also Backend), Module und Templates dagegen
// unbenannt aus modules/ bzw. templates/ (also Frontend). Ein „Component"
// ohne Kennzeichnung neben einem „Module" ohne Kennzeichnung liest sich
// deshalb falsch. Hier wird der stille Bereich ausgeschrieben; der in der
// Datenbank gespeicherte Typ bleibt unangetastet, weil an ihm der Schlüssel
// der Versionskorrekturen hängt.
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

// Lesereihenfolge: das am häufigsten Manipulierte zuerst.
const TYPE_ORDER: Record<string, number> = {
  Plugin: 1, Theme: 2, Template: 3, Component: 4, Module: 5,
}

/** Worauf sich eine Versionskorrektur bezieht — Installation oder
 *  Erweiterung. Das Fenster ist für beide dasselbe. */
interface VersionTarget extends VersionFacts {
  kind: 'install' | 'item'
  id: number
  label: string
}

export function Cms({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const { data } = useQuery({
    queryKey: ['cms', slug],
    queryFn: () => api<{ installs: CmsInstall[] }>(`/api/cases/${slug}/cms`),
  })
  const [search, setSearch] = useState('')
  // Ausblende-Schalter wie überall: Typen und Versions-Zustand.
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set())
  const [hiddenVersion, setHiddenVersion] = useState<Set<string>>(new Set())

  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
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

  // Chip-Zähler über ALLE Installationen — eine Filterleiste für die Seite.
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
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title="CMS Inventory"
          body="Welche CMS-Installationen im Webroot stecken und welche Erweiterungen mit welcher Version installiert sind — und welche davon geflaggte Dateien enthalten."
          hint="Die Versionen gleichst du gegen bekannte Lücken ab (WPScan, Joomla VEL). Jeder Chip blendet seine Klasse aus; Klick auf ein Finding-Badge öffnet das Artefakt.">
          <h1 className="mr-2 text-lg font-bold">CMS Inventory</h1>
        </Tooltip>
        {typeCounts.map(([base, n]) => (
          <Tooltip key={base}
            hint={hiddenTypes.has(base)
              ? 'Ausgeblendet — Klick holt diese Einträge zurück.'
              : 'Klick blendet diesen Typ aus.'}>
            <Chip active={false} dimmed={hiddenTypes.has(base)}
              onClick={() => toggle(setHiddenTypes, base)} count={n}>
              {base}
            </Chip>
          </Tooltip>
        ))}
        {typeCounts.length > 0 && <span className="mx-1 h-4 w-px bg-[var(--line)]" />}
        <Tooltip hint="Klick blendet Erweiterungen mit erkannter Version aus — übrig bleiben die ohne Manifest.">
          <Chip active={false} dimmed={hiddenVersion.has('known')}
            onClick={() => toggle(setHiddenVersion, 'known')} count={versionCounts.known}>
            mit Version
          </Chip>
        </Tooltip>
        <Tooltip hint={FIELD_EXPLAIN.unknown_version}>
          <Chip active={false} dimmed={hiddenVersion.has('unknown')}
            onClick={() => toggle(setHiddenVersion, 'unknown')} count={versionCounts.unknown}>
            <TriangleAlert size={12} /> ohne Version
          </Chip>
        </Tooltip>
        <div className="ml-auto">
          <SearchInput value={search} onChange={setSearch} placeholder="Extension suchen…" />
        </div>
      </div>

      {installs.map((inst) => (
        <InstallCard key={inst.id} install={inst} visible={visible}
          filtering={Boolean(search || hiddenTypes.size || hiddenVersion.size)}
          onOpenArtifact={(stub) => { t.clearCollected(); setSelected(stub) }}
          onEditVersion={setVersionTarget} />
      ))}

      {data && !installs.length && (
        <EmptyState icon={<Puzzle size={36} />} title="Noch kein CMS erfasst"
          sub="Das Inventar entsteht aus dem Webroot. Registriere die Webroot-Kopie als Evidence und starte die Analyse — WordPress- und Joomla-Installationen werden mitsamt ihren Erweiterungen automatisch erkannt." />
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
        onTrace={(ips) => setTraceIps(ips)}
        onClose={() => { setSelected(null); t.clearCollected() }}
        onTriage={(state, note) => {
          if (selected) t.decide([selected.artifact], state, note)
        }}
      />
      <TraceWindow slug={slug} ips={traceIps} layer={1}
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
  const unknown = install.items.filter((i) => i.version === '(unknown)').length
  const flagged = install.items.filter((i) => i.flagged > 0).length
  // Zugeklappte Gruppen. Ein Filter oder eine Suche klappt alles auf — sonst
  // steckt der Treffer hinter einem Klick, den man nicht sieht.
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())

  // Eine Liste, gegliedert nach Basis-Typ — die Plugin-Gruppe steht als
  // Zusatz an der Zeile.
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
      // Geflaggtes zuerst — das ist, was man hier sucht.
      list.sort((a, b) => (b.flagged - a.flagged) || a.name.localeCompare(b.name))
    }
    return [...byBase.entries()].sort(
      (a, b) => (TYPE_ORDER[a[0]] ?? 99) - (TYPE_ORDER[b[0]] ?? 99))
  }, [install.items, visible])

  const shown = sections.reduce((n, [, list]) => n + list.length, 0)

  return (
    <Card className="overflow-hidden">
      {/* ---- der Kopf: die wichtigste Zahl der Seite ist die Version ---- */}
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
          <Server size={18} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-[15px] font-semibold tracking-tight">
            {install.cms}
            {install.version === '(unknown)'
              ? <Tag tone="warn" hint="Die Kern-Version ließ sich nicht bestimmen — bei einer manipulierten Installation selbst ein Befund.">Version unbekannt</Tag>
              : <span className="mono text-[var(--accent-text)]">{install.version}</span>}
            {install.version_set && (
              <Tag tone="accent"
                hint={`Von Hand gesetzt${install.version_parsed !== '(unknown)' ? ` — gemessen war ${install.version_parsed}` : ''}.`}>
                manuell
              </Tag>
            )}
          </div>
          <div className="mono truncate text-[11.5px] text-[var(--muted)]" title={install.root}>
            {install.root}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2 text-[12px] text-[var(--muted)]">
          {/* Kein `ghost`: auf dem ohnehin panel-2-farbenen Kopf wäre ein
              Knopf aus gedämpftem Text unsichtbar, bis man ihn zufällig
              überfährt. Ein Rahmen sagt „hier kann man klicken". */}
          <Tooltip hint="Version prüfen: zeigt die Datei, aus der sie gelesen wurde, und lässt sie von Hand setzen.">
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
              <PencilLine size={13} /> Version prüfen
            </Button>
          </Tooltip>
          <span>{formatCount(install.items.length)} Erweiterung{install.items.length === 1 ? '' : 'en'}</span>
          {unknown > 0 && (
            <Tag tone="warn" hint={FIELD_EXPLAIN.unknown_version}>{unknown} ohne Version</Tag>
          )}
          {flagged > 0 && (
            <Tag tone="danger"
              hint="Erweiterungen, unter deren Pfad geflaggte Dateien liegen — die Kandidaten für den Einstiegspunkt.">
              <Bug size={11} /> {flagged} mit Findings
            </Tag>
          )}
        </div>
      </div>

      {/* ---- eine Liste, Gruppen als aufklappbare Bänder ---- */}
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
                {/* Farbkante nur, wenn hier etwas gefunden wurde. */}
                <span className="h-8 w-1 shrink-0 rounded-full"
                  style={{ background: worstHit ? SEVERITY_VAR[worstHit.worst] : 'transparent' }} />
                <div className="min-w-0 flex-1">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="truncate text-[13px] font-medium">{item.name}</span>
                    {qualifier && (
                      <Tag explain={explainPluginGroup(qualifier).what}
                        hint={explainPluginGroup(qualifier).why}>
                        {qualifier}
                      </Tag>
                    )}
                    {scope && (
                      <Tag explain={CMS_SCOPE_EXPLAIN[scope]?.what}
                        hint={CMS_SCOPE_EXPLAIN[scope]?.why}>
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
                    title={`${item.flagged} geflaggte${item.flagged === 1 ? 's' : ''} Artefakt${item.flagged === 1 ? '' : 'e'} unter diesem Pfad`}
                    body={item.artifacts.map((a) => a.artifact).join('\n')}
                    hint="Klick öffnet das Artefakt — entscheiden wie in Findings."
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
                      <Bug size={11} /> {item.flagged} Artefakt{item.flagged === 1 ? '' : 'e'}
                    </button>
                  </Tooltip>
                )}
                {/* Die Versionszelle ist ein KNOPF: prüfen heißt, die Datei
                    aufzumachen, aus der die Zahl stammt. */}
                <Tooltip
                  title={item.version_set ? 'Von Hand gesetzt' : 'Version prüfen'}
                  body={item.version_source
                    ? `gelesen aus: ${item.version_source}`
                    : 'Keine Quelle — es wurde kein Manifest/Header gefunden.'}
                  hint={item.version_set
                    ? `Gemessen war: ${item.version_parsed}. Klick zum Ändern oder Zurücksetzen.`
                    : 'Klick öffnet die Quelldatei und lässt die Version von Hand setzen.'}
                  wide>
                  {/* Die Zelle sieht aus wie ein Eingabefeld, nicht wie
                      Text: Rahmen und Stift stehen IMMER da. Eine Fläche,
                      die sich erst beim Überfahren zu erkennen gibt, findet
                      man nur, wenn man ohnehin schon weiß, dass es sie
                      gibt. */}
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
                      'flex w-36 shrink-0 cursor-pointer items-center justify-between gap-1.5',
                      'rounded-lg border px-2 py-1 transition-colors',
                      'border-[var(--line)] bg-[var(--panel-2)] hover:border-[var(--accent)]/60',
                      item.version_set && 'border-[var(--accent)]/50')}>
                    <PencilLine size={11}
                      className={clsx('shrink-0',
                        item.version_set ? 'text-[var(--accent)]' : 'text-[var(--muted)]')} />
                    {item.version === '(unknown)'
                      ? <span className="text-[11px] text-[var(--sev-low)]">unbekannt</span>
                      : <span className="mono truncate text-[12px]">{item.version}</span>}
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
          Kein Eintrag entspricht Filter/Suche — durchgestrichene Chips holen
          Ausgeblendetes zurück.
        </div>
      )}
    </Card>
  )
}

/** Version prüfen und setzen.
 *
 *  Eine Versionsangabe ist eine BEHAUPTUNG des Manifests — und Manifeste
 *  lassen sich fälschen oder fehlen ganz. Deshalb zeigt dieses Fenster
 *  zuerst, WORAUS die Zahl gelesen wurde, und macht die Datei aufmachbar.
 *  Was der Analyst danach von Hand setzt, ersetzt den Messwert NICHT,
 *  sondern legt sich darüber: beides bleibt nebeneinander sichtbar, und die
 *  Korrektur überlebt jede Re-Analyse. */
function VersionWindow({ slug, target, onClose, onView }: {
  slug: string
  target: VersionTarget | null
  onClose: () => void
  onView: (path: string) => void
}) {
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
        <span className="truncate">Version prüfen — {target.label}</span>
      </span>}>
      <div className="flex flex-col gap-4">
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="rounded-lg bg-[var(--panel-2)] px-3 py-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              Gemessen
            </div>
            <div className="mono mt-0.5 text-[13px]">
              {target.version_parsed === '(unknown)'
                ? <span className="text-[var(--sev-low)]">nicht gefunden</span>
                : target.version_parsed}
            </div>
          </div>
          <div className="rounded-lg bg-[var(--panel-2)] px-3 py-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              Gilt aktuell
            </div>
            <div className="mono mt-0.5 flex items-center gap-2 text-[13px]">
              {target.version === '(unknown)' ? '—' : target.version}
              {target.version_set && <Tag tone="accent">manuell</Tag>}
            </div>
          </div>
        </div>

        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            Quelle der Angabe
          </div>
          {source ? (
            <div className="flex flex-wrap items-center gap-2">
              <span className="mono min-w-0 flex-1 truncate rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[11.5px]"
                title={source}>
                {source}
              </span>
              <Button onClick={() => onView(source)}>
                <FileSearch size={14} /> Datei ansehen
              </Button>
            </div>
          ) : (
            <p className="text-[12.5px] text-[var(--muted)]">
              Es wurde kein Manifest und kein Header gefunden — deshalb steht
              hier keine Version. Genau das ist bei einer manipulierten oder
              unvollständigen Erweiterung der Normalfall: die Version musst du
              anders belegen (Changelog, Paketquelle, Dateivergleich) und dann
              hier eintragen.
            </p>
          )}
        </div>

        <div>
          <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            Version von Hand setzen
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder="z.B. 5.3.1"
              className="mono w-40 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
            />
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Woher weißt du das? (wandert ins Fall-Archiv)"
              className="min-w-56 flex-1 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70"
            />
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Button variant="primary" disabled={!value.trim() || save.isPending}
              onClick={() => save.mutate({ version: value.trim(), note })}>
              <Check size={14} /> Setzen
            </Button>
            {target.version_set && (
              <Button disabled={save.isPending}
                onClick={() => save.mutate({ version: '', note: '' })}>
                <RotateCcw size={14} /> Auf gemessenen Wert zurück
              </Button>
            )}
            <Button variant="ghost" onClick={onClose}>Abbrechen</Button>
            {target.version_set_at && (
              <span className="text-[11px] text-[var(--muted)]">
                gesetzt: {absoluteTime(target.version_set_at)}
              </span>
            )}
          </div>
          <p className="mt-2 text-[11px] text-[var(--muted)]">
            Der gemessene Wert bleibt erhalten und daneben sichtbar — eine
            Korrektur ersetzt die Messung nicht, sie überlagert sie. Sie
            überlebt auch eine erneute Analyse.
          </p>
        </div>
      </div>
    </Modal>
  )
}
