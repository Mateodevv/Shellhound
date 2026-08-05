// Database.tsx — was der Datenbank-Export hergibt.
//
// Die Seite beantwortet EINE Frage: was hat der Angreifer in der Datenbank
// hinterlassen? Deshalb steht oben, WORAUS wir das lesen (welcher Export,
// wann erstellt — ein Dump von VOR dem Vorfall zeigt einen anderen Zustand
// als einer von danach), dann der eingeschleuste Code, dann die Konten.
//
// Die Konten sind der heikelste Teil: ein Dump kann nicht sagen, dass ein
// Admin bösartig ist — nur, dass er existiert, gestern angelegt wurde und
// sich nie angemeldet hat. Deshalb stehen an jedem Konto BENANNTE
// Beobachtungen und keine Punktzahl; sie bestimmen nur die Reihenfolge,
// damit die eine auffällige Zeile nicht in 400 gewöhnlichen untergeht.
import { useT } from '../i18n'
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box, Clock, Crown, Database as DatabaseIcon, Download, FileCode2, HelpCircle,
  KeyRound, Table2,
} from 'lucide-react'
import clsx from 'clsx'
import {
  api, downloadUrl, post, type CaseDetail, type DbAccount, type DbDump,
  type DbTable, type Finding,
} from '../api'
import {
  SEVERITY_VAR, baseName, formatBytes, formatCount,
  type EvidenceRoot,
} from '../format'
import {
  Button, Card, Chip, EmptyState, SearchInput, Section, SeverityBadge, Tag,
  TriageBadge,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { TraceWindow } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import type { ViewId } from '../App'

interface DatabaseData {
  dumps: DbDump[]
  /** Mit Erweiterungen ausgelieferte install/uninstall/update-SQL — kein
   *  Export, aber weiter auf eingeschleusten Code geprüft. */
  schema_files: DbDump[]
  tables: DbTable[]
  /** Wie viele Tabellen aus Schema-Dateien nicht im Inventar stehen. */
  schema_tables: number
  accounts: DbAccount[]
  findings: Finding[]
  /** Bezugszeitpunkt für „jung": Erstellung des Dumps, sonst jüngstes Konto. */
  reference: string
}

export function DatabaseView({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['database', slug],
    queryFn: () => api<DatabaseData>(`/api/cases/${slug}/database`),
  })
  const [hiddenSignals, setHiddenSignals] = useState<Set<string>>(new Set())
  const [accountSearch, setAccountSearch] = useState('')
  const [tableSearch, setTableSearch] = useState('')
  const [onlyFlaggedTables, setOnlyFlaggedTables] = useState(false)

  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const t = useTriage(slug)

  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))

  const accounts = useMemo(() => data?.accounts ?? [], [data])

  const flagAccount = useMutation({
    mutationFn: (account_id: number) => post<{ added: { value: string }[] }>(
      `/api/cases/${slug}/database/accounts/flag`, { account_id }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['database'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })

  // Wie oft kommt jede Beobachtung vor — die Zahlen auf den Chips.
  const signalCounts = useMemo(() => {
    const out = new Map<string, { label: string; why: string; n: number }>()
    for (const a of accounts) {
      for (const s of a.signals) {
        // Der Text von „vor 3 Tagen angelegt" ist je Konto anders; der Chip
        // fasst sie unter einem Namen zusammen.
        const label = s.id === 'young' ? 'kürzlich angelegt' : s.label
        const e = out.get(s.id) ?? { label, why: s.why, n: 0 }
        e.n += 1
        out.set(s.id, e)
      }
    }
    return [...out.entries()]
  }, [accounts])

  const visibleAccounts = useMemo(() => accounts.filter((a) => {
    if (a.signals.some((s) => hiddenSignals.has(s.id))) return false
    const q = accountSearch.toLowerCase()
    if (q && !a.login.toLowerCase().includes(q) &&
        !a.email.toLowerCase().includes(q)) return false
    return true
  }), [accounts, hiddenSignals, accountSearch])

  const tables = useMemo(() => (data?.tables ?? []).filter((t2) =>
    (!onlyFlaggedTables || t2.flagged > 0) &&
    (!tableSearch || t2.name.toLowerCase().includes(tableSearch.toLowerCase()))),
    [data, tableSearch, onlyFlaggedTables])

  // Kein Export — aber vielleicht Schema-Dateien. Das ist ein ANDERER
  // Zustand als "nichts analysiert", und der Unterschied ist der Grund,
  // warum jemand hier ratlos steht: der Ordner enthielt .sql-Dateien, nur
  // eben keine Datenbank.
  if (data && !data.dumps.length) {
    return (
      <div className="flex flex-col gap-4">
        <EmptyState icon={<DatabaseIcon size={36} />}
          title={data.schema_files.length
            ? 'Kein Datenbank-Export dabei'
            : 'Noch kein Datenbank-Export analysiert'}
          sub={data.schema_files.length
            ? `Gefunden wurden ${formatCount(data.schema_files.length)} SQL-Dateien, die mit Erweiterungen ausgeliefert werden (install/uninstall/updates) — sie legen Tabellen an, enthalten aber keine Daten und keine Konten. Registriere zusätzlich einen echten Export (mysqldump, .sql/.sql.gz), um Konten und eingeschleusten Code zu sehen.`
            : 'Diese Ansicht liest den Datenbank-Export des CMS (mysqldump, .sql/.sql.gz). Registriere ihn als Evidence und starte die Analyse — dann stehen hier die Benutzerkonten und in Datenfelder eingeschleuster Code.'} />
        {data.schema_files.length > 0 && <SchemaCard files={data.schema_files} />}
      </div>
    )
  }

  const admins = accounts.filter((a) => a.admin).length
  const flaggedTables = (data?.tables ?? []).filter((t2) => t2.flagged > 0).length
  const openArtifact = (stub: ArtifactStub) => { t.clearCollected(); setSelected(stub) }

  return (
    <div className="flex flex-col gap-6">
      <Tooltip title="Database"
        body="Was der Datenbank-Export des CMS verrät: Konten, eingeschleuster Code, das Tabellen-Inventar."
        hint="Kein Live-Zugriff — analysiert wird der exportierte Dump. Ein untergeschobener Admin oder PHP in einer Datenspalte übersteht jedes Bereinigen der Dateien.">
        <h1 className="text-lg font-bold">Database</h1>
      </Tooltip>

      {/* ---- WORAUS wir lesen: der Export selbst ---- */}
      {data?.dumps.map((d) => <DumpCard key={d.id} dump={d} />)}

      {!!data?.schema_files.length && <SchemaCard files={data.schema_files} />}

      {/* ---- die Konten, nach Auffälligkeit ---- */}
      <Section title="Konten"
        sub="Ein Dump kann nicht sagen, dass ein Admin bösartig ist — nur, was an ihm auffällt. Die Beobachtungen bestimmen die Reihenfolge, die Bewertung bleibt bei dir."
        right={
          <div className="flex items-center gap-2">
            <Tooltip hint="Konten als CSV — die Grundlage für die Passwort-Reset-Liste. Ohne Hashes: dieses Werkzeug dokumentiert, es bereitet keinen Angriff vor.">
              <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] font-medium hover:border-[var(--accent)]/60"
                href={downloadUrl(`/api/cases/${slug}/database/accounts.csv`)}>
                <Download size={13} /> Alle
              </a>
            </Tooltip>
            <Tooltip hint="Nur Konten mit vollen Rechten — die Liste, mit der ein Reset anfängt.">
              <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] font-medium hover:border-[var(--accent)]/60"
                href={downloadUrl(`/api/cases/${slug}/database/accounts.csv?only=admins`)}>
                <Crown size={13} /> Nur Admins
              </a>
            </Tooltip>
            <SearchInput value={accountSearch} onChange={setAccountSearch}
              placeholder="Login oder E-Mail…" />
          </div>
        }
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          {signalCounts.map(([id, s]) => (
            <Tooltip key={id} title={s.label} body={s.why}
              hint={hiddenSignals.has(id)
                ? 'Ausgeblendet — Klick holt diese Konten zurück.'
                : 'Klick blendet Konten mit dieser Beobachtung aus.'}>
              <Chip active={false} dimmed={hiddenSignals.has(id)} count={s.n}
                onClick={() => setHiddenSignals((prev) => {
                  const next = new Set(prev)
                  if (next.has(id)) next.delete(id)
                  else next.add(id)
                  return next
                })}>
                {s.label}
              </Chip>
            </Tooltip>
          ))}
          <span className="text-[11.5px] text-[var(--muted)]">
            {formatCount(visibleAccounts.length)} von {formatCount(accounts.length)} Konten
            {admins > 0 && ` · ${formatCount(admins)} mit vollen Rechten`}
          </span>
        </div>

        <Card className="overflow-hidden">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
                <th className="px-4 py-2">Login</th>
                <th className="px-2 py-2">E-Mail</th>
                <th className="px-2 py-2">Auffällig</th>
                <th className="px-2 py-2">Registriert</th>
                <th className="px-2 py-2">Letzter Login</th>
                <th className="px-2 py-2">Hash</th>
                <th className="px-2 py-2">Herkunft</th>
                <th className="w-24 px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {visibleAccounts.map((a) => (
                <tr key={a.id}
                  className={clsx('group border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]',
                    a.admin && 'bg-[rgba(208,59,59,0.05)]')}>
                  <td className="mono px-4 py-2 font-medium">
                    <span className="flex items-center gap-1.5">
                      {a.admin === 1 && (
                        <Tooltip hint={tr('field.admin_account')}>
                          <Crown size={13} className="text-[var(--sev-high)]" />
                        </Tooltip>
                      )}
                      <span className={clsx(a.blocked === 1 && 'line-through opacity-60')}>
                        {a.login}
                      </span>
                    </span>
                  </td>
                  <td className="px-2 py-2 text-[12px]">{a.email}</td>
                  <td className="px-2 py-2">
                    <div className="flex flex-wrap gap-1">
                      {a.signals.length
                        ? a.signals.map((s) => (
                          <Tag key={s.id} explain={s.label} hint={s.why}
                            tone={s.id === 'admin' ? 'danger'
                              : s.id === 'young' || s.id === 'never' ? 'warn' : undefined}>
                            {s.label}
                          </Tag>
                        ))
                        : <span className="text-[11.5px] text-[var(--muted)]">—</span>}
                    </div>
                  </td>
                  <td className="px-2 py-2 text-[12px] text-[var(--muted)]">{a.registered}</td>
                  <td className="px-2 py-2 text-[12px] text-[var(--muted)]">
                    {a.last_login || (
                      <Tooltip hint="Der Export enthält dazu nichts — WordPress führt den letzten Login im Kern nicht. Das heißt NICHT »nie angemeldet«.">
                        <span className="opacity-60">nicht im Dump</span>
                      </Tooltip>
                    )}
                  </td>
                  <td className="px-2 py-2">
                    {a.hash_type.includes('weak')
                      ? <Tag tone="warn" hint={tr('field.weak_hash')}>{a.hash_type}</Tag>
                      : <span className="text-[12px] text-[var(--muted)]">{a.hash_type}</span>}
                  </td>
                  <td className="mono px-2 py-2 text-[11px] text-[var(--muted)]">
                    {a.cms} · {a.tbl}
                  </td>
                  {/* Ein Dump kann nicht sagen, dass ein Konto
                      untergeschoben wurde — das entscheidet der Analyst.
                      Deshalb ein Knopf und keine Regel. */}
                  <td className="px-3 py-2 text-right">
                    {a.in_box ? (
                      <Tooltip hint="Der Login liegt bereits in der IOC Box.">
                        <Tag tone="accent">IOC</Tag>
                      </Tooltip>
                    ) : (
                      <Tooltip title="Konto als Indikator aufnehmen"
                        body="Nimmt den Login in die IOC Box — und die E-Mail als eigenen, damit verknüpften Eintrag."
                        hint="Der Login ist der Indikator, nicht die Zeile: unter diesem Namen meldet sich jemand wieder an, und danach sucht man in anderen Systemen.">
                        <Button variant="ghost" disabled={flagAccount.isPending}
                          className="opacity-0 transition-opacity group-hover:opacity-100"
                          onClick={() => flagAccount.mutate(a.id)}>
                          <Box size={13} /> IOC
                        </Button>
                      </Tooltip>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!visibleAccounts.length && (
            <div className="px-4 py-6 text-center text-[13px] text-[var(--muted)]">
              {accounts.length
                ? 'Alle Konten sind ausgeblendet — durchgestrichene Chips holen sie zurück.'
                : 'Keine Konten im Dump gefunden.'}
            </div>
          )}
        </Card>
      </Section>

      {/* ---- der eingeschleuste Code, jetzt anklickbar ----
          NACH den Konten: wer diese Ansicht öffnet, sucht zuerst das
          untergeschobene Konto. Der eingeschleuste Code ist der zweite
          Befund, und er liest sich erst richtig, wenn man weiß, wessen
          Konto ihn geschrieben haben könnte. */}
      {data && data.findings.length > 0 && (
        <Section title="Eingeschleuster Code in Datenfeldern"
          sub="Ein CMS speichert Code in Dateien, nie in der Datenbank. Klick auf eine Zeile öffnet die Tabelle als Artefakt — entscheiden wie in Findings.">
          <Card className="overflow-hidden">
            {data.findings.map((f) => (
              <button key={f.fingerprint}
                onClick={() => openArtifact({
                  artifact: f.artifact, artifact_kind: 'table',
                  worst: f.severity, triage: f.triage, triage_note: f.triage_note,
                })}
                className={clsx(
                  'flex w-full cursor-pointer items-center gap-3 border-b border-[var(--line-soft)]',
                  'px-4 py-2 text-left transition-colors last:border-0 hover:bg-[var(--panel-2)]',
                  f.triage === 'confirmed' && 'opacity-45')}>
                <span className="h-6 w-1 shrink-0 rounded-full"
                  style={{ background: SEVERITY_VAR[f.severity] }} />
                <SeverityBadge severity={f.severity} />
                <span className="mono w-40 shrink-0 truncate text-[12px] font-medium">
                  {f.artifact}
                </span>
                <span className="w-56 shrink-0 truncate text-[12.5px]">{f.rule}</span>
                <span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]"
                  title={f.evidence}>
                  {f.line ? `Zeile ${f.line} — ` : ''}{f.evidence}
                </span>
                <TriageBadge state={f.triage} label={tr(`triage.${f.triage}`)} />
              </button>
            ))}
          </Card>
        </Section>
      )}

      {/* ---- das Tabellen-Inventar, mit Fall-Bezug ---- */}
      <Section title="Tabellen im Dump"
        sub={'Auch leere Tabellen stehen hier — »existiert und ist leer« ist eine andere Aussage als »nicht im Dump«, und nur eine davon kann bedeuten, dass jemand geleert hat.'
          + (data?.schema_tables
            ? ` ${formatCount(data.schema_tables)} Tabellen aus mitgelieferten Schema-Dateien sind nicht aufgeführt — sie sagen nur, was eine Erweiterung anlegen WÜRDE.`
            : '')}
        right={
          <div className="flex items-center gap-2">
            {flaggedTables > 0 && (
              <Tooltip hint="Nur Tabellen, auf denen Findings sitzen.">
                <Chip active={onlyFlaggedTables} count={flaggedTables}
                  onClick={() => setOnlyFlaggedTables(!onlyFlaggedTables)}>
                  mit Findings
                </Chip>
              </Tooltip>
            )}
            <SearchInput value={tableSearch} onChange={setTableSearch} placeholder="Tabelle suchen…" />
          </div>
        }
      >
        <Card className="max-h-[420px] overflow-y-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead className="sticky top-0 z-10 bg-[var(--panel)]">
              <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
                <th className="px-4 py-2">Tabelle</th>
                <th className="px-2 py-2">Findings</th>
                <th className="px-2 py-2 text-right">Spalten</th>
                <th className="px-2 py-2 text-right">Zeilen</th>
                <th className="px-2 py-2 text-right">Dump-Bytes</th>
              </tr>
            </thead>
            <tbody>
              {tables.map((t2) => (
                <tr key={t2.id}
                  className="border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]">
                  <td className="mono px-4 py-1.5 text-[12px]">
                    <span className="flex items-center gap-2">
                      <Table2 size={12} className="shrink-0 text-[var(--muted)]" />
                      {t2.name}
                    </span>
                  </td>
                  <td className="px-2 py-1.5">
                    {t2.flagged > 0 && t2.worst != null ? (
                      <button
                        onClick={() => openArtifact({
                          artifact: t2.name, artifact_kind: 'table',
                          worst: t2.worst!, triage: t2.triage ?? 'new',
                          triage_note: '',
                        })}
                        className="inline-flex cursor-pointer items-center gap-1 rounded-md bg-[var(--danger-soft)] px-2 py-0.5 text-[11px] font-medium text-[var(--danger-text)]">
                        {t2.flagged} Finding{t2.flagged === 1 ? '' : 's'}
                      </button>
                    ) : (
                      <span className="text-[11px] text-[var(--muted)]">—</span>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-right tabular text-[12px]">{t2.columns}</td>
                  <td className={clsx('px-2 py-1.5 text-right tabular text-[12px]',
                    !t2.rows && 'text-[var(--sev-low)]')}>
                    {t2.rows ? formatCount(t2.rows) : (
                      <Tooltip hint="Die Tabelle existiert im Dump, enthält aber keine Zeile. Bei Tabellen, die normalerweise gefüllt sind, ist das eine Frage wert.">
                        <span>leer</span>
                      </Tooltip>
                    )}
                  </td>
                  <td className="px-2 py-1.5 text-right tabular text-[12px] text-[var(--muted)]">
                    {formatBytes(t2.bytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!tables.length && (
            <div className="px-4 py-6 text-center text-[13px] text-[var(--muted)]">
              Keine Tabelle entspricht Filter/Suche.
            </div>
          )}
        </Card>
      </Section>

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

/** Die mitgelieferten SQL-Dateien der Erweiterungen — zusammengefaltet.
 *
 *  Ein Webroot enthält Dutzende davon (install/uninstall/updates je
 *  Erweiterung). Als Datenbank-Evidence sind sie wertlos: keine Daten, keine
 *  Konten, kein Export-Kopf. Sie verschwinden deshalb aus der Export-Ansicht
 *  — aber NICHT aus der Prüfung: eine manipulierte install.sql läuft bei der
 *  nächsten Installation wieder an und überlebt jedes Aufräumen im
 *  Dateisystem. Trägt eine von ihnen Findings, steht das hier vorne. */
function SchemaCard({ files }: { files: DbDump[] }) {
  const [open, setOpen] = useState(false)
  const flagged = files.filter((f) => (f.flagged ?? 0) > 0)
  return (
    <Card className="overflow-hidden">
      <button onClick={() => setOpen(!open)}
        className="flex w-full cursor-pointer items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-[var(--panel-2)]">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-[var(--panel-2)] text-[var(--muted)]">
          <FileCode2 size={16} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-[13.5px] font-semibold">
            {formatCount(files.length)} mitgelieferte SQL-Datei{files.length === 1 ? '' : 'en'}
            {' '}<span className="font-normal text-[var(--muted)]">— kein Export</span>
          </div>
          <div className="text-[11.5px] text-[var(--muted)]">
            install/uninstall/update-Skripte von Erweiterungen: sie legen
            Tabellen an, enthalten aber keine Daten und keine Konten.
          </div>
        </div>
        {flagged.length > 0 && (
          <Tag tone="danger" hint="Eine mitgelieferte SQL-Datei mit eingeschleustem Code ist ein Persistenz-Trick: sie läuft bei der nächsten Installation oder beim Update wieder an.">
            {formatCount(flagged.length)} mit Findings
          </Tag>
        )}
        <span className="shrink-0 text-[11px] text-[var(--muted)]">
          {open ? 'zuklappen' : 'ansehen'}
        </span>
      </button>
      {open && (
        <div className="border-t border-[var(--line)]">
          {files.map((f) => (
            <div key={f.id}
              className="flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-1.5 text-[12px] last:border-0">
              <span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]"
                title={f.path}>
                {f.path}
              </span>
              {(f.flagged ?? 0) > 0 && (
                <Tag tone="danger">{f.flagged} Finding{f.flagged === 1 ? '' : 's'}</Tag>
              )}
              <span className="shrink-0 tabular text-[11px] text-[var(--muted)]">
                {formatBytes(f.size)}
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}

/** Der Export selbst — der Bezugsrahmen für alles darunter. Der
 *  ERSTELLUNGSZEITPUNKT ist die wichtigste Angabe: ein Dump von vor dem
 *  Vorfall zeigt einen anderen Zustand als einer von danach, und davon
 *  hängt ab, ob ein fehlender Admin etwas bedeutet. */
function DumpCard({ dump }: { dump: DbDump }) {
  const meta = dump.meta ?? {}
  // Jede Angabe erklärt sich selbst — sie stammen aus dem KOPF des Dumps,
  // den das Export-Werkzeug geschrieben hat, und was fehlt, ist genauso eine
  // Aussage wie was dasteht.
  const facts: [string, string, string, string][] = [
    ['Datenbank', meta.database || '—',
     'Der Name des Schemas, aus dem exportiert wurde.',
     'Bei mehreren Instanzen auf einem Server entscheidet er, ob dieser Dump überhaupt zu dem Webroot gehört, den du untersuchst.'],
    ['Erstellt', meta.created || 'nicht im Kopf des Dumps vermerkt',
     'Der Zeitstempel, den das Export-Werkzeug geschrieben hat.',
     'Die wichtigste Angabe der Karte: ein Dump von VOR dem Vorfall zeigt einen anderen Zustand als einer von danach — davon hängt ab, ob ein fehlendes Konto etwas bedeutet. Ohne ihn ist unklar, welchen Stand dieser Dump zeigt.'],
    ['Server', meta.server || '—',
     'Die MySQL-/MariaDB-Version, die den Export erzeugt hat.',
     'Eine alte Version erklärt manchmal, warum ein Angriff funktioniert hat — und sie sagt, wohin der Dump sich zurückspielen lässt.'],
    ['Werkzeug', [meta.tool, meta.tool_version].filter(Boolean).join(' ') || '—',
     'Womit exportiert wurde (mysqldump, phpMyAdmin, ein Plugin).',
     'Das Werkzeug bestimmt, WAS im Dump steht: manche Backup-Plugins lassen Sitzungen oder Log-Tabellen weg. Fehlt hier etwas, fehlt es womöglich auch in den Daten.'],
  ]
  return (
    <Card className="overflow-hidden">
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-3">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]">
          <DatabaseIcon size={18} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 text-[15px] font-semibold tracking-tight">
            {baseName(dump.path)}
            {dump.cms && <Tag tone="accent">{dump.cms}</Tag>}
          </div>
          <div className="mono truncate text-[11.5px] text-[var(--muted)]" title={dump.path}>
            {dump.path}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-3 text-[12px] text-[var(--muted)]">
          <span>{formatBytes(dump.size)}</span>
          <span>{formatCount(dump.statements)} Statements</span>
        </div>
      </div>
      <div className="grid gap-2 px-4 py-3 sm:grid-cols-2 lg:grid-cols-4">
        {facts.map(([label, value, body, hint]) => (
          <Tooltip key={label} title={label} body={body} hint={hint}
            as="div" className="!block rounded-lg bg-[var(--panel-2)] px-3 py-2">
            {/* Das Fragezeichen ist die Einladung: ohne es hovert niemand
                über einer Kennzahl, und die Erklärung bliebe ungelesen. */}
            <div className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
              {label === 'Erstellt' && <Clock size={10} />}
              {label === 'Server' && <KeyRound size={10} className="opacity-0" />}
              {label}
              <HelpCircle size={10} className="ml-auto shrink-0 opacity-50" />
            </div>
            <div className="mt-0.5 truncate text-[12px]" title={value}>{value}</div>
          </Tooltip>
        ))}
      </div>
    </Card>
  )
}
