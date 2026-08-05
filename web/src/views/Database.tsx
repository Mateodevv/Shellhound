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
import { plural, useT } from '../i18n'
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
        // The wording of "created 3 days ago" differs per account; the chip
        // gathers them under one name.
        const label = s.id === 'young' ? tr('database.signal.young') : s.label
        const e = out.get(s.id) ?? { label, why: s.why, n: 0 }
        e.n += 1
        out.set(s.id, e)
      }
    }
    return [...out.entries()]
  }, [accounts, tr])

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

  // No export -- but possibly schema files. That is a DIFFERENT state from
  // "nothing analysed", and the difference is why someone stands here
  // puzzled: the folder did contain .sql files, just no database.
  if (data && !data.dumps.length) {
    return (
      <div className="flex flex-col gap-4">
        <EmptyState icon={<DatabaseIcon size={36} />}
          title={data.schema_files.length
            ? tr('database.empty.schemaOnly')
            : tr('database.empty.title')}
          sub={data.schema_files.length
            ? tr('database.onlySchema', { n: formatCount(data.schema_files.length) })
            : tr('database.empty.sub')} />
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
        body={tr('database.title.body')}
        hint={tr('database.title.hint')}>
        <h1 className="text-lg font-bold">Database</h1>
      </Tooltip>

      {/* ---- WORAUS wir lesen: der Export selbst ---- */}
      {data?.dumps.map((d) => <DumpCard key={d.id} dump={d} />)}

      {!!data?.schema_files.length && <SchemaCard files={data.schema_files} />}

      {/* ---- die Konten, nach Auffälligkeit ---- */}
      <Section title={tr('database.accounts')}
        sub={tr('database.accounts.sub')}
        right={
          <div className="flex items-center gap-2">
            <Tooltip hint={tr('database.csv.hint')}>
              <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] font-medium hover:border-[var(--accent)]/60"
                href={downloadUrl(`/api/cases/${slug}/database/accounts.csv`)}>
                <Download size={13} /> Alle
              </a>
            </Tooltip>
            <Tooltip hint={tr('database.csvAdmins.hint')}>
              <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] font-medium hover:border-[var(--accent)]/60"
                href={downloadUrl(`/api/cases/${slug}/database/accounts.csv?only=admins`)}>
                <Crown size={13} /> {tr('database.adminsOnly')}
              </a>
            </Tooltip>
            <SearchInput value={accountSearch} onChange={setAccountSearch}
              placeholder={tr('database.search')} />
          </div>
        }
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          {signalCounts.map(([id, s]) => (
            <Tooltip key={id} title={s.label} body={s.why}
              hint={hiddenSignals.has(id)
                ? tr('database.signal.hidden')
                : tr('database.signal.hide')}>
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
            {tr('database.accountCount', {
              shown: formatCount(visibleAccounts.length), total: formatCount(accounts.length),
            })}
            {admins > 0 && ` · ${tr('database.adminCount', { n: formatCount(admins) })}`}
          </span>
        </div>

        <Card className="overflow-hidden">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
                <th className="px-4 py-2">Login</th>
                <th className="px-2 py-2">E-Mail</th>
                <th className="px-2 py-2">{tr('database.signalsColumn')}</th>
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
                      <Tooltip hint={tr('database.noLastLogin')}>
                        <span className="opacity-60">{tr('database.notInDump')}</span>
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
                  {/* A dump cannot say that an account was planted -- the
                      analyst decides that. Hence a button, not a rule. */}
                  <td className="px-3 py-2 text-right">
                    {a.in_box ? (
                      <Tooltip hint={tr('database.loginInBox')}>
                        <Tag tone="accent">IOC</Tag>
                      </Tooltip>
                    ) : (
                      <Tooltip title={tr('database.flagAccount')}
                        body={tr('database.flagAccount.body')}
                        hint={tr('database.flagAccount.hint')}>
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
                ? tr('database.allHidden')
                : tr('database.noAccounts')}
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
        <Section title={tr('database.injected')}
          sub={tr('database.injected.sub')}>
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
                  {f.line ? `${tr('artifact.line')} ${f.line} — ` : ''}{f.evidence}
                </span>
                <TriageBadge state={f.triage} label={tr(`triage.${f.triage}`)} />
              </button>
            ))}
          </Card>
        </Section>
      )}

      {/* ---- the table inventory, tied to the case ---- */}
      <Section title={tr('database.tables')}
        sub={tr('database.tables.sub')
          + (data?.schema_tables
            ? ' ' + tr('database.schemaTablesNote', { n: formatCount(data.schema_tables) })
            : '')}
        right={
          <div className="flex items-center gap-2">
            {flaggedTables > 0 && (
              <Tooltip hint={tr('database.flaggedTables.hint')}>
                <Chip active={onlyFlaggedTables} count={flaggedTables}
                  onClick={() => setOnlyFlaggedTables(!onlyFlaggedTables)}>
                  {tr('database.withFindings')}
                </Chip>
              </Tooltip>
            )}
            <SearchInput value={tableSearch} onChange={setTableSearch} placeholder={tr('database.tableSearch')} />
          </div>
        }
      >
        <Card className="max-h-[420px] overflow-y-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead className="sticky top-0 z-10 bg-[var(--panel)]">
              <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
                <th className="px-4 py-2">{tr('kind.table')}</th>
                <th className="px-2 py-2">Findings</th>
                <th className="px-2 py-2 text-right">{tr('artifact.columns')}</th>
                <th className="px-2 py-2 text-right">{tr('table.rows')}</th>
                <th className="px-2 py-2 text-right">{tr('artifact.dumpBytes')}</th>
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
                      <Tooltip hint={tr('database.emptyTable')}>
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
  const tr = useT()
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
            {plural(tr, files.length, 'database.schemaFiles.one', 'database.schemaFiles.many',
                    { n: formatCount(files.length) })}
            {' '}<span className="font-normal text-[var(--muted)]">— {tr('database.noExport')}</span>
          </div>
          <div className="text-[11.5px] text-[var(--muted)]">
            {tr('database.schemaFiles.sub')}
          </div>
        </div>
        {flagged.length > 0 && (
          <Tag tone="danger" hint={tr('database.schemaFlagged')}>
            {formatCount(flagged.length)} {tr('database.withFindings')}
          </Tag>
        )}
        <span className="shrink-0 text-[11px] text-[var(--muted)]">
          {open ? tr('common.collapse') : tr('common.view')}
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
  const tr = useT()
  const meta = dump.meta ?? {}
  // Every fact explains itself -- they come from the HEAD of the dump that
  // the export tool wrote, and what is missing is as much a statement as
  // what is there.
  const facts: [string, string, string, string][] = [
    [tr('database.fact.database'), meta.database || '—',
     tr('database.fact.database.body'),
     tr('database.fact.database.hint')],
    [tr('database.fact.created'), meta.created || tr('database.fact.created.missing'),
     tr('database.fact.created.body'),
     tr('database.fact.created.hint')],
    [tr('database.fact.server'), meta.server || '—',
     tr('database.fact.server.body'),
     tr('database.fact.server.hint')],
    [tr('database.fact.tool'), [meta.tool, meta.tool_version].filter(Boolean).join(' ') || '—',
     tr('database.fact.tool.body'),
     tr('database.fact.tool.hint')],
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
