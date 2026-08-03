// Database.tsx — was der SQL-Dump hergibt: Accounts (Admins zuerst),
// Injected-Code-Findings, Tabellen-Inventar, Dump-Metadaten.
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Crown, Database as DatabaseIcon, ShieldAlert } from 'lucide-react'
import clsx from 'clsx'
import {
  api, type DbAccount, type DbDump, type DbTable, type Finding,
} from '../api'
import { baseName, formatBytes, formatCount } from '../format'
import {
  Card, Chip, EmptyState, SearchInput, Section, SeverityBadge, Tag,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { FIELD_EXPLAIN } from '../explain'
import type { ViewId } from '../App'

interface DatabaseData {
  dumps: DbDump[]
  tables: DbTable[]
  accounts: DbAccount[]
  findings: Finding[]
}

export function DatabaseView({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const { data } = useQuery({
    queryKey: ['database', slug],
    queryFn: () => api<DatabaseData>(`/api/cases/${slug}/database`),
  })
  const [onlyAdmins, setOnlyAdmins] = useState(false)
  const [tableSearch, setTableSearch] = useState('')

  const accounts = useMemo(() =>
    (data?.accounts ?? []).filter((a) => !onlyAdmins || a.admin),
    [data, onlyAdmins])
  const tables = useMemo(() =>
    (data?.tables ?? []).filter((t) =>
      !tableSearch || t.name.toLowerCase().includes(tableSearch.toLowerCase())),
    [data, tableSearch])

  if (data && !data.dumps.length) {
    return (
      <EmptyState icon={<DatabaseIcon size={36} />} title="Noch kein Datenbank-Export analysiert"
        sub="Diese Ansicht liest den Datenbank-Export des CMS (mysqldump, .sql/.sql.gz). Registriere ihn als Evidence und starte die Analyse — dann stehen hier die Benutzerkonten und in Datenfelder eingeschleuster Code." />
    )
  }

  const admins = data?.accounts.filter((a) => a.admin).length ?? 0

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-2">
        <Tooltip title="Database"
          body="Was der Datenbank-Export des CMS verrät: Benutzerkonten (Admins zuerst) und Code, der in Datenfelder eingeschleust wurde."
          hint="Kein Live-Zugriff — analysiert wird der exportierte Dump. Ein rogue-Admin oder PHP in einer Datenspalte übersteht jedes Bereinigen der Dateien.">
          <h1 className="text-lg font-bold">Database</h1>
        </Tooltip>
        {data?.dumps.map((d) => (
          <Tag key={d.id} tone="accent">
            {baseName(d.path)} · {d.cms || 'CMS unbekannt'} · {formatBytes(d.size)}
          </Tag>
        ))}
      </div>

      {data && data.findings.length > 0 && (
        <Section title="Injected Code in Daten"
          sub="Ausführbarer PHP-/Script-Code in Datenspalten — ein CMS speichert Code in Dateien, nie in der Datenbank. Triage in der Findings-View.">
          <Card className="overflow-hidden">
            <table className="w-full border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-2 py-2">Tabelle</th>
                  <th className="px-2 py-2">Regel</th>
                  <th className="px-2 py-2 text-right">Zeile</th>
                  <th className="px-2 py-2">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {data.findings.map((f) => (
                  <tr key={f.fingerprint}
                    className={clsx('border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]',
                      f.triage === 'dismissed' && 'opacity-45')}>
                    <td className="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
                    <td className="mono px-2 py-2 text-[12px]">{f.artifact}</td>
                    <td className="px-2 py-2">{f.rule}</td>
                    <td className="px-2 py-2 text-right tabular text-[12px]">{f.line ?? '—'}</td>
                    <td className="mono max-w-[380px] truncate px-2 py-2 text-[11px] text-[var(--muted)]"
                      title={f.evidence}>
                      {f.evidence}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </Section>
      )}

      <Section title="Accounts"
        sub="Die Account-Liste ist Evidence: ein Dump kann nicht sagen, dass ein Admin bösartig ist — nur, dass er existiert. Unbekannte Admins und junge Registrierungen prüfen."
        right={
          <Tooltip hint={FIELD_EXPLAIN.admin_account}>
            <Chip active={onlyAdmins} onClick={() => setOnlyAdmins(!onlyAdmins)} count={admins}>
              <Crown size={12} /> Nur Admins / Super User
            </Chip>
          </Tooltip>
        }
      >
        <Card className="overflow-hidden">
          <table className="w-full border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
                <th className="px-4 py-2">Login</th>
                <th className="px-2 py-2">Rolle</th>
                <th className="px-2 py-2">E-Mail</th>
                <th className="px-2 py-2">Registriert</th>
                <th className="px-2 py-2">Passwort-Hash</th>
                <th className="px-2 py-2">CMS / Tabelle</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((a) => (
                <tr key={a.id}
                  className={clsx('border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]',
                    a.admin && 'bg-[rgba(208,59,59,0.05)]')}>
                  <td className="mono px-4 py-2 font-medium">
                    <span className="flex items-center gap-1.5">
                      {a.admin === 1 && <ShieldAlert size={13} className="text-[var(--sev-high)]" />}
                      {a.login}
                    </span>
                  </td>
                  <td className="px-2 py-2">
                    {a.admin
                      ? <Tag tone="danger" hint={FIELD_EXPLAIN.admin_account}>
                          {a.cms === 'Joomla' ? 'Super User' : 'Administrator'}
                        </Tag>
                      : <span className="text-[12px] text-[var(--muted)]">User</span>}
                  </td>
                  <td className="px-2 py-2 text-[12px]">{a.email}</td>
                  <td className="px-2 py-2 text-[12px] text-[var(--muted)]">{a.registered}</td>
                  <td className="px-2 py-2">
                    {a.hash_type.includes('weak')
                      ? <Tag tone="warn" hint={FIELD_EXPLAIN.weak_hash}>{a.hash_type}</Tag>
                      : <span className="text-[12px] text-[var(--muted)]">{a.hash_type}</span>}
                  </td>
                  <td className="mono px-2 py-2 text-[11px] text-[var(--muted)]">
                    {a.cms} · {a.tbl}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!accounts.length && (
            <div className="px-4 py-6 text-center text-[13px] text-[var(--muted)]">
              Keine Accounts {onlyAdmins ? 'mit Admin-Rechten ' : ''}im Dump gefunden.
            </div>
          )}
        </Card>
      </Section>

      <Section title="Tabellen im Dump"
        sub="Auch leere Tabellen werden gelistet — »existiert und ist leer« ist eine andere Aussage als »nicht im Dump«, und nur eine davon kann Truncation durch den Angreifer bedeuten."
        right={<SearchInput value={tableSearch} onChange={setTableSearch} placeholder="Tabelle suchen…" />}
      >
        <Card className="max-h-[420px] overflow-y-auto">
          <table className="w-full border-collapse text-[13px]">
            <thead className="sticky top-0 bg-[var(--panel)]">
              <tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
                <th className="px-4 py-2">Tabelle</th>
                <th className="px-2 py-2 text-right">Spalten</th>
                <th className="px-2 py-2 text-right">Zeilen</th>
                <th className="px-2 py-2 text-right">Dump-Bytes</th>
              </tr>
            </thead>
            <tbody>
              {tables.map((t) => (
                <tr key={t.id} className="border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]">
                  <td className="mono px-4 py-1.5 text-[12px]">{t.name}</td>
                  <td className="px-2 py-1.5 text-right tabular text-[12px]">{t.columns}</td>
                  <td className={clsx('px-2 py-1.5 text-right tabular text-[12px]',
                    !t.rows && 'text-[var(--muted)]')}>
                    {formatCount(t.rows)}
                  </td>
                  <td className="px-2 py-1.5 text-right tabular text-[12px] text-[var(--muted)]">
                    {formatBytes(t.bytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      </Section>

      {data?.dumps.map((d) => (
        <Card key={d.id} className="px-4 py-3 text-[12px] text-[var(--muted)]">
          <span className="mono">{d.path}</span>
          {' — '}
          {[d.meta.tool && `Tool: ${d.meta.tool}`,
            d.meta.server && `Server: ${d.meta.server}`,
            d.meta.database && `DB: ${d.meta.database}`,
            d.meta.created && `Erstellt: ${d.meta.created}`,
            `${formatCount(d.statements)} Statements`,
          ].filter(Boolean).join(' · ')}
        </Card>
      ))}
    </div>
  )
}
