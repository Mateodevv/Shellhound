// Database.tsx -- a focused forensic workspace over exported CMS state.
// The analyst-facing questions are deliberately narrow: who can access the
// CMS, which extensions are active, and what was published. The SQL parser
// still preserves all raw evidence; this workspace does not duplicate it.
import { useMemo, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box, ChevronDown, ChevronRight, Crown, Database as DatabaseIcon, Download, Table2,
} from 'lucide-react'
import clsx from 'clsx'
import { useT } from '../i18n'
import {
  api, downloadUrl, post, type CaseDetail, type DatabaseIntelligence,
  type DbAccount, type DbDump, type DbIntelligenceItem,
} from '../api'
import { formatCount, type EvidenceRoot } from '../format'
import {
  Button, Card, Chip, EmptyState, SearchInput, Section, Tabs, Tag,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { TraceWindow } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import type { ViewId } from '../App'

type Lens = 'accounts' | 'extensions' | 'content'

interface DatabaseData {
  dumps: DbDump[]
  schema_files: DbDump[]
  accounts: DbAccount[]
  intelligence: DatabaseIntelligence
}

export function DatabaseView({ slug, gotoView }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [lens, setLens] = useState<Lens>('accounts')
  const [selected, setSelected] = useState<ArtifactStub | null>(null)
  const [viewing, setViewing] = useState<{ path: string; line: number | null } | null>(null)
  const [traceIps, setTraceIps] = useState<string[] | null>(null)
  const triage = useTriage(slug)
  const { data } = useQuery({
    queryKey: ['database', slug],
    queryFn: () => api<DatabaseData>(`/api/cases/${slug}/database`),
  })
  const { data: caseInfo } = useQuery({
    queryKey: ['case', slug],
    queryFn: () => api<CaseDetail>(`/api/cases/${slug}`),
  })
  const roots: EvidenceRoot[] = (caseInfo?.evidence_items ?? []).map((e) => ({
    kind: e.kind, path: e.path, label: e.label,
  }))
  const flagAccount = useMutation({
    mutationFn: (account_id: number) => post<{ added: { value: string }[] }>(
      `/api/cases/${slug}/database/accounts/flag`, { account_id }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['database'] })
      qc.invalidateQueries({ queryKey: ['iocs'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
    },
  })
  const openArtifact = (stub: ArtifactStub) => {
    triage.clearCollected()
    setSelected(stub)
  }

  if (data && !data.dumps.length) {
    return <div className="flex flex-col gap-4">
      <EmptyState icon={<DatabaseIcon size={36} />}
        title={data.schema_files.length ? tr('database.empty.schemaOnly') : tr('database.empty.title')}
        sub={data.schema_files.length
          ? tr('database.onlySchema', { n: formatCount(data.schema_files.length) })
          : tr('database.empty.sub')} />
    </div>
  }

  const intel = data?.intelligence
  const tabs: { id: Lens; label: string; badge?: ReactNode }[] = [
    { id: 'accounts', label: tr('database.lens.access'), badge: data?.accounts.length
      ? <CountBadge n={data.accounts.length} /> : undefined },
    { id: 'extensions', label: tr('database.lens.extensions'), badge: intel?.extensions.length
      ? <CountBadge n={intel.extensions.length} /> : undefined },
    { id: 'content', label: tr('database.lens.content'), badge: intel?.content.length
      ? <CountBadge n={intel.content.length} /> : undefined },
  ]

  return <div className="flex flex-col gap-5">
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div>
        <Tooltip title={tr('nav.database')} body={tr('database.title.body')} hint={tr('database.title.hint')}>
          <h1 className="text-lg font-bold">{tr('nav.database')}</h1>
        </Tooltip>
        <div className="mt-1 flex flex-wrap items-center gap-1.5">
          {(intel?.cms ?? []).map((cms) => <Tag key={cms} tone="accent">{cms}</Tag>)}
          <span className="text-xs text-[var(--muted)]">{tr('database.workspace.sub')}</span>
        </div>
      </div>
      <Button variant="ghost" onClick={() => gotoView('cms')}>
        <Table2 size={14} /> {tr('database.openInventory')}
      </Button>
    </div>
    <Tabs tabs={tabs} active={lens} onChange={setLens} />

    {lens === 'accounts' && data && intel && <AccessLens slug={slug} accounts={data.accounts}
      access={intel.access} flagAccount={(id) => flagAccount.mutate(id)} flagging={flagAccount.isPending} />}
    {lens === 'extensions' && intel && <ExtensionLens rows={intel.extensions}
      onOpenArtifact={openArtifact} onOpenInventory={() => gotoView('cms')} />}
    {lens === 'content' && intel && <ContentLens rows={intel.content} />}

    <ArtifactWindow slug={slug} artifact={selected} roots={roots} collected={triage.collected}
      onView={(path, line) => setViewing({ path, line })} onTrace={(ips) => setTraceIps(ips)}
      onClose={() => { setSelected(null); triage.clearCollected() }}
      onTriage={(state, note) => { if (selected) triage.decide([selected.artifact], state, note) }} />
    <TraceWindow slug={slug} ips={traceIps} layer={1} onClose={() => setTraceIps(null)} />
    <FileViewer slug={slug} path={viewing?.path ?? null} focusLine={viewing?.line}
      layer={2} onClose={() => setViewing(null)} />
    <TriageFollowUp t={triage} roots={roots} />
  </div>
}

function CountBadge({ n, tone }: { n: number; tone?: 'danger' }) {
  return <span className={clsx('ml-1.5 rounded-full px-1.5 py-0.5 text-[10px] tabular',
    tone === 'danger' ? 'bg-[var(--danger-soft)] text-[var(--danger-text)]'
      : 'bg-[var(--panel-2)] text-[var(--muted)]')}>{formatCount(n)}</span>
}

function itemTitle(row: DbIntelligenceItem) {
  return row.name || row.title || row.account_login || row.label || row.key
}

function SignalTags({ signals }: { signals: string[] }) {
  const tr = useT()
  return <>{signals.map((signal) => <Tag key={signal}
    tone={signal === 'active_missing_files' || signal === 'flagged_files' ? 'danger' : 'warn'}>
    {tr(`database.intel.signal.${signal}`)}
  </Tag>)}</>
}

function Source({ item }: { item: DbIntelligenceItem }) {
  const tr = useT()
  if (!item.source_table) return <span className="text-[11px] text-[var(--muted)]">{tr('database.filesystem')}</span>
  return <Tooltip hint={item.dump_name || undefined}><span
    className="mono max-w-52 truncate text-[10.5px] text-[var(--muted)]">
    {item.source_table}{item.source_row ? ` · #${item.source_row}` : ''}
  </span></Tooltip>
}

function AccessLens({ slug, accounts, access, flagAccount, flagging }: {
  slug: string; accounts: DbAccount[]; access: DbIntelligenceItem[]
  flagAccount: (id: number) => void; flagging: boolean
}) {
  const tr = useT()
  const [search, setSearch] = useState('')
  const [hiddenSignals, setHiddenSignals] = useState<Set<string>>(new Set())
  const signalCounts = useMemo(() => {
    const result = new Map<string, { label: string; why: string; n: number }>()
    for (const account of accounts) for (const signal of account.signals) {
      const label = signal.id === 'young' ? tr('database.signal.young') : signal.label
      const value = result.get(signal.id) ?? { label, why: signal.why, n: 0 }
      value.n += 1
      result.set(signal.id, value)
    }
    return [...result.entries()]
  }, [accounts, tr])
  const visible = accounts.filter((account) => {
    if (account.signals.some((signal) => hiddenSignals.has(signal.id))) return false
    const q = search.toLowerCase()
    return !q || account.login.toLowerCase().includes(q) || account.email.toLowerCase().includes(q)
  })
  const permissions = useMemo(() => {
    const result = new Map<number, { roles: string[]; methods: string[] }>()
    for (const account of accounts) {
      const rows = access.filter((row) => {
        if (row.dump_id != null && row.dump_id !== account.dump_id) return false
        return (row.user_id && row.user_id === account.user_id)
          || (row.account_login && row.account_login.toLowerCase() === account.login.toLowerCase())
      })
      const roles = rows.flatMap((row) => row.roles ?? [])
      for (const row of rows) {
        if (row.kind === 'group' && row.label) roles.push(row.label)
      }
      if (account.admin && !roles.length) roles.push(tr('database.permission.admin'))
      result.set(account.id, {
        roles: [...new Set(roles.filter(Boolean))],
        methods: [...new Set(rows.map((row) => row.kind ?? '').filter((kind) =>
          kind === 'session' || kind === 'application_password'))],
      })
    }
    return result
  }, [accounts, access, tr])
  return <Section title={tr('database.accounts')} sub={tr('database.accounts.sub')} right={<div className="flex flex-wrap items-center gap-2">
      <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] font-medium hover:border-[var(--accent)]/60"
        href={downloadUrl(`/api/cases/${slug}/database/accounts.csv`)}><Download size={13} /> CSV</a>
      <SearchInput value={search} onChange={setSearch} placeholder={tr('database.search')} />
    </div>}>
      <div className="mb-3 flex flex-wrap items-center gap-2 rounded-xl border border-[var(--line)] bg-[var(--panel-2)] p-2.5">
        <span className="mr-1 text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">
          {tr('database.filters.included')}
        </span>
        {signalCounts.map(([id, signal]) => <Tooltip key={id} title={signal.label} body={signal.why}>
        <Chip active={!hiddenSignals.has(id)} dimmed={hiddenSignals.has(id)} count={signal.n}
          onClick={() => setHiddenSignals((previous) => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next })}>
          {signal.label}</Chip></Tooltip>)}
        <span className="text-xs text-[var(--muted)]">{tr('database.accountCount', { shown: formatCount(visible.length), total: formatCount(accounts.length) })}</span>
      </div>
      <Card className="overflow-x-auto"><table className="w-full min-w-[980px] border-collapse text-[13px]">
        <thead><tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
          <th className="px-4 py-2">{tr('csv.login')}</th><th className="px-2 py-2">{tr('csv.email')}</th>
          <th className="px-2 py-2">{tr('database.permissions')}</th><th className="px-2 py-2">{tr('database.signalsColumn')}</th>
          <th className="px-2 py-2">{tr('csv.registered')}</th><th className="px-2 py-2">{tr('csv.lastLogin')}</th>
          <th className="px-2 py-2">{tr('table.origin')}</th><th className="w-20 px-3 py-2" />
        </tr></thead><tbody>{visible.map((account) => {
          const permission = permissions.get(account.id)
          return <tr key={account.id}
            className={clsx('group border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]', account.admin && 'bg-[rgba(208,59,59,0.05)]')}>
          <td className="mono px-4 py-2 font-medium"><span className="flex items-center gap-1.5">{!!account.admin && <Crown size={13} className="text-[var(--sev-high)]" />}{account.login}</span></td>
          <td className="px-2 py-2 text-[12px]">{account.email}</td>
          <td className="px-2 py-2"><div className="flex max-w-80 flex-wrap gap-1">
            {permission?.roles.map((role) => <Tag key={role} tone={account.admin ? 'danger' : 'accent'}>{role}</Tag>)}
            {permission?.methods.map((method) => <Tag key={method}>{tr(`database.access.kind.${method}`)}</Tag>)}
            {!permission?.roles.length && !permission?.methods.length && (
              <span className="text-[11.5px] text-[var(--muted)]">{tr('database.permissions.unknown')}</span>
            )}
          </div></td>
          <td className="px-2 py-2"><div className="flex flex-wrap gap-1">{account.signals.map((signal) => <Tag key={signal.id}
            tone={signal.id === 'admin' ? 'danger' : signal.id === 'young' ? 'warn' : undefined} hint={signal.why}>{signal.label}</Tag>)}</div></td>
          <td className="px-2 py-2 text-[12px] text-[var(--muted)]">{account.registered}</td>
          <td className="px-2 py-2 text-[12px] text-[var(--muted)]">{account.last_login || '—'}</td>
          <td className="mono px-2 py-2 text-[11px] text-[var(--muted)]">{account.cms} · {account.tbl}</td>
          <td className="px-3 py-2 text-right">{account.in_box ? <Tag tone="accent">IOC</Tag>
            : <Button variant="ghost" disabled={flagging} className="whitespace-nowrap"
              onClick={() => flagAccount(account.id)}>
              <Box size={13} /> {tr('database.flagAccount')}
            </Button>}</td>
        </tr>
        })}</tbody>
      </table>{!visible.length && <EmptyRow text={accounts.length ? tr('database.allHidden') : tr('database.noAccounts')} />}</Card>
    </Section>
}

function ExtensionLens({ rows, onOpenArtifact, onOpenInventory }: {
  rows: DbIntelligenceItem[]; onOpenArtifact: (artifact: ArtifactStub) => void; onOpenInventory: () => void
}) {
  const tr = useT()
  const [cms, setCms] = useState('all')
  const [search, setSearch] = useState('')
  const [reviewOnly, setReviewOnly] = useState(false)
  const visible = rows.filter((row) => (cms === 'all' || row.cms === cms) && (!reviewOnly || row.review)
    && (!search || itemTitle(row).toLowerCase().includes(search.toLowerCase())))
  const cmsNames = [...new Set(rows.map((row) => row.cms))]
  return <Section title={tr('database.extensions')} sub={tr('database.extensions.sub')} right={<div className="flex flex-wrap items-center gap-2">
    <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">
      {tr('database.filters.included')}
    </span>
    <Chip active={cms === 'all'} onClick={() => setCms('all')}>{tr('database.allCms')}</Chip>
    {cmsNames.map((name) => <Chip key={name} active={cms === name} onClick={() => setCms(cms === name ? 'all' : name)}>{name}</Chip>)}
    <Chip active={reviewOnly} count={rows.filter((row) => row.review).length} onClick={() => setReviewOnly(!reviewOnly)}>{tr('database.needsReview')}</Chip>
    <SearchInput value={search} onChange={setSearch} placeholder={tr('database.extensionSearch')} />
    <Button variant="ghost" onClick={onOpenInventory}><Table2 size={13} /> {tr('database.openInventory')}</Button>
  </div>}>
    <Card className="overflow-x-auto"><table className="w-full min-w-[920px] border-collapse text-[13px]">
      <thead><tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
        <th className="px-4 py-2">{tr('database.extension')}</th><th className="px-2 py-2">{tr('database.state')}</th>
        <th className="px-2 py-2">{tr('database.dbVersion')}</th><th className="px-2 py-2">{tr('database.filesystemVersion')}</th>
        <th className="px-2 py-2">{tr('database.correlation')}</th><th className="px-2 py-2">{tr('database.observations')}</th>
        <th className="px-3 py-2">{tr('table.origin')}</th>
      </tr></thead><tbody>{visible.map((row, index) => <tr key={`${row.key}:${index}`}
        className={clsx('border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]', row.review && 'bg-[rgba(208,59,59,0.035)]')}>
        <td className="px-4 py-2"><div className="font-medium">{itemTitle(row)}</div><div className="text-[11px] text-[var(--muted)]">{row.cms} · {row.type}{row.scope ? ` · ${row.scope}` : ''}</div></td>
        <td className="px-2 py-2"><State value={row.enabled} alwaysOn={row.type === 'Must-use plugin' || row.type === 'Drop-in'} /></td>
        <td className="mono px-2 py-2 text-[12px]">{row.version || '—'}</td><td className="mono px-2 py-2 text-[12px]">{row.filesystem?.version || '—'}</td>
        <td className="px-2 py-2"><Tag tone={row.filesystem?.status === 'missing' ? 'danger' : row.filesystem?.status === 'present' ? 'accent' : undefined}>
          {tr(`database.fs.${row.filesystem?.status || 'unknown'}`)}</Tag>
          {row.filesystem?.path && <div className="mono mt-1 max-w-72 truncate text-[10px] text-[var(--muted)]" title={row.filesystem.path}>{row.filesystem.path}</div>}</td>
        <td className="px-2 py-2"><div className="flex flex-wrap gap-1"><SignalTags signals={row.signals} />
          {row.filesystem?.findings.map((finding) => <button key={finding.artifact} onClick={() => onOpenArtifact({
            artifact: finding.artifact, artifact_kind: 'file', worst: finding.worst, triage: finding.triage, triage_note: '',
          })}><Tag tone="danger">{finding.findings} Finding{finding.findings === 1 ? '' : 's'}</Tag></button>)}</div></td>
        <td className="px-3 py-2"><Source item={row} /></td>
      </tr>)}</tbody>
    </table>{!visible.length && <EmptyRow text={tr('database.noExtensionMatch')} />}</Card>
  </Section>
}

function State({ value, alwaysOn }: { value?: boolean | null; alwaysOn?: boolean }) {
  const tr = useT()
  if (alwaysOn) return <Tag tone="accent">{tr('database.state.alwaysOn')}</Tag>
  if (value === true) return <Tag tone="accent">{tr('database.state.active')}</Tag>
  if (value === false) return <Tag>{tr('database.state.inactive')}</Tag>
  return <Tag>{tr('database.state.unknown')}</Tag>
}

function ContentLens({ rows }: { rows: DbIntelligenceItem[] }) {
  const tr = useT()
  const [signalsOnly, setSignalsOnly] = useState(false)
  const [search, setSearch] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  const visible = rows.filter((row) => (!signalsOnly || row.signals.length)
    && (!search || itemTitle(row).toLowerCase().includes(search.toLowerCase())))
  return <Section title={tr('database.content')} sub={tr('database.content.sub')} right={<div className="flex items-center gap-2">
    <span className="text-[10px] font-bold uppercase tracking-wider text-[var(--muted)]">
      {tr('database.filters.included')}
    </span>
    <Chip active={signalsOnly} count={rows.filter((row) => row.signals.length).length} onClick={() => setSignalsOnly(!signalsOnly)}>{tr('database.withSignals')}</Chip>
    <SearchInput value={search} onChange={setSearch} placeholder={tr('database.contentSearch')} /></div>}>
    <Card className="overflow-hidden">{visible.map((row, index) => {
      const id = `${row.dump_id}:${row.key}:${index}`
      const expanded = open === id
      return <div key={id} className={clsx('border-b border-[var(--line-soft)] last:border-0', row.review && 'bg-[rgba(208,59,59,0.035)]')}>
        <button onClick={() => setOpen(expanded ? null : id)}
          className="grid w-full cursor-pointer gap-2 px-4 py-3 text-left hover:bg-[var(--panel-2)] lg:grid-cols-[20px_minmax(220px,1.4fr)_minmax(160px,1fr)_minmax(240px,1.4fr)_auto] lg:items-center">
          {expanded ? <ChevronDown size={14} className="text-[var(--muted)]" /> : <ChevronRight size={14} className="text-[var(--muted)]" />}
          <div><div className="font-medium">{row.title || row.key}</div><div className="text-[11px] text-[var(--muted)]">{row.cms} · {row.type} · ID {row.key.split(':').pop()}</div></div>
          <div className="text-[11.5px] text-[var(--muted)]">{row.modified || row.created || '—'}{row.path && <div className="mono truncate" title={row.path}>{row.path}</div>}</div>
          <div><div className="flex flex-wrap gap-1"><SignalTags signals={row.signals} /></div>{!!row.domains?.length && <div className="mt-1 flex flex-wrap gap-1">
            {row.domains.map((domain) => <Tag key={domain}>{domain}</Tag>)}</div>}</div><Source item={row} />
        </button>
        {expanded && <div className="border-t border-[var(--line-soft)] bg-[var(--code-bg)] px-4 py-3">
          {row.content ? <pre className="mono max-h-[520px] overflow-auto whitespace-pre-wrap break-words text-[11.5px] leading-relaxed text-[#e6edf3]">{row.content}</pre>
            : <p className="text-[12px] text-[var(--muted)]">{tr('database.post.noContent')}</p>}
          {row.content_truncated && <p className="mt-2 text-[11px] text-[var(--sev-low)]">{tr('database.post.truncated')}</p>}
        </div>}
      </div>
    })}{!visible.length && <EmptyRow text={tr('database.content.empty')} />}</Card>
  </Section>
}

function EmptyRow({ text }: { text: string }) {
  return <div className="px-4 py-7 text-center text-[13px] text-[var(--muted)]">{text}</div>
}
