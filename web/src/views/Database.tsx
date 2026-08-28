// Database.tsx -- a forensic workspace over exported CMS state.
// WordPress and Joomla semantics are lenses over the immutable export. Raw
// tables remain available without burying the investigation workflow.
import { useMemo, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Box, Clock, Crown, Database as DatabaseIcon, Download, FileCode2, HelpCircle,
  Table2,
} from 'lucide-react'
import clsx from 'clsx'
import { plural, useT } from '../i18n'
import {
  api, downloadUrl, post, type CaseDetail, type DatabaseIntelligence,
  type DbAccount, type DbDump, type DbIntelligenceItem, type DbTable, type Finding,
} from '../api'
import { SEVERITY_VAR, baseName, formatBytes, formatCount, type EvidenceRoot } from '../format'
import {
  Button, Card, Chip, EmptyState, SearchInput, Section, SeverityBadge, StatTile,
  Tabs, Tag, TriageBadge,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { ArtifactWindow, type ArtifactStub } from '../components/ArtifactWindow'
import { TriageFollowUp } from '../components/triage'
import { useTriage } from '../components/useTriage'
import { TraceWindow } from '../components/TraceWindow'
import { FileViewer } from '../components/FileViewer'
import type { ViewId } from '../App'

type Lens = 'overview' | 'accounts' | 'extensions' | 'persistence' | 'content' | 'raw'

interface DatabaseData {
  dumps: DbDump[]
  schema_files: DbDump[]
  tables: DbTable[]
  schema_tables: number
  accounts: DbAccount[]
  findings: Finding[]
  reference: string
  intelligence: DatabaseIntelligence
}

export function DatabaseView({ slug, gotoView }: { slug: string; gotoView: (v: ViewId) => void }) {
  const tr = useT()
  const qc = useQueryClient()
  const [lens, setLens] = useState<Lens>('overview')
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
      {data.schema_files.length > 0 && <SchemaCard files={data.schema_files} />}
    </div>
  }

  const intel = data?.intelligence
  const summary = intel?.summary
  const tabs: { id: Lens; label: string; badge?: ReactNode }[] = [
    { id: 'overview', label: tr('database.lens.overview'), badge: summary?.needs_review
      ? <CountBadge n={summary.needs_review} tone="danger" /> : undefined },
    { id: 'accounts', label: tr('database.lens.access'), badge: data?.accounts.length
      ? <CountBadge n={data.accounts.length} /> : undefined },
    { id: 'extensions', label: tr('database.lens.extensions'), badge: intel?.extensions.length
      ? <CountBadge n={intel.extensions.length} /> : undefined },
    { id: 'persistence', label: tr('database.lens.persistence'), badge: intel?.persistence.length
      ? <CountBadge n={intel.persistence.length} /> : undefined },
    { id: 'content', label: tr('database.lens.content'), badge: summary?.content_signals
      ? <CountBadge n={summary.content_signals} tone="danger" /> : undefined },
    { id: 'raw', label: tr('database.lens.raw') },
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

    {lens === 'overview' && data && intel && <Overview data={data} intel={intel} onOpenLens={setLens} />}
    {lens === 'accounts' && data && intel && <AccessLens slug={slug} accounts={data.accounts}
      access={intel.access} flagAccount={(id) => flagAccount.mutate(id)} flagging={flagAccount.isPending} />}
    {lens === 'extensions' && intel && <ExtensionLens rows={intel.extensions}
      onOpenArtifact={openArtifact} onOpenInventory={() => gotoView('cms')} />}
    {lens === 'persistence' && intel && <PersistenceLens configuration={intel.configuration} rows={intel.persistence} />}
    {lens === 'content' && intel && <ContentLens rows={intel.content} />}
    {lens === 'raw' && data && <RawLens data={data} onOpenArtifact={openArtifact} />}

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

function Overview({ data, intel, onOpenLens }: {
  data: DatabaseData; intel: DatabaseIntelligence; onOpenLens: (lens: Lens) => void
}) {
  const tr = useT()
  const s = intel.summary
  return <div className="flex flex-col gap-6">
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
      <StatTile label={tr('database.reviewQueue')} value={formatCount(s.needs_review)}
        tone={s.needs_review ? 'var(--sev-high)' : undefined} sub={tr('database.reviewQueue.sub')} />
      <StatTile label={tr('database.activeExtensions')} value={formatCount(s.active_extensions)}
        sub={tr('database.activeExtensions.sub')} onClick={() => onOpenLens('extensions')} />
      <StatTile label={tr('database.accounts')} value={formatCount(data.accounts.length)}
        sub={tr('database.accounts.stat')} onClick={() => onOpenLens('accounts')} />
      <StatTile label={tr('database.scheduled')} value={formatCount(s.persistence_records)}
        sub={tr('database.scheduled.sub')} onClick={() => onOpenLens('persistence')} />
      <StatTile label={tr('database.contentSignals')} value={formatCount(s.content_signals)}
        tone={s.content_signals ? 'var(--sev-med)' : undefined}
        sub={tr('database.contentSignals.sub')} onClick={() => onOpenLens('content')} />
    </div>
    <Section title={tr('database.reviewQueue')} sub={tr('database.reviewQueue.body')}>
      <Card className="overflow-hidden">
        {intel.review_queue.slice(0, 14).map((row, index) => <button
          key={`${row.category}:${row.key}:${index}`} onClick={() => onOpenLens(lensFor(row.category))}
          className="flex w-full items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2.5 text-left last:border-0 hover:bg-[var(--panel-2)]">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--danger-soft)] text-[var(--danger-text)]">
            <span className="text-sm font-bold">!</span>
          </span>
          <div className="min-w-0 flex-1"><div className="truncate text-[13px] font-medium">{itemTitle(row)}</div>
            <div className="mt-0.5 flex flex-wrap gap-1"><SignalTags signals={row.signals} /></div></div>
          <Source item={row} />
        </button>)}
        {!intel.review_queue.length && <EmptyRow text={tr('database.reviewQueue.empty')} />}
        {intel.review_queue.length > 14 && <div className="border-t border-[var(--line)] px-4 py-2 text-xs text-[var(--muted)]">
          {tr('database.reviewQueue.more', { n: formatCount(intel.review_queue.length - 14) })}
        </div>}
      </Card>
    </Section>
    <Section title={tr('database.sources')} sub={tr('database.sources.sub')}>
      <div className="grid gap-3 xl:grid-cols-2">{data.dumps.map((dump) => <DumpCard key={dump.id} dump={dump} />)}</div>
      {!!data.schema_files.length && <div className="mt-3"><SchemaCard files={data.schema_files} /></div>}
    </Section>
  </div>
}

function lensFor(category?: DbIntelligenceItem['category']): Lens {
  if (category === 'access') return 'accounts'
  if (category === 'extensions') return 'extensions'
  if (category === 'persistence' || category === 'configuration') return 'persistence'
  if (category === 'content') return 'content'
  return 'overview'
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
  return <div className="flex flex-col gap-6">
    <Section title={tr('database.liveAccess')} sub={tr('database.liveAccess.sub')}>
      <Card className="overflow-hidden">{access.map((row, index) => <div key={`${row.key}:${index}`}
        className="grid gap-2 border-b border-[var(--line-soft)] px-4 py-2.5 last:border-0 lg:grid-cols-[minmax(170px,1fr)_minmax(220px,2fr)_minmax(160px,1fr)_auto] lg:items-center">
        <div><div className="text-[13px] font-medium">{row.account_login || row.label}</div>
          <div className="text-[11px] text-[var(--muted)]">{row.cms} · {tr(`database.access.kind.${row.kind}`)}</div></div>
        <div className="flex flex-wrap gap-1"><SignalTags signals={row.signals} /></div>
        <div className="text-[11.5px] text-[var(--muted)]">{row.last_ip && <span className="mono">{row.last_ip}</span>}
          {(row.last_used || row.created || row.expires) && <div>{row.last_used || row.created || row.expires}</div>}</div>
        <Source item={row} />
      </div>)}{!access.length && <EmptyRow text={tr('database.liveAccess.empty')} />}</Card>
    </Section>
    <Section title={tr('database.accounts')} sub={tr('database.accounts.sub')} right={<div className="flex flex-wrap items-center gap-2">
      <a className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] font-medium hover:border-[var(--accent)]/60"
        href={downloadUrl(`/api/cases/${slug}/database/accounts.csv`)}><Download size={13} /> CSV</a>
      <SearchInput value={search} onChange={setSearch} placeholder={tr('database.search')} />
    </div>}>
      <div className="mb-3 flex flex-wrap items-center gap-2">{signalCounts.map(([id, signal]) => <Tooltip key={id} title={signal.label} body={signal.why}>
        <Chip active={!hiddenSignals.has(id)} dimmed={hiddenSignals.has(id)} count={signal.n}
          onClick={() => setHiddenSignals((previous) => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next })}>
          {signal.label}</Chip></Tooltip>)}
        <span className="text-xs text-[var(--muted)]">{tr('database.accountCount', { shown: formatCount(visible.length), total: formatCount(accounts.length) })}</span>
      </div>
      <Card className="overflow-x-auto"><table className="w-full min-w-[980px] border-collapse text-[13px]">
        <thead><tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
          <th className="px-4 py-2">{tr('csv.login')}</th><th className="px-2 py-2">{tr('csv.email')}</th>
          <th className="px-2 py-2">{tr('database.signalsColumn')}</th><th className="px-2 py-2">{tr('csv.registered')}</th>
          <th className="px-2 py-2">{tr('csv.lastLogin')}</th><th className="px-2 py-2">Hash</th>
          <th className="px-2 py-2">{tr('table.origin')}</th><th className="w-20 px-3 py-2" />
        </tr></thead><tbody>{visible.map((account) => <tr key={account.id}
          className={clsx('group border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]', account.admin && 'bg-[rgba(208,59,59,0.05)]')}>
          <td className="mono px-4 py-2 font-medium"><span className="flex items-center gap-1.5">{!!account.admin && <Crown size={13} className="text-[var(--sev-high)]" />}{account.login}</span></td>
          <td className="px-2 py-2 text-[12px]">{account.email}</td>
          <td className="px-2 py-2"><div className="flex flex-wrap gap-1">{account.signals.map((signal) => <Tag key={signal.id}
            tone={signal.id === 'admin' ? 'danger' : signal.id === 'young' ? 'warn' : undefined} hint={signal.why}>{signal.label}</Tag>)}</div></td>
          <td className="px-2 py-2 text-[12px] text-[var(--muted)]">{account.registered}</td>
          <td className="px-2 py-2 text-[12px] text-[var(--muted)]">{account.last_login || '—'}</td>
          <td className="px-2 py-2 text-[12px] text-[var(--muted)]">{account.hash_type}</td>
          <td className="mono px-2 py-2 text-[11px] text-[var(--muted)]">{account.cms} · {account.tbl}</td>
          <td className="px-3 py-2 text-right">{account.in_box ? <Tag tone="accent">IOC</Tag>
            : <Button variant="ghost" disabled={flagging} className="opacity-0 group-hover:opacity-100" onClick={() => flagAccount(account.id)}><Box size={13} /> IOC</Button>}</td>
        </tr>)}</tbody>
      </table>{!visible.length && <EmptyRow text={accounts.length ? tr('database.allHidden') : tr('database.noAccounts')} />}</Card>
    </Section>
  </div>
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

function PersistenceLens({ configuration, rows }: { configuration: DbIntelligenceItem[]; rows: DbIntelligenceItem[] }) {
  const tr = useT()
  return <div className="grid gap-6 2xl:grid-cols-[minmax(300px,0.8fr)_minmax(600px,2fr)]">
    <Section title={tr('database.configuration')} sub={tr('database.configuration.sub')}>
      <Card className="overflow-hidden">{configuration.map((row, index) => <div key={`${row.key}:${index}`}
        className="border-b border-[var(--line-soft)] px-4 py-2.5 last:border-0"><div className="flex items-center justify-between gap-3">
          <span className="mono text-[12px]">{row.key}</span><Source item={row} /></div>
        <div className="mt-1 break-all text-[12px] text-[var(--muted)]">{row.value || '—'}</div>
        {!!row.signals.length && <div className="mt-1 flex flex-wrap gap-1"><SignalTags signals={row.signals} /></div>}
      </div>)}{!configuration.length && <EmptyRow text={tr('database.configuration.empty')} />}</Card>
    </Section>
    <Section title={tr('database.scheduledJobs')} sub={tr('database.scheduledJobs.sub')}>
      <Card className="overflow-hidden">{rows.map((row, index) => <div key={`${row.key}:${index}`}
        className="grid gap-2 border-b border-[var(--line-soft)] px-4 py-3 last:border-0 lg:grid-cols-[minmax(190px,1.2fr)_minmax(150px,1fr)_minmax(170px,1fr)_auto] lg:items-center">
        <div><div className="font-medium">{row.label || row.task_type || row.key}</div><div className="text-[11px] text-[var(--muted)]">{row.cms} · {row.kind}</div></div>
        <div className="text-[12px]"><span className="mono">{row.schedule || '—'}</span>{row.state && <div className="text-[11px] text-[var(--muted)]">{row.state}</div>}</div>
        <div className="text-[11.5px] text-[var(--muted)]">{row.next_run && <div>{tr('database.nextRun')}: {row.next_run}</div>}
          {row.last_run && <div>{tr('database.lastRun')}: {row.last_run}</div>}{row.domains?.map((domain) => <Tag key={domain} tone="warn">{domain}</Tag>)}</div>
        <div className="flex flex-col items-end gap-1"><SignalTags signals={row.signals} /><Source item={row} /></div>
      </div>)}{!rows.length && <EmptyRow text={tr('database.scheduledJobs.empty')} />}</Card>
    </Section>
  </div>
}

function ContentLens({ rows }: { rows: DbIntelligenceItem[] }) {
  const tr = useT()
  const [signalsOnly, setSignalsOnly] = useState(true)
  const [search, setSearch] = useState('')
  const visible = rows.filter((row) => (!signalsOnly || row.signals.length)
    && (!search || itemTitle(row).toLowerCase().includes(search.toLowerCase())))
  return <Section title={tr('database.content')} sub={tr('database.content.sub')} right={<div className="flex items-center gap-2">
    <Chip active={signalsOnly} count={rows.filter((row) => row.signals.length).length} onClick={() => setSignalsOnly(!signalsOnly)}>{tr('database.withSignals')}</Chip>
    <SearchInput value={search} onChange={setSearch} placeholder={tr('database.contentSearch')} /></div>}>
    <Card className="overflow-hidden">{visible.map((row, index) => <div key={`${row.key}:${index}`}
      className={clsx('grid gap-2 border-b border-[var(--line-soft)] px-4 py-3 last:border-0 lg:grid-cols-[minmax(220px,1.4fr)_minmax(160px,1fr)_minmax(240px,1.4fr)_auto]', row.review && 'bg-[rgba(208,59,59,0.035)]')}>
      <div><div className="font-medium">{row.title || row.key}</div><div className="text-[11px] text-[var(--muted)]">{row.cms} · {row.type} · ID {row.key.split(':').pop()}</div></div>
      <div className="text-[11.5px] text-[var(--muted)]">{row.modified || row.created || '—'}{row.path && <div className="mono truncate" title={row.path}>{row.path}</div>}</div>
      <div><div className="flex flex-wrap gap-1"><SignalTags signals={row.signals} /></div>{!!row.domains?.length && <div className="mt-1 flex flex-wrap gap-1">
        {row.domains.map((domain) => <Tag key={domain}>{domain}</Tag>)}</div>}</div><Source item={row} />
    </div>)}{!visible.length && <EmptyRow text={tr('database.content.empty')} />}</Card>
  </Section>
}

function RawLens({ data, onOpenArtifact }: { data: DatabaseData; onOpenArtifact: (artifact: ArtifactStub) => void }) {
  const tr = useT()
  const [search, setSearch] = useState('')
  const [flaggedOnly, setFlaggedOnly] = useState(false)
  const tables = data.tables.filter((table) => (!flaggedOnly || table.flagged > 0)
    && (!search || table.name.toLowerCase().includes(search.toLowerCase())))
  return <div className="flex flex-col gap-6">
    {data.findings.length > 0 && <Section title={tr('database.injected')} sub={tr('database.injected.sub')}>
      <Card className="overflow-hidden">{data.findings.map((finding) => <button key={finding.fingerprint}
        onClick={() => onOpenArtifact({ artifact: finding.artifact, artifact_kind: 'table', worst: finding.severity, triage: finding.triage, triage_note: finding.triage_note })}
        className="flex w-full items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2 text-left last:border-0 hover:bg-[var(--panel-2)]">
        <span className="h-6 w-1 rounded-full" style={{ background: SEVERITY_VAR[finding.severity] }} /><SeverityBadge severity={finding.severity} />
        <span className="mono w-40 truncate text-[12px]">{finding.artifact}</span><span className="min-w-0 flex-1 truncate text-[12px]">{finding.rule}</span>
        <TriageBadge state={finding.triage} label={tr(`triage.${finding.triage}`)} />
      </button>)}</Card>
    </Section>}
    {!!data.schema_files.length && <SchemaCard files={data.schema_files} />}
    <Section title={tr('database.tables')} sub={tr('database.tables.sub')} right={<div className="flex items-center gap-2">
      <Chip active={flaggedOnly} count={data.tables.filter((table) => table.flagged).length} onClick={() => setFlaggedOnly(!flaggedOnly)}>{tr('database.withFindings')}</Chip>
      <SearchInput value={search} onChange={setSearch} placeholder={tr('database.tableSearch')} /></div>}>
      <Card className="max-h-[640px] overflow-auto"><table className="w-full border-collapse text-[13px]">
        <thead className="sticky top-0 bg-[var(--panel)]"><tr className="border-b border-[var(--line)] text-left text-[11px] uppercase tracking-wider text-[var(--muted)]">
          <th className="px-4 py-2">{tr('kind.table')}</th><th className="px-2 py-2">{tr('nav.findings')}</th><th className="px-2 py-2 text-right">{tr('artifact.columns')}</th>
          <th className="px-2 py-2 text-right">{tr('table.rows')}</th><th className="px-2 py-2 text-right">{tr('artifact.dumpBytes')}</th>
        </tr></thead><tbody>{tables.map((table) => <tr key={table.id} className="border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]">
          <td className="mono px-4 py-1.5 text-[12px]"><span className="flex items-center gap-2"><Table2 size={12} />{table.name}</span></td>
          <td className="px-2 py-1.5">{table.flagged && table.worst != null ? <button onClick={() => onOpenArtifact({
            artifact: table.name, artifact_kind: 'table', worst: table.worst!, triage: table.triage ?? 'new', triage_note: '',
          })}><Tag tone="danger">{table.flagged} Finding{table.flagged === 1 ? '' : 's'}</Tag></button> : '—'}</td>
          <td className="px-2 py-1.5 text-right tabular">{table.columns}</td><td className="px-2 py-1.5 text-right tabular">{formatCount(table.rows)}</td>
          <td className="px-2 py-1.5 text-right text-[var(--muted)]">{formatBytes(table.bytes)}</td>
        </tr>)}</tbody></table>{!tables.length && <EmptyRow text={tr('database.noTableMatch')} />}</Card>
    </Section>
  </div>
}

function EmptyRow({ text }: { text: string }) {
  return <div className="px-4 py-7 text-center text-[13px] text-[var(--muted)]">{text}</div>
}

function SchemaCard({ files }: { files: DbDump[] }) {
  const tr = useT()
  const [open, setOpen] = useState(false)
  const flagged = files.filter((file) => (file.flagged ?? 0) > 0)
  return <Card className="overflow-hidden"><button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-[var(--panel-2)]">
    <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--panel-2)] text-[var(--muted)]"><FileCode2 size={16} /></span>
    <div className="min-w-0 flex-1"><div className="font-semibold">{plural(tr, files.length, 'database.schemaFiles.one', 'database.schemaFiles.many', { n: formatCount(files.length) })}</div>
      <div className="text-[11.5px] text-[var(--muted)]">{tr('database.schemaFiles.sub')}</div></div>
    {!!flagged.length && <Tag tone="danger">{flagged.length} {tr('database.withFindings')}</Tag>}
    <span className="text-xs text-[var(--muted)]">{open ? tr('common.collapse') : tr('common.view')}</span>
  </button>{open && <div className="border-t border-[var(--line)]">{files.map((file) => <div key={file.id}
    className="flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-1.5 last:border-0"><span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]">{file.path}</span>
    {!!file.flagged && <Tag tone="danger">{file.flagged} Findings</Tag>}<span className="text-xs text-[var(--muted)]">{formatBytes(file.size)}</span>
  </div>)}</div>}</Card>
}

function DumpCard({ dump }: { dump: DbDump }) {
  const tr = useT()
  const meta = dump.meta ?? {}
  const facts: [string, string, string][] = [
    [tr('database.fact.database'), meta.database || '—', tr('database.fact.database.hint')],
    [tr('database.fact.created'), meta.created || tr('database.fact.created.missing'), tr('database.fact.created.hint')],
    [tr('database.fact.server'), meta.server || '—', tr('database.fact.server.hint')],
    [tr('database.fact.tool'), [meta.tool, meta.tool_version].filter(Boolean).join(' ') || '—', tr('database.fact.tool.hint')],
  ]
  return <Card className="overflow-hidden"><div className="flex items-center gap-3 border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-3">
    <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--accent-soft)] text-[var(--accent)]"><DatabaseIcon size={17} /></span>
    <div className="min-w-0 flex-1"><div className="flex items-center gap-2 font-semibold">{baseName(dump.path)}{dump.cms && <Tag tone="accent">{dump.cms}</Tag>}</div>
      <div className="mono truncate text-[11px] text-[var(--muted)]" title={dump.path}>{dump.path}</div></div>
    <div className="text-right text-[11px] text-[var(--muted)]">{formatBytes(dump.size)}<br />{formatCount(dump.statements)} {tr('database.statements')}</div>
  </div><div className="grid grid-cols-2 gap-2 p-3 xl:grid-cols-4">{facts.map(([label, value, hint]) => <Tooltip key={label} title={label} hint={hint}
    as="div" className="!block rounded-lg bg-[var(--panel-2)] px-3 py-2"><div className="flex items-center text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
      {label === tr('database.fact.created') && <Clock size={10} className="mr-1" />}{label}<HelpCircle size={10} className="ml-auto opacity-50" /></div>
    <div className="mt-0.5 truncate text-[12px]" title={value}>{value}</div></Tooltip>)}</div></Card>
}
