// Settings.tsx -- what the ANALYST set up, not what a case found.
//
// The whole page is about ONE decision: whether this workstation is allowed
// to ask a third party about an indicator. Everything else here serves that
// decision -- the keys, and the sentence that says what a lookup costs.
//
// A key that is set never comes back in full. The server hands out its last
// four characters, enough to tell two keys apart and useless to sign a
// request with; the field below therefore starts empty and only ever WRITES.
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  CheckCircle2, Download, ExternalLink, FileCode2, Globe, KeyRound,
  PencilLine, Plus, ShieldAlert, ToggleLeft, ToggleRight, Trash2,
} from 'lucide-react'
import clsx from 'clsx'
import {
  api, del, post, put, type DetectionRule, type SettingsInfo,
  type YaraRuleFile,
} from '../api'
import { useT } from '../i18n'
import {
  Button, Card, Section, SeverityBadge, Tabs, Tag,
} from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { GeoDownloadModal } from '../components/GeoBanner'
import { useGeoStatus } from '../geo'

const SERVICE_ICON: Record<string, string> = {
  virustotal: 'VT',
  abuseipdb: 'AB',
}

type Tab = 'intel' | 'detection'

export function Settings({ initialTab = 'intel' }: { initialTab?: Tab }) {
  const tr = useT()
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>(initialTab)
  const { data } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api<SettingsInfo>('/api/settings'),
  })
  const refresh = () => qc.invalidateQueries({ queryKey: ['settings'] })

  const setKey = useMutation({
    mutationFn: (v: { service: string; key: string }) =>
      post('/api/settings/key', v),
    onSuccess: refresh,
  })
  const setAck = useMutation({
    mutationFn: (accepted: boolean) =>
      post('/api/settings/enrichment-ack', { accepted }),
    onSuccess: refresh,
  })

  if (!data) return null
  const services = Object.entries(data.services)

  return (
    <div className="flex max-w-3xl flex-col gap-5">
      <div>
        <h1 className="text-lg font-bold">{tr('settings.title')}</h1>
        <p className="mt-1 text-[12.5px] text-[var(--muted)]">
          {tr('settings.sub')}{' '}
          <span className="mono break-all">{data.path}</span>
        </p>
      </div>

      {/* Two groups, and they are not the same kind of decision. One is about
          what leaves this machine; the other is about what the machine looks
          for. Mixing them into one scroll made the outward-facing gate just
          another row. */}
      <Tabs tabs={[
        { id: 'intel' as const, label: tr('settings.tab.intel') },
        { id: 'detection' as const, label: tr('settings.tab.detection') },
      ]} active={tab} onChange={setTab} />

      {tab === 'intel' && <>
      <GeoSection />

      {/* The gate. It sits ABOVE the keys on purpose: a key without this is
          inert, and reading what a lookup sends is the actual decision. */}
      <Section title={tr('settings.enrichment')} sub={tr('settings.enrichment.sub')}>
        <Card className="flex flex-col gap-3 px-4 py-3">
          <div className="flex items-start gap-2.5 text-[13px]">
            <ShieldAlert size={16} className="mt-0.5 shrink-0 text-[var(--sev-low)]" />
            <div className="min-w-0">
              <div className="font-semibold">{tr('settings.ack.title')}</div>
              <p className="mt-1 text-[12.5px] leading-relaxed text-[var(--muted)]">
                {tr('settings.ack.body')}
              </p>
              <p className="mt-2 text-[12.5px] leading-relaxed text-[var(--muted)]">
                {tr('settings.ack.opinion')}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {data.enrichment_ack ? (
              <>
                <span className="inline-flex items-center gap-1.5 text-[12.5px] text-[var(--ok)]">
                  <CheckCircle2 size={14} /> {tr('settings.ack.on')}
                </span>
                <Button variant="ghost" disabled={setAck.isPending}
                  onClick={() => setAck.mutate(false)}>
                  {tr('settings.ack.revoke')}
                </Button>
              </>
            ) : (
              <Button variant="primary" disabled={setAck.isPending}
                onClick={() => setAck.mutate(true)}>
                {tr('settings.ack.accept')}
              </Button>
            )}
          </div>
        </Card>
      </Section>

      <Section title={tr('settings.keys')} sub={tr('settings.keys.sub')}>
        <div className="flex flex-col gap-2">
          {services.map(([name, svc]) => (
            <ServiceRow key={name} name={name} svc={svc}
              disabled={!data.enrichment_ack}
              onSave={(key) => setKey.mutate({ service: name, key })}
              pending={setKey.isPending} />
          ))}
        </div>
        {setKey.isError && (
          <div className="mt-2 rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[12.5px] text-[var(--danger-text)]">
            {String((setKey.error as Error)?.message ?? setKey.error)}
          </div>
        )}
      </Section>
      </>}

      {tab === 'detection' && <>
        <DetectionRules />
        <YaraRules />
      </>}
    </div>
  )
}

/** The built-in rules, with a switch each.
 *
 *  SWITCHING ONE OFF STOPS IT RUNNING. It does not withdraw what it already
 *  wrote: an artifact somebody confirmed does not stop being confirmed
 *  because the rule that pointed at it was later muted. And the setting
 *  belongs to the workspace, not the case -- "this rule is noise on the
 *  systems I work on" is knowledge about the analyst's practice. */
function DetectionRules() {
  const tr = useT()
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['rules'],
    queryFn: () => api<{ rules: DetectionRule[]; disabled: number }>('/api/rules'),
  })
  const toggle = useMutation({
    mutationFn: (v: { id: string; enabled: boolean }) =>
      post(`/api/rules/${encodeURIComponent(v.id)}/enabled`, { enabled: v.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  const rows = data?.rules ?? []
  const groups = ENGINE_ORDER
    .map((engine) => [engine, rows.filter((r) => r.engine === engine)] as const)
    .filter(([, rs]) => rs.length)

  return (
    <Section title={tr('settings.rules')} sub={tr('settings.rules.sub')}
      right={data && data.disabled > 0
        ? <span className="text-[12px] text-[var(--muted)]">
            {tr('settings.rules.off', { n: data.disabled })}
          </span>
        : undefined}>
      <div className="flex flex-col gap-3">
        {groups.map(([engine, rs]) => (
          <div key={engine}>
            <div className="mb-1 flex items-center gap-2 px-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
                {tr(`settings.rules.engine.${engine}`)}
              </span>
              <span className="text-[11px] text-[var(--muted)]">{rs.length}</span>
            </div>
            <Card className="overflow-hidden">
              {rs.map((r) => (
                <div key={r.id}
                  className={clsx('flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2 last:border-0',
                    !r.enabled && 'opacity-45')}>
                  <SeverityBadge severity={r.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px]">{r.name}</div>
                    <div className="mono truncate text-[11px] text-[var(--muted)]">
                      {r.id}
                    </div>
                  </div>
                  <Tooltip hint={r.enabled ? tr('settings.rules.off.hint')
                                           : tr('settings.rules.on.hint')}>
                    <button
                      className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)] hover:text-[var(--accent)]"
                      onClick={() => toggle.mutate({ id: r.id, enabled: !r.enabled })}>
                      {r.enabled ? <ToggleRight size={17} className="text-[var(--accent)]" />
                                 : <ToggleLeft size={17} />}
                    </button>
                  </Tooltip>
                </div>
              ))}
            </Card>
          </div>
        ))}
      </div>
    </Section>
  )
}

const ENGINE_ORDER = ['webshell', 'sqldb', 'logs', 'errorlog']

/** The country database. It sits in this tab because it is the same kind of
 *  decision as the two lookup services -- something leaves this machine --
 *  and the same kind of restraint applies: nothing is fetched until it is
 *  asked for, and after that the lookup runs entirely offline. */
function GeoSection() {
  const tr = useT()
  const [confirming, setConfirming] = useState(false)
  const { data } = useGeoStatus()

  return (
    <Section title={tr('settings.geo')} sub={tr('settings.geo.sub')}>
      <Card className="flex items-center gap-3 px-4 py-3">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--panel-2)]">
          <Globe size={15} className="text-[var(--muted)]" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[13px] font-semibold">
              {tr('settings.geo.db')}
            </span>
            {data?.available
              ? <Tag tone="accent">{tr('settings.geo.present')}</Tag>
              : <Tag>{tr('settings.geo.absent')}</Tag>}
          </div>
          <div className="mt-0.5 text-[12px] text-[var(--muted)]">
            {data?.available ? data.source : tr('settings.geo.absent.body')}
          </div>
        </div>
        <Button variant={data?.available ? 'default' : 'primary'}
          onClick={() => setConfirming(true)}>
          <Download size={14} />
          {data?.available ? tr('settings.geo.refresh') : tr('geo.download.cta')}
        </Button>
      </Card>
      <GeoDownloadModal open={confirming} onClose={() => setConfirming(false)} />
    </Section>
  )
}

/** The analyst's own YARA rules. Workspace, not case -- a rule set grows
 *  across cases, the way the pattern library does.
 *
 *  Editing them here is convenience only: the files stay plain `.yar` on
 *  disk, so a rule set from a CERT or a vendor feed can still be dropped into
 *  the folder by hand and shows up here unchanged. */
function YaraRules() {
  const tr = useT()
  const qc = useQueryClient()
  const [editing, setEditing] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)

  const { data } = useQuery({
    queryKey: ['yara-rules'],
    queryFn: () => api<{ rules: YaraRuleFile[]; dir: string; available: boolean }>(
      '/api/yara/rules'),
  })
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['yara-rules'] })
    qc.invalidateQueries({ queryKey: ['yara'] })
  }

  const toggle = useMutation({
    mutationFn: (v: { name: string; enabled: boolean }) =>
      post(`/api/yara/rules/${encodeURIComponent(v.name)}/enabled`,
           { enabled: v.enabled }),
    onSuccess: refresh,
  })
  const remove = useMutation({
    mutationFn: (name: string) =>
      del(`/api/yara/rules/${encodeURIComponent(name)}`),
    onSuccess: refresh,
  })

  const rules = data?.rules ?? []

  return (
    <Section title={tr('settings.yara')} sub={tr('settings.yara.sub')}>
      {/* Without the package the rules are inert. Saying so once, here, is
          what keeps "no YARA findings" from being ambiguous later. */}
      {data && !data.available && (
        <Card className="mb-2 flex items-start gap-2.5 px-4 py-3 text-[12.5px]">
          <ShieldAlert size={15} className="mt-0.5 shrink-0 text-[var(--sev-low)]" />
          <div>
            <div className="font-semibold">{tr('settings.yara.missing')}</div>
            <p className="mt-1 text-[var(--muted)]">
              {tr('settings.yara.missing.body')}
            </p>
            <code className="mono mt-1.5 inline-block rounded bg-[var(--code-bg)] px-2 py-1 text-[11.5px]">
              pip install &quot;yara-python&gt;=4.3&quot;
            </code>
          </div>
        </Card>
      )}

      <div className="mb-2 flex items-center gap-2">
        <Button variant="primary" onClick={() => { setCreating(true); setEditing(null) }}>
          <Plus size={14} /> {tr('settings.yara.new')}
        </Button>
        <span className="mono min-w-0 flex-1 truncate text-[11px] text-[var(--muted)]"
          title={data?.dir}>
          {data?.dir}
        </span>
      </div>

      {creating && (
        <RuleEditor name="" source={TEMPLATE} available={data?.available ?? false}
          onDone={() => { setCreating(false); refresh() }}
          onCancel={() => setCreating(false)} />
      )}

      <div className="flex flex-col gap-2">
        {rules.map((r) => editing === r.name ? (
          <LoadedEditor key={r.name} name={r.name}
            available={data?.available ?? false}
            onDone={() => { setEditing(null); refresh() }}
            onCancel={() => setEditing(null)} />
        ) : (
          <Card key={r.name}
            className={clsx('flex items-center gap-3 px-4 py-2.5',
              !r.enabled && 'opacity-45')}>
            <FileCode2 size={15} className="shrink-0 text-[var(--muted)]" />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="mono truncate text-[13px] font-medium">{r.name}</span>
                {r.error
                  ? <Tag tone="danger" hint={r.error}>{tr('settings.yara.broken')}</Tag>
                  : <Tag>{tr('settings.yara.count', { n: r.rules.length })}</Tag>}
              </div>
              <div className="mono mt-0.5 truncate text-[11px] text-[var(--muted)]"
                title={r.rules.join(', ')}>
                {r.rules.join(' · ') || '—'}
              </div>
            </div>
            <Tooltip hint={tr('settings.yara.edit.hint')}>
              <button
                className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)] hover:text-[var(--accent)]"
                onClick={() => { setEditing(r.name); setCreating(false) }}>
                <PencilLine size={15} />
              </button>
            </Tooltip>
            <Tooltip hint={r.enabled ? tr('settings.yara.off.hint')
                                     : tr('settings.yara.on.hint')}>
              <button
                className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--panel-2)] hover:text-[var(--accent)]"
                onClick={() => toggle.mutate({ name: r.name, enabled: !r.enabled })}>
                {r.enabled ? <ToggleRight size={17} className="text-[var(--accent)]" />
                           : <ToggleLeft size={17} />}
              </button>
            </Tooltip>
            <Tooltip hint={tr('settings.yara.delete.hint')}>
              <button
                className="shrink-0 cursor-pointer rounded p-1.5 text-[var(--muted)] transition-colors hover:bg-[var(--danger-soft)] hover:text-[var(--danger-text)]"
                onClick={() => remove.mutate(r.name)}>
                <Trash2 size={15} />
              </button>
            </Tooltip>
          </Card>
        ))}
        {!rules.length && !creating && (
          <div className="px-1 py-2 text-[12.5px] text-[var(--muted)]">
            {tr('settings.yara.empty')}
          </div>
        )}
      </div>
    </Section>
  )
}

/** Fetches the source, then hands it to the editor. Separate so the editor
 *  itself never has to render without its text. */
function LoadedEditor({ name, available, onDone, onCancel }: {
  name: string
  available: boolean
  onDone: () => void
  onCancel: () => void
}) {
  const { data } = useQuery({
    queryKey: ['yara-source', name],
    queryFn: () => api<{ name: string; source: string }>(
      `/api/yara/rules/${encodeURIComponent(name)}`),
  })
  if (!data) return null
  return <RuleEditor name={name} source={data.source} available={available}
    onDone={onDone} onCancel={onCancel} />
}

const TEMPLATE = `rule my_rule
{
    meta:
        // Honoured by SHELLHOUND: high / medium / low / info.
        // Without it a match lands at MEDIUM.
        severity = "medium"
        author = ""
        description = ""

    strings:
        $a = "something" nocase

    condition:
        $a
}
`

function RuleEditor({ name, source, available, onDone, onCancel }: {
  name: string
  source: string
  available: boolean
  onDone: () => void
  onCancel: () => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const [fileName, setFileName] = useState(name)
  const [text, setText] = useState(source)
  const [error, setError] = useState('')

  const save = useMutation({
    mutationFn: () => put(`/api/yara/rules/${encodeURIComponent(fileName)}`,
                          { source: text }),
    onSuccess: () => {
      setError('')
      qc.invalidateQueries({ queryKey: ['yara-source', fileName] })
      onDone()
    },
    onError: (e: Error) => setError(e.message),
  })

  return (
    <Card className="flex flex-col gap-2 px-4 py-3">
      <div className="flex items-end gap-2">
        <label className="flex min-w-56 flex-1 flex-col gap-1">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr('settings.yara.file')}
          </span>
          <input value={fileName} onChange={(e) => setFileName(e.target.value)}
            placeholder="my-rules.yar" disabled={!!name}
            className="mono w-full rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[13px] outline-none focus:border-[var(--accent)]/70 disabled:opacity-60" />
        </label>
        <Button variant="primary"
          disabled={!fileName.trim() || !text.trim() || save.isPending}
          onClick={() => save.mutate()}>
          {tr('common.save')}
        </Button>
        <Button variant="ghost" onClick={onCancel}>{tr('common.cancel')}</Button>
      </div>
      <textarea value={text} onChange={(e) => setText(e.target.value)}
        rows={16} spellCheck={false}
        className="mono w-full resize-y rounded-lg border border-[var(--line)] bg-[var(--code-bg)] px-3 py-2 text-[12px] leading-relaxed outline-none focus:border-[var(--accent)]/70" />
      <div className="text-[11.5px] text-[var(--muted)]">
        {/* Saving compiles first -- but only where the package exists. On a
            machine without it the text is stored unchecked, and saying so
            beats a green save that means nothing. */}
        {available ? tr('settings.yara.compiles') : tr('settings.yara.unchecked')}
      </div>
      {error && (
        <pre className="mono overflow-x-auto whitespace-pre-wrap rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[11.5px] text-[var(--danger-text)]">
          {error}
        </pre>
      )}
    </Card>
  )
}

function ServiceRow({ name, svc, disabled, onSave, pending }: {
  name: string
  svc: SettingsInfo['services'][string]
  disabled: boolean
  onSave: (key: string) => void
  pending: boolean
}) {
  const tr = useT()
  // Starts empty and only ever WRITES: the real key is never sent to the
  // browser, so there is nothing to prefill it with.
  const [value, setValue] = useState('')

  return (
    <Card className="flex flex-wrap items-center gap-3 px-4 py-3">
      <span className="mono flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--panel-2)] text-[11px] font-bold text-[var(--muted)]">
        {SERVICE_ICON[name] ?? '?'}
      </span>
      <div className="min-w-40 flex-1">
        <div className="flex items-center gap-2 text-[13.5px] font-semibold">
          {tr(`settings.service.${name}`)}
          {svc.configured
            ? <Tag tone="accent" hint={tr('settings.key.stored')}>{svc.hint}</Tag>
            : <Tag hint={tr('settings.key.none.hint')}>{tr('settings.key.none')}</Tag>}
        </div>
        <div className="mt-0.5 flex items-center gap-2 text-[11.5px] text-[var(--muted)]">
          <Tooltip hint={tr('settings.sends.hint')}>
            <span>{tr('settings.sends', { what: tr(`settings.kind.${svc.sends}`) })}</span>
          </Tooltip>
          <a href={svc.url} target="_blank" rel="noreferrer noopener"
            className="inline-flex items-center gap-1 hover:text-[var(--fg)]">
            <ExternalLink size={11} /> {svc.url.replace('https://', '')}
          </a>
        </div>
      </div>
      <input
        type="password"
        autoComplete="off"
        value={value}
        disabled={disabled}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && value.trim()) { onSave(value.trim()); setValue('') }
        }}
        placeholder={disabled ? tr('settings.key.locked') : tr('settings.key.placeholder')}
        className="mono w-56 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-1.5 text-[12px] outline-none focus:border-[var(--accent)]/70 disabled:opacity-50"
      />
      <Button variant="primary" disabled={disabled || pending || !value.trim()}
        onClick={() => { onSave(value.trim()); setValue('') }}>
        <KeyRound size={13} /> {tr('settings.key.save')}
      </Button>
      {svc.configured && (
        <Tooltip hint={tr('settings.key.clear.hint')}>
          <Button variant="ghost" disabled={pending} onClick={() => onSave('')}>
            <Trash2 size={13} />
          </Button>
        </Tooltip>
      )}
    </Card>
  )
}
