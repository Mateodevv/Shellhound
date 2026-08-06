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
  CheckCircle2, ExternalLink, FileCode2, KeyRound, PencilLine, Plus,
  ShieldAlert, ToggleLeft, ToggleRight, Trash2,
} from 'lucide-react'
import clsx from 'clsx'
import {
  api, del, post, put, type SettingsInfo, type YaraRuleFile,
} from '../api'
import { useT } from '../i18n'
import { Button, Card, Section, Tag } from '../components/ui'
import { Tooltip } from '../components/Tooltip'

const SERVICE_ICON: Record<string, string> = {
  virustotal: 'VT',
  abuseipdb: 'AB',
}

export function Settings() {
  const tr = useT()
  const qc = useQueryClient()
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
    <div className="flex max-w-3xl flex-col gap-6">
      <div>
        <h1 className="text-lg font-bold">{tr('settings.title')}</h1>
        <p className="mt-1 text-[12.5px] text-[var(--muted)]">
          {tr('settings.sub')}{' '}
          <span className="mono break-all">{data.path}</span>
        </p>
      </div>

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

      <YaraRules />
    </div>
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
