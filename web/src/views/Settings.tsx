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
import { CheckCircle2, ExternalLink, KeyRound, ShieldAlert, Trash2 } from 'lucide-react'
import { api, post, type SettingsInfo } from '../api'
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
    </div>
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
