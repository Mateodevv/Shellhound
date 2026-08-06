// SetupBanners.tsx -- what this workstation could do and has not been set up
// to do yet.
//
// Three things sit outside the tool proper: the GeoIP database, and the two
// lookup services. All three are OPTIONAL BY DESIGN, and two of them send a
// value off this machine. So these are reminders, not prompts -- they say
// what is available and what it would cost, and they take "no" for an answer
// permanently.
//
// THE RESTRAINT IS THE POINT. A banner that reappears in every case teaches
// the analyst to dismiss banners without reading them, and the next one that
// matters gets the same treatment. Each is dismissed once, per workstation,
// and stays dismissed.
//
// The enrichment banners deliberately do NOT appear until the analyst has
// accepted what a lookup sends. Nagging somebody towards sending a hash to a
// third party before they have read what that costs would invert the gate
// the settings page is built around.
import { useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { KeyRound, Settings2, X } from 'lucide-react'
import { api, type SettingsInfo } from '../api'
import { useT } from '../i18n'
import { Card } from './ui'

const HIDE_PREFIX = 'shellhound.setupHidden.'

/** One reminder. Exported because the GeoIP one carries its own download
 *  flow and only borrows the shape. */
export function SetupBanner({ id, icon, title, body, cta, onCta, onOpenSettings }: {
  /** Stable -- it is the localStorage key. Renaming it un-dismisses the
   *  banner for everybody who already said no. */
  id: string
  icon: ReactNode
  title: string
  body: string
  cta?: ReactNode
  onCta?: () => void
  onOpenSettings?: () => void
}) {
  const tr = useT()
  const [hidden, setHidden] = useState(
    () => localStorage.getItem(HIDE_PREFIX + id) === '1')
  if (hidden) return null

  return (
    <Card className="flex items-center justify-between gap-3 border-[var(--accent)]/40 bg-[var(--accent-soft)] px-4 py-3 animate-fade-up">
      <div className="flex min-w-0 items-center gap-2.5 text-[13px]">
        {icon}
        <span className="min-w-0">
          <span className="font-semibold">{title}</span> {body}
        </span>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        {cta && onCta && (
          <button onClick={onCta}
            className="inline-flex cursor-pointer items-center gap-1 text-[13px] font-semibold text-[var(--accent-text)] hover:underline">
            {cta}
          </button>
        )}
        {onOpenSettings && (
          <button onClick={onOpenSettings}
            title={tr('setup.toSettings')}
            className="inline-flex cursor-pointer items-center gap-1 text-[13px] font-semibold text-[var(--accent-text)] hover:underline">
            <Settings2 size={14} /> {tr('setup.toSettings')}
          </button>
        )}
        <button
          onClick={() => { localStorage.setItem(HIDE_PREFIX + id, '1'); setHidden(true) }}
          title={tr('setup.dismiss.hint')}
          className="cursor-pointer rounded p-1 text-[var(--muted)] transition-colors hover:text-[var(--fg)]">
          <X size={14} />
        </button>
      </div>
    </Card>
  )
}

/** The two lookup services. One banner each, and only once the analyst has
 *  opened the door -- see the note at the top of the file. */
export function EnrichmentBanners({ onOpenSettings }: {
  onOpenSettings?: () => void
}) {
  const tr = useT()
  const { data } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api<SettingsInfo>('/api/settings'),
    staleTime: 60_000,
  })
  if (!data || !data.enrichment_ack) return null

  const missing = Object.entries(data.services).filter(([, s]) => !s.configured)
  return (
    <>
      {missing.map(([name, svc]) => (
        <SetupBanner key={name} id={`key.${name}`}
          icon={<KeyRound size={15} className="shrink-0 text-[var(--accent)]" />}
          title={tr(`setup.key.${name}`)}
          body={tr('setup.key.body', { sends: tr(`settings.kind.${svc.sends}`) })}
          onOpenSettings={onOpenSettings} />
      ))}
    </>
  )
}
