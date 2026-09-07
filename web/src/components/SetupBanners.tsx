// Optional workstation setup reminders are dismissible and never start external requests.
import { useState, type ReactNode } from 'react'
import { KeyRound, Settings2, X } from 'lucide-react'
import { useOpenCtiSettings } from '../opencti'
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
    <Card className="flex flex-col items-start justify-between gap-3 border-[var(--accent)]/40 bg-[var(--accent-soft)] px-4 py-3 animate-fade-up sm:flex-row sm:items-center">
      <div className="flex min-w-0 flex-1 items-center gap-2.5 text-[13px]">
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
          title={tr('setup.dismiss.hint')} aria-label={`${tr('setup.dismiss')} ${title}`}
          className="cursor-pointer rounded p-1 text-[var(--muted)] transition-colors hover:text-[var(--fg)]">
          <X size={14} />
        </button>
      </div>
    </Card>
  )
}

/** Missing optional API keys, with an explicit route to their setup. */
export function EnrichmentBanners({ onOpenSettings }: {
  onOpenSettings?: () => void
}) {
  const tr = useT()
  const { data } = useOpenCtiSettings()
  if (!data || data.configured) return null
  return <SetupBanner id="opencti"
    icon={<KeyRound size={15} className="shrink-0 text-[var(--accent)]" />}
    title={tr('cti.noConfig')} body={tr('cti.setupBody')}
    onOpenSettings={onOpenSettings} />
}
