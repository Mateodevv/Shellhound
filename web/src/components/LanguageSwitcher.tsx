// LanguageSwitcher.tsx — switch the interface language at runtime.
//
// Sits next to the theme switcher, because both are the same kind of
// setting: presentation, not case data. The choice is remembered per
// browser and travels to the server, which assembles parts of the case
// narrative itself.
import { Languages } from 'lucide-react'
import { LANGUAGES, useI18n } from '../i18n'
import { Tooltip } from './Tooltip'

export function LanguageSwitcher({ up }: { up?: boolean }) {
  const { lang, setLang, t } = useI18n()
  return (
    <Tooltip title={t('app.language')} hint={t('app.language.hint')}>
      <div className="relative w-full">
        <Languages size={13}
          className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
        <select
          value={lang}
          onChange={(e) => setLang(e.target.value as typeof lang)}
          aria-label={t('app.language')}
          className="w-full cursor-pointer appearance-none rounded-lg border border-[var(--line)] bg-[var(--panel-2)] py-1.5 pl-8 pr-2 text-[12px] outline-none hover:border-[var(--accent)]/60"
          style={up ? { direction: 'ltr' } : undefined}
        >
          {LANGUAGES.map((l) => (
            <option key={l.id} value={l.id}>{l.label}</option>
          ))}
        </select>
      </div>
    </Tooltip>
  )
}
