// i18n — language handling for the whole interface.
//
// English is the project default. German is a full translation, switchable
// at runtime and remembered per browser.
//
// The catalogue is a flat map of dotted keys. Flat instead of nested
// because a missing key must be obvious: `t('findings.empty.title')` that
// falls through prints the key itself, and a key is a searchable string.
//
// The chosen language also travels to the server (`?lang=`), because parts
// of the case narrative are assembled there — the chronology, GeoIP
// descriptions, log alert texts.
import { en } from './en'
import { de } from './de'

export const LANGUAGES = [
  { id: 'en', label: 'English' },
  { id: 'de', label: 'Deutsch' },
] as const

export type Lang = (typeof LANGUAGES)[number]['id']

export const CATALOGUES: Record<Lang, Record<string, string>> = { en, de }
export const STORE_KEY = 'shellhound.lang'

/** The active language outside React — the API layer needs it for `?lang=`
 *  and cannot use a hook. */
let current: Lang = 'en'
export function activeLang(): Lang {
  return current
}
export function setActiveLang(l: Lang) {
  current = l
}

export function initialLang(): Lang {
  const stored = localStorage.getItem(STORE_KEY)
  if (stored === 'en' || stored === 'de') return stored
  // Only an explicitly German browser gets German; everything else gets
  // the project default rather than a guess.
  return navigator.language?.toLowerCase().startsWith('de') ? 'de' : 'en'
}

export type Translate = (key: string, vars?: Record<string, string | number>) => string

export { I18nProvider } from './Provider'
export { useI18n, useT, plural } from './hooks'
export type { Ctx } from './context'
