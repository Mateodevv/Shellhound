// Provider.tsx — the React side of i18n, separate from the catalogue and
// the helpers so that Fast Refresh keeps working.
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { CATALOGUES, STORE_KEY, initialLang, setActiveLang, type Lang, type Translate } from './index'
import { I18nContext } from './context'
import { en } from './en'

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(() => {
    const l = initialLang()
    setActiveLang(l)
    return l
  })

  useEffect(() => {
    setActiveLang(lang)
    localStorage.setItem(STORE_KEY, lang)
    document.documentElement.lang = lang
  }, [lang])

  const t = useCallback<Translate>((key, vars) => {
    const table = CATALOGUES[lang]
    // Fall back to English before falling back to the key: a string the
    // German catalogue has not caught up with should still read as text.
    let out = table[key] ?? en[key] ?? key
    if (vars) {
      for (const [name, value] of Object.entries(vars)) {
        out = out.replaceAll(`{${name}}`, String(value))
      }
    }
    return out
  }, [lang])

  const value = useMemo(
    () => ({ lang, setLang: setLangState, t }), [lang, t])
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}
