// context.ts — the React context object alone, so that Provider.tsx can
// export nothing but a component and Fast Refresh keeps working.
import { createContext } from 'react'
import type { Lang, Translate } from './index'

export interface Ctx {
  lang: Lang
  setLang: (l: Lang) => void
  t: Translate
}

export const I18nContext = createContext<Ctx | null>(null)
