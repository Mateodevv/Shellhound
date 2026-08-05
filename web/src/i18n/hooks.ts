// hooks.ts — reading the language from any component.
import { useContext } from 'react'
import { I18nContext, type Ctx } from './context'
import type { Translate } from './index'

export function useI18n(): Ctx {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n outside I18nProvider')
  return ctx
}

/** Shorthand for the common case. */
export function useT(): Translate {
  return useI18n().t
}

/** Plural helper for the two forms English and German share. */
export function plural(t: Translate, n: number, one: string, many: string,
                       vars?: Record<string, string | number>): string {
  return t(n === 1 ? one : many, { n, ...vars })
}
