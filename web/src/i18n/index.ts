// Shared English interface copy. Stable keys keep repeated wording consistent.
import { en } from './en'

export type Translate = (key: string, vars?: Record<string, string | number>) => string

export const translate: Translate = (key, vars) => {
  let out = en[key] ?? key
  if (vars) {
    for (const [name, value] of Object.entries(vars)) {
      out = out.replaceAll(`{${name}}`, String(value))
    }
  }
  return out
}

/** Existing views share one stable text lookup without language state. */
export function useT(): Translate {
  return translate
}

export function plural(t: Translate, n: number, one: string, many: string,
                       vars?: Record<string, string | number>): string {
  return t(n === 1 ? one : many, { n, ...vars })
}
