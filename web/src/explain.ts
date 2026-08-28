// explain.ts — plain language for everything that would otherwise be jargon.
//
// Every rule, badge, tag and state gets TWO sentences: what the finding
// STATES, and what it means for the assessment. The second one is the
// important one — "eval on request input" helps nobody who does not already
// know what that means.
//
// The text itself lives in the i18n catalogues; this module only maps
// engine output (rule names, sources, groups) onto catalogue keys. That
// mapping is language-independent: rule names come from the engines in
// English and are never translated, because they are part of the stored
// case record.
import type { Translate } from './i18n'

export interface Explanation {
  what: string
  why?: string
}

/** Look up `<base>.what` / `<base>.why`. A key without a translation
 *  returns itself, which is how a missing entry stays visible instead of
 *  rendering as an empty tooltip. */
export function explain(t: Translate, base: string): Explanation {
  const what = t(`${base}.what`)
  const why = t(`${base}.why`)
  return {
    what: what === `${base}.what` ? '' : what,
    why: why === `${base}.why` ? undefined : why,
  }
}

// --- rules ------------------------------------------------------------------
// The key is a substring of the rule name (first match wins), so that new
// rule variants do not immediately stand there unexplained.

const RULE_KEYS: [string, string][] = [
  ['Unguarded PHP in writable upload', 'rule.unguardedUpload'],
  ['Double extension disguise', 'rule.doubleExtension'],
  ['PHP code hidden inside image', 'rule.phpInImage'],
  ['PHP file containing no PHP', 'rule.noPhp'],
  ['eval/assert on decoded or request input', 'rule.evalOnInput'],
  ['Variable function called on request input', 'rule.variableFunction'],
  ['Command execution on request input', 'rule.commandExec'],
  ['File dropper writing request input', 'rule.fileDropper'],
  ['preg_replace with /e', 'rule.pregReplaceE'],
  ['Callback taken straight from the request', 'rule.callbackInput'],
  ['create_function', 'rule.createFunction'],
  ['Upload destination taken from the request', 'rule.uploadDest'],
  ['Obfuscation decode chain', 'rule.decodeChain'],
  ['Hex/octal string obfuscation', 'rule.hexObfuscation'],
  ['chr() concatenation', 'rule.chrConcat'],
  ['goto-based control-flow', 'rule.gotoFlow'],
  ['Standalone command-execution shell', 'rule.standaloneShell'],
  ['.htaccess maps non-PHP extension', 'rule.htaccessHandler'],
  ['.htaccess auto_prepend', 'rule.htaccessPrepend'],
  ['too large to inspect', 'rule.tooLarge'],
  ['could not be read', 'rule.unreadable'],
  ['PHP open tag in database value', 'rule.dbPhpTag'],
  ['Command execution call in database value', 'rule.dbCommandExec'],
  ['Inline <script> in database value', 'rule.dbScript'],
  ['Injected <iframe>', 'rule.dbIframe'],
  ['document.write', 'rule.dbDocumentWrite'],
  ['Possible successful brute-force', 'rule.bruteForceSuccess'],
  ['CMS login POST flood', 'rule.loginFlood'],
  ['Requested PHP in upload/cache directory answered 2xx', 'rule.uploadPhpOk'],
  ['Requested PHP directly in a CMS extension directory', 'rule.cmsDirPhp'],
  ['SQL injection patterns in URIs answered 2xx', 'rule.sqliOk'],
  ['Path traversal patterns answered 2xx', 'rule.traversalOk'],
  ['Scanner tool User-Agent', 'rule.scannerUa'],
  ['PHP error names this file', 'rule.errorNames'],
]

export function explainRule(t: Translate, rule: string): Explanation | null {
  for (const [needle, key] of RULE_KEYS) {
    if (rule.includes(needle)) return explain(t, key)
  }
  return null
}

// --- categories -------------------------------------------------------------
// The top-level grouping of the findings list: not "which file" but "what
// kind of find". A case with 119 findings may have 8 categories — that is
// the overview you start from.
//
// The order is the reading order of an investigation: first what was
// CERTAINLY there (shells, injected code), then what someone DID (access,
// brute force), and last the noise (scanners).

export interface Category {
  id: string
  label: string
  what: string
  order: number
}

const CATEGORY_ORDER: [string, number][] = [
  ['webshell', 1], ['obfuscation', 2], ['htaccess', 3], ['yara', 4],
  ['db_injected', 5], ['db_markup', 6], ['shell_access', 7],
  ['bruteforce', 8], ['probes', 9], ['errorlog', 10], ['scanner', 11],
  ['other', 99],
]

export function categories(t: Translate): Record<string, Category> {
  const out: Record<string, Category> = {}
  for (const [id, order] of CATEGORY_ORDER) {
    out[id] = {
      id, order,
      label: t(`category.${id}.label`),
      what: t(`category.${id}.what`),
    }
  }
  return out
}

// (source, rule substring) -> category. The source is part of the key
// because the same rule means different things in two engines:
// "Obfuscation decode chain" in a file is obfuscation, in a data column it
// is injected code.
const CATEGORY_RULES: [string | null, string, string][] = [
  ['webshell', 'Obfuscation decode chain', 'obfuscation'],
  ['webshell', 'Hex/octal string obfuscation', 'obfuscation'],
  ['webshell', 'chr() concatenation', 'obfuscation'],
  ['webshell', 'goto-based control-flow', 'obfuscation'],
  ['webshell', '.htaccess', 'htaccess'],
  ['webshell', '', 'webshell'],
  ['sqldb', 'Inline <script>', 'db_markup'],
  ['sqldb', 'Injected <iframe>', 'db_markup'],
  ['sqldb', 'document.write', 'db_markup'],
  ['sqldb', '', 'db_injected'],
  ['logs', 'upload/cache directory', 'shell_access'],
  ['logs', 'CMS extension directory', 'shell_access'],
  ['logs', 'brute-force', 'bruteforce'],
  ['logs', 'login POST flood', 'bruteforce'],
  ['logs', 'Scanner tool User-Agent', 'scanner'],
  ['logs', 'SQL injection', 'probes'],
  ['logs', 'Path traversal', 'probes'],
  ['analyst', 'Manual file review', 'webshell'],
  ['yara', '', 'yara'],
  ['errorlog', '', 'errorlog'],
]

export function categoryId(source: string, rule: string): string {
  for (const [src, needle, category] of CATEGORY_RULES) {
    if (src !== null && src !== source) continue
    if (needle === '' || rule.includes(needle)) return category
  }
  return 'other'
}

export function categorize(t: Translate, source: string, rule: string): Category {
  return categories(t)[categoryId(source, rule)]
}

/** "12 files" / "66 clients" — what the artifacts of a category are called. */
export function artifactNoun(t: Translate, kind: string, n: number): string {
  const known = ['file', 'client', 'table', 'dump'].includes(kind)
  const base = known ? kind : 'artifact'
  return t(`kind.${base}.${n === 1 ? 'one' : 'many'}`)
}

// --- Joomla plugin groups ---------------------------------------------------
// Joomla splits every extension into a public and a backend part and sorts
// plugins into groups. Both appear as a short label on the row — and a label
// without an explanation is just a word to anyone who does not work with
// Joomla daily.

const PLUGIN_GROUPS = [
  'system', 'authentication', 'user', 'content', 'editors', 'quickicon',
  'captcha', 'search', 'finder', 'fields', 'webservices',
]

export function explainPluginGroup(t: Translate, group: string): Explanation {
  const key = group.toLowerCase()
  if (PLUGIN_GROUPS.includes(key)) return explain(t, `pluginGroup.${key}`)
  return {
    what: t('pluginGroup.unknown.what', { group }),
    why: t('pluginGroup.unknown.why'),
  }
}
