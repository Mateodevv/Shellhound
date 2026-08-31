import type {
  HuntClause, HuntPattern, HuntRuleV2, HuntTechnology,
} from '../../api'

export interface HuntDraft {
  sourceId: string
  source: 'bundled' | 'own' | 'new'
  expectedVersion: number | null
  name: string
  cve: string
  technology: HuntTechnology
  means: string
  notMeans: string
  rule: HuntRuleV2
  dsl: string
  textMode: boolean
}

export interface HuntSessionState {
  selectedId: string
  draft: HuntDraft | null
  testedHash: string
  testId: number | null
  selectedClusters: string[]
  libraryWidth: number
  editorWidth: number
  editorOpen: boolean
  libraryCollapsed: boolean
  resultCollapsed: boolean
  search: string
  filter: 'active' | 'all' | 'own' | 'bundled' | 'archived' | 'hit'
}

const DEFAULT_RULE: HuntRuleV2 = {
  client_match: 'any',
  requests: [{ clauses: [
    { field: 'uri', operator: 'wildcard', values: [''] },
  ] }],
}

export const DEFAULT_SESSION: HuntSessionState = {
  selectedId: '', draft: null, testedHash: '', testId: null,
  selectedClusters: [], libraryWidth: 340, editorWidth: 560, editorOpen: false,
  libraryCollapsed: false, resultCollapsed: false,
  search: '', filter: 'active',
}

export function splitDescription(description: string) {
  const [means = '', notMeans = ''] = String(description || '')
    .split(/WHAT A HIT DOES NOT PROVE:/i)
  return { means: means.trim(), notMeans: notMeans.trim() }
}

export function joinDescription(means: string, notMeans: string) {
  const cleanMeans = means.trim()
  const cleanNot = notMeans.trim()
  return cleanNot
    ? `${cleanMeans}\n\nWHAT A HIT DOES NOT PROVE:\n${cleanNot}`.trim()
    : cleanMeans
}

export function patternDraft(pattern: HuntPattern): HuntDraft {
  const description = splitDescription(pattern.description)
  return {
    sourceId: pattern.id,
    source: pattern.source,
    expectedVersion: pattern.version,
    name: pattern.name,
    cve: pattern.cve,
    technology: pattern.technology,
    means: description.means,
    notMeans: description.notMeans,
    rule: structuredClone(pattern.rule),
    dsl: pattern.dsl,
    textMode: false,
  }
}

export function emptyDraft(seed?: Partial<HuntDraft>): HuntDraft {
  return {
    sourceId: '', source: 'new', expectedVersion: null,
    name: '', cve: '', technology: 'generic', means: '', notMeans: '',
    rule: structuredClone(DEFAULT_RULE), dsl: toDsl(DEFAULT_RULE),
    textMode: false, ...seed,
  }
}

export function toDsl(rule: HuntRuleV2) {
  const lines = [`client ${rule.client_match}`]
  rule.requests.forEach((request) => {
    lines.push('request')
    request.clauses.forEach((clause) => {
      lines.push(`  ${clause.field} ${clause.operator} ${JSON.stringify(clause.values)}`)
    })
    lines.push('end')
  })
  return lines.join('\n')
}

export function draftHash(draft: HuntDraft | null) {
  if (!draft) return ''
  return JSON.stringify({
    name: draft.name, cve: draft.cve, technology: draft.technology,
    means: draft.means, notMeans: draft.notMeans,
    rule: draft.rule, dsl: draft.textMode ? draft.dsl : toDsl(draft.rule),
  })
}

export function updateClause(
  rule: HuntRuleV2, requestIndex: number, clauseIndex: number,
  update: Partial<HuntClause>,
) {
  const next = structuredClone(rule)
  next.requests[requestIndex].clauses[clauseIndex] = {
    ...next.requests[requestIndex].clauses[clauseIndex], ...update,
  }
  return next
}

export function sessionKey(slug: string) {
  return `shellhound:hunt-workbench:${slug}`
}

export function loadSession(slug: string): HuntSessionState {
  try {
    const raw = JSON.parse(sessionStorage.getItem(sessionKey(slug)) || '{}')
    return { ...DEFAULT_SESSION, ...raw }
  } catch {
    return { ...DEFAULT_SESSION }
  }
}

export function saveSession(slug: string, state: HuntSessionState) {
  try { sessionStorage.setItem(sessionKey(slug), JSON.stringify(state)) } catch { /* non-fatal */ }
}
