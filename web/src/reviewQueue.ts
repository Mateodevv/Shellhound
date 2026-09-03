import type { TriageState } from './api'

/** Start with an untouched artifact. Items deliberately skipped earlier stay
 * available, but only become the fallback after the new work is exhausted. */
export function firstReviewArtifact<T extends { artifact: string; triage: TriageState }>(
  ordered: T[],
): T | null {
  return ordered.find((artifact) => artifact.triage === 'new')
    ?? ordered.find((artifact) => artifact.triage === 'reviewed')
    ?? null
}

/** Pick only a later, still-reviewable artifact. There is intentionally no
 * wrap: reaching the end is useful completion feedback, not a loop. */
export function nextReviewArtifact<T extends { artifact: string; triage: TriageState }>(
  ordered: T[], current: string, propagated: Iterable<string>,
): T | null {
  const currentIndex = ordered.findIndex((artifact) => artifact.artifact === current)
  if (currentIndex < 0) return null
  const skip = new Set(propagated)
  return ordered.slice(currentIndex + 1).find((artifact) =>
    !skip.has(artifact.artifact) &&
    (artifact.triage === 'new' || artifact.triage === 'reviewed')) ?? null
}
