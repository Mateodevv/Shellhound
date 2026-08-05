// useTriage.ts -- the decision as a reusable building block.
//
// Deciding happens in several places (findings list, artifact window,
// Actors, dashboard), but what happens afterwards has to be the same
// everywhere: the receipt of the IOC box, the message about artifacts
// decided along with undo, the suggestion window for the middle tier.
// Whoever uses the hook renders <TriageFollowUp> (triage.tsx) once for it.
//
// Its own file, because a hook next to a component breaks Fast Refresh for
// the whole file.
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { post, type TriageLink, type TriageResult } from '../api'

export interface TriageController {
  /** Decide artifacts. `propagate: false` for undos and suggestions -- those
   *  must not trigger a new wave of propagation. */
  decide: (artifacts: string[], state: string, note?: string,
           propagate?: boolean) => void
  /** Take a propagation back: every artifact returns to the state the
   *  server supplied. */
  undo: (links: TriageLink[]) => Promise<void>
  collected: TriageResult['collected']
  clearCollected: () => void
  /** For TriageFollowUp. */
  notice: { linked: TriageLink[]; suggested: TriageLink[] } | null
  dismissNotice: () => void
  reviewing: TriageLink[] | null
  review: (links: TriageLink[] | null) => void
}

export function useTriage(slug: string, onDecided?: () => void): TriageController {
  const qc = useQueryClient()
  const [collected, setCollected] = useState<TriageResult['collected']>([])
  const [notice, setNotice] = useState<
    { linked: TriageLink[]; suggested: TriageLink[] } | null>(null)
  const [reviewing, setReviewing] = useState<TriageLink[] | null>(null)

  const refresh = () => {
    for (const key of ['findings', 'artifact', 'dashboard', 'iocs', 'actors', 'chain']) {
      qc.invalidateQueries({ queryKey: [key] })
    }
  }

  const mutation = useMutation({
    mutationFn: (v: {
      artifacts: string[]; state: string; note?: string; propagate?: boolean
    }) => post<TriageResult>(`/api/cases/${slug}/triage`, v),
    onSuccess: (result) => {
      setCollected(result.collected)
      // What was decided along and what is suggested are a MESSAGE, not a
      // question: the analyst has just decided and should learn what
      // followed from it without being torn out of their flow.
      if (result.linked?.length || result.suggested?.length) {
        setNotice({ linked: result.linked ?? [], suggested: result.suggested ?? [] })
      }
      refresh()
      onDecided?.()
    },
  })

  return {
    decide: (artifacts, state, note, propagate) =>
      mutation.mutate({ artifacts, state, note, propagate }),
    // Grouped by state so that it stays one call per group.
    // `propagate: false`, otherwise taking it back triggers a new wave.
    undo: async (links) => {
      const groups = new Map<string, { state: string; note: string; names: string[] }>()
      for (const l of links) {
        const key = `${l.previous.state}\x1f${l.previous.note}`
        const g = groups.get(key)
        if (g) g.names.push(l.artifact)
        else groups.set(key, { state: l.previous.state, note: l.previous.note,
                               names: [l.artifact] })
      }
      for (const g of groups.values()) {
        await post(`/api/cases/${slug}/triage`,
                   { artifacts: g.names, state: g.state, note: g.note,
                     propagate: false })
      }
      setNotice(null)
      refresh()
    },
    collected,
    clearCollected: () => setCollected([]),
    notice,
    dismissNotice: () => setNotice(null),
    reviewing,
    review: setReviewing,
  }
}
