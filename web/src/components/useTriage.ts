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
import { post, type RetainedIoc, type TriageLink, type TriageResult } from '../api'

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
  /** The last decision changed nothing, because the artifact carries no
   *  findings. The server answers 200 for that, so somebody has to say it. */
  nothingToDecide: boolean
  dismissNothingToDecide: () => void
  retained: RetainedIoc[] | null
  keepRetained: () => void
  removeRetained: () => Promise<void>
}

export function useTriage(slug: string, onDecided?: () => void): TriageController {
  const qc = useQueryClient()
  const [collected, setCollected] = useState<TriageResult['collected']>([])
  const [nothingToDecide, setNothingToDecide] = useState(false)
  const [notice, setNotice] = useState<
    { linked: TriageLink[]; suggested: TriageLink[] } | null>(null)
  const [reviewing, setReviewing] = useState<TriageLink[] | null>(null)
  const [retained, setRetained] = useState<RetainedIoc[] | null>(null)

  const refresh = () => {
    // EVERY view that shows a triage state. The file browser, the database
    // and the CMS inventory all draw the badge and were never invalidated,
    // so they kept showing the state from before the decision until
    // something else happened to refetch them.
    for (const key of ['findings', 'artifact', 'dashboard', 'iocs', 'actors',
                       'chain', 'browse', 'database', 'cms', 'file',
                       'search']) {
      qc.invalidateQueries({ queryKey: [key] })
    }
  }

  const mutation = useMutation({
    mutationFn: (v: {
      artifacts: string[]; state: string; note?: string; propagate?: boolean
    }) => post<TriageResult>(`/api/cases/${slug}/triage`, v),
    onSuccess: (result) => {
      // A DECISION THAT RECORDED NOTHING IS NOT A DECISION. The server
      // answers 200 with `updated: 0` when the artifact has no findings --
      // an actor picked out of the search, say, which exists in the log
      // index but not in the work list. The interface reported that as
      // success and the analyst walked away believing it was filed.
      setNothingToDecide(result.updated === 0)
      setCollected(result.collected)
      setRetained(result.retained_iocs?.length ? result.retained_iocs : null)
      // What was decided along and what is suggested are a MESSAGE, not a
      // question: the analyst has just decided and should learn what
      // followed from it without being torn out of their flow.
      // SET OR CLEARED, never only set. Left standing, the previous
      // decision's message survives the next one -- and its undo button
      // reverts the artifacts THAT decision pulled along, which are not the
      // ones the analyst has just decided. An undo that takes back something
      // else is worse than no undo.
      setNotice(
        (result.linked?.length || result.suggested?.length)
          ? { linked: result.linked ?? [], suggested: result.suggested ?? [] }
          : null)
      refresh()
      onDecided?.()
    },
  })

  return {
    nothingToDecide,
    dismissNothingToDecide: () => setNothingToDecide(false),
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
    retained,
    keepRetained: () => setRetained(null),
    removeRetained: async () => {
      if (!retained) return
      const removable = retained.filter((ioc) => ioc.removable)
      if (!removable.length) return
      const artifacts = [...new Set(removable.flatMap((ioc) =>
        ioc.sources.filter((source) => !source.active).map((source) => source.artifact)))]
      await post(`/api/cases/${slug}/triage/iocs/remove`, {
        ioc_ids: removable.map((ioc) => ioc.id), artifacts,
      })
      setRetained(null)
      refresh()
    },
  }
}
