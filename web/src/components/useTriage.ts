// useTriage.ts — die Entscheidung als wiederverwendbarer Baustein.
//
// Entschieden wird an mehreren Stellen (Findings-Liste, Artefakt-Fenster,
// Actors, Dashboard), aber was danach passiert, muss überall dasselbe sein:
// die Quittung der IOC Box, die Meldung über mitentschiedene Artefakte mit
// Rückgängig, das Vorschlagsfenster für die mittlere Stufe. Wer den Hook
// benutzt, rendert dazu einmal <TriageFollowUp> (triage.tsx).
//
// Eigene Datei, weil ein Hook neben einer Komponente Fast Refresh für die
// ganze Datei bricht.
import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { post, type TriageLink, type TriageResult } from '../api'

export interface TriageController {
  /** Artefakte entscheiden. `propagate: false` für Rücknahmen und
   *  Vorschläge — die dürfen keine neue Übernahme-Welle auslösen. */
  decide: (artifacts: string[], state: string, note?: string,
           propagate?: boolean) => void
  /** Eine Übernahme zurücknehmen: jedes Artefakt zurück auf den Zustand,
   *  den der Server mitgeliefert hat. */
  undo: (links: TriageLink[]) => Promise<void>
  collected: TriageResult['collected']
  clearCollected: () => void
  /** Für TriageFollowUp. */
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
      // Mitentschiedenes und Vorschläge sind eine MELDUNG, keine Frage: der
      // Analyst hat gerade entschieden und soll erfahren, was daraus folgte,
      // ohne aus seinem Ablauf gerissen zu werden.
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
    // Nach Zustand gruppiert, damit es ein Aufruf je Gruppe bleibt.
    // `propagate: false`, sonst löst das Zurücknehmen eine neue Welle aus.
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
