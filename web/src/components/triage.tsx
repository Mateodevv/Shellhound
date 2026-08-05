// triage.tsx — was einer Entscheidung FOLGT, als sichtbarer Baustein:
// Meldung über Mitentschiedenes mit Rückgängig, Vorschlagsfenster für die
// mittlere Stufe. Der Hook dazu lebt in useTriage.ts; wer ihn benutzt,
// rendert einmal <TriageFollowUp>.
import { plural, useT } from '../i18n'
import { useEffect, useState } from 'react'
import { Bug, Check, Crosshair, Undo2, X } from 'lucide-react'
import { type TriageLink } from '../api'
import { formatCount, relativeToRoot, type EvidenceRoot } from '../format'
import { Button, Modal, Toast, TriageBadge } from './ui'
import { KIND_ICON } from '../artifactKinds'
import type { TriageController } from './useTriage'

/** Nur der Dateiname bzw. die Adresse — in einer Meldung zählt, WAS gemeint
 *  ist, nicht der vollständige Pfad. */
function shortArtifact(artifact: string): string {
  return artifact.replace(/\\/g, '/').replace(/\/+$/, '').split('/').pop() ?? artifact
}

/** Meldung + Vorschlagsfenster zu einer Entscheidung. Einmal pro View
 *  rendern; `layer` hebt das Vorschlagsfenster über ein offenes
 *  Artefakt-Fenster. */
export function TriageFollowUp({ t, roots, layer = 1 }: {
  t: TriageController
  roots: EvidenceRoot[]
  layer?: number
}) {
  const tr = useT()
  const n = t.notice
  return (
    <>
      <SuggestionWindow
        links={t.reviewing}
        roots={roots}
        layer={layer}
        onClose={() => t.review(null)}
        onDecide={(names, state) => {
          t.review(null)
          t.dismissNotice()
          // A suggestion is already the result of a propagation — it does
          // not pull another one behind it. The note is written into the case
          // and therefore stays in the project language, English.
          t.decide(names, state, 'decided from suggestion', false)
        }}
      />

      <Toast
        open={!!n}
        onClose={t.dismissNotice}
        tone={n?.linked.length ? 'ok' : 'info'}
        title={n?.linked.length
          ? plural(tr, n.linked.length, 'triage.alsoDecided.one', 'triage.alsoDecided.many',
                   { n: formatCount(n.linked.length) })
          : plural(tr, n?.suggested.length ?? 0, 'triage.linkedFound.one', 'triage.linkedFound.many',
                   { n: formatCount(n?.suggested.length ?? 0) })}
        actions={
          <>
            {!!n?.suggested.length && (
              <Button onClick={() => t.review(n.suggested)}>
                {plural(tr, n.suggested.length, 'triage.review.one', 'triage.review.many',
                        { n: formatCount(n.suggested.length) })}
              </Button>
            )}
            {!!n?.linked.length && (
              <Button variant="ghost" onClick={() => t.undo(n.linked)}>
                <Undo2 size={14} /> {tr('common.undo')}
              </Button>
            )}
            <Button variant="ghost" onClick={t.dismissNotice}>{tr('common.close')}</Button>
          </>
        }>
        {!!n?.linked.length && (
          <>
            {tr('triage.alsoDecided.body')}
            <ul className="mt-1 flex flex-col gap-0.5">
              {n.linked.slice(0, 4).map((l) => (
                <li key={l.artifact} className="truncate">
                  <span className="mono text-[var(--fg)]">{shortArtifact(l.artifact)}</span>
                  {' — '}{l.why}
                </li>
              ))}
              {n.linked.length > 4 && <li>{tr('triage.andMore', { n: n.linked.length - 4 })}</li>}
            </ul>
          </>
        )}
        {!n?.linked.length && !!n?.suggested.length && (
          <>{tr('triage.linkedFound.body')}</>
        )}
      </Toast>
    </>
  )
}

/** The middle tier: artifacts that HANG on the decision but do not FOLLOW
 *  from it — requested, never successful. They are put forward, not decided:
 *  a probe into the void is something other than an access. */
function SuggestionWindow({ links, roots, layer, onClose, onDecide }: {
  links: TriageLink[] | null
  roots: EvidenceRoot[]
  layer: number
  onClose: () => void
  onDecide: (artifacts: string[], state: string) => void
}) {
  const tr = useT()
  const [picked, setPicked] = useState<Set<string>>(new Set())
  useEffect(() => { setPicked(new Set(links?.map((l) => l.artifact) ?? [])) }, [links])
  if (!links) return null
  return (
    <Modal open onClose={onClose} layer={layer}
      title={<span className="flex items-center gap-2">
        <Crosshair size={16} className="text-[var(--accent)]" />
        {plural(tr, links.length, 'triage.review.linked.one', 'triage.review.linked.many',
                { n: formatCount(links.length) })}
      </span>}>
      <div className="flex flex-col gap-3">
        <p className="text-[12.5px] text-[var(--muted)]">
          {tr('triage.suggest.a')}{' '}
          <span className="text-[var(--fg)]">{tr('triage.suggest.noAccess')}</span>.{' '}
          {tr('triage.suggest.b')}
        </p>
        <div className="flex flex-col gap-1">
          {links.map((l) => {
            const Icon = KIND_ICON[l.kind] ?? Bug
            const { root, rel } = relativeToRoot(l.artifact, roots)
            return (
              <label key={l.artifact}
                className="flex cursor-pointer items-center gap-2.5 rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[12.5px]">
                <input type="checkbox" className="cursor-pointer accent-[var(--accent)]"
                  checked={picked.has(l.artifact)}
                  onChange={(e) => {
                    const next = new Set(picked)
                    if (e.target.checked) next.add(l.artifact)
                    else next.delete(l.artifact)
                    setPicked(next)
                  }} />
                <Icon size={14} className="shrink-0 text-[var(--muted)]" />
                <span className="mono min-w-0 truncate font-medium"
                  title={l.artifact}>
                  {l.kind === 'file' && root ? rel : l.artifact}
                </span>
                <span className="min-w-0 flex-1 truncate text-[var(--muted)]">{l.why}</span>
                <TriageBadge state={l.previous.state}
                  label={tr(`triage.${l.previous.state}`)} />
              </label>
            )
          })}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" disabled={!picked.size}
            onClick={() => onDecide([...picked], 'confirmed')}>
            <Check size={14} /> {tr('triage.markAs', { n: formatCount(picked.size), what: 'True Positive' })}
          </Button>
          <Button variant="danger" disabled={!picked.size}
            onClick={() => onDecide([...picked], 'dismissed')}>
            <X size={14} /> {tr('triage.markAs', { n: formatCount(picked.size), what: 'False Positive' })}
          </Button>
          <Button variant="ghost" onClick={onClose}>{tr('common.later')}</Button>
        </div>
      </div>
    </Modal>
  )
}
