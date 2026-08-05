// ArtifactWindow.tsx -- the detail window of ONE artifact: everything needed
// for the decision, in one view.
//
// Centred and wide rather than a strip at the edge -- judgement comes from
// CONTEXT, and context only arises when reasoning, file content and the
// clients on it lie side by side instead of scrolling one after another. On
// the left is what one decides and why; on the right, what one looks at for
// it. The decision itself at the very top, because it is the reason the
// window is open.
//
// SHARED between Findings and Actors: the same artifact looks the same
// everywhere, and a decision is the same decision everywhere.
import { plural, useT } from '../i18n'
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Bug, Check, Crosshair, Eye, FileSearch, ShieldCheck, ShieldOff, X,
} from 'lucide-react'
import { KIND_ICON } from '../artifactKinds'
import {
  api, type ArtifactContext, type Finding, type TriageResult, type TriageState,
} from '../api'
import {
  SEVERITY_VAR, absoluteTime, formatBytes, formatCount,
  formatDay, relativeTime, relativeToRoot, type EvidenceRoot,
} from '../format'
import { Button, CopyButton, Modal, SeverityBadge, Tag, TriageBadge } from './ui'
import { InfoDot, Tooltip } from './Tooltip'
import { IpFlag } from './IpFlag'
import type { TraceMarks } from './TraceWindow'
import { explainRule } from '../explain'

// With article, for the question in the detail window: "Is this file part of
// the incident?" is the most important line in there, so each kind gets its
// own phrasing instead of a generic noun.
const KIND_THIS: Record<string, string> = {
  file: 'artifact.this.file', table: 'artifact.this.table',
  client: 'artifact.this.client', dump: 'artifact.this.dump',
}

/** The minimum the window can be opened with. Findings hands in its full
 *  artifact row; Actors only knows the IP and the decision -- everything else
 *  the window fetches itself through the context endpoint. */
export interface ArtifactStub {
  artifact: string
  artifact_kind: 'file' | 'table' | 'client' | 'dump'
  worst: number
  triage: TriageState
  triage_note: string
  items?: Finding[]
}

function MetaCell({ label, children, explain }: {
  label: string; children: React.ReactNode; explain?: string
}) {
  return (
    <div className="rounded-lg bg-[var(--panel-2)] px-3 py-2">
      <div className="flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">
        {label}
        {explain && <InfoDot body={explain} />}
      </div>
      <div className="mt-0.5 text-[12px]">{children}</div>
    </div>
  )
}

function Block({ title, children, right }: {
  title: React.ReactNode; children: React.ReactNode; right?: React.ReactNode
}) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
          {title}
        </div>
        {right}
      </div>
      {children}
    </div>
  )
}

export function ArtifactWindow({ slug, artifact, roots, collected, onClose,
                                 onTriage, onView, onTrace }: {
  slug: string
  artifact: ArtifactStub | null
  roots: EvidenceRoot[]
  collected: TriageResult['collected']
  onClose: () => void
  onTriage: (state: string, note?: string) => void
  onView: (path: string, line: number | null) => void
  /** The trace is told WHAT to mark red -- otherwise one stands in front of
   *  a thousand lines looking for the one that matters. */
  onTrace: (ips: string[], marks?: TraceMarks) => void
}) {
  const tr = useT()
  const [note, setNote] = useState('')
  useEffect(() => { setNote(artifact?.triage_note ?? '') }, [artifact])

  const { data: ctx } = useQuery({
    queryKey: ['artifact', slug, artifact?.artifact],
    queryFn: () => api<ArtifactContext>(
      `/api/cases/${slug}/artifact?artifact=${encodeURIComponent(artifact!.artifact)}`),
    enabled: !!artifact,
  })

  if (!artifact) return null
  const kind = artifact.artifact_kind
  const file = ctx?.file
  const preview = file?.preview
  const actor = ctx?.actor
  const findings = ctx?.findings ?? artifact.items ?? []
  const state: TriageState = ctx?.triage ?? artifact.triage
  const worst = ctx?.worst ?? artifact.worst
  const ips = ctx?.related_ips ?? []
  const { root, rel } = relativeToRoot(artifact.artifact, roots)
  const Icon = KIND_ICON[kind] ?? Bug

  // WHAT turns red in the trace depends on the kind of artifact:
  //   file   -> the requests for THIS file. The path below the evidence is
  //             known, the query variants behind it are not -- hence a
  //             substring instead of an exact list.
  //   client -> the URI that triggered its alert.
  const marks: TraceMarks = kind === 'file'
    ? { contains: [root ? rel : artifact.artifact.replace(/\\/g, '/')],
        reason: tr('marks.fileFetched') }
    : { exact: (actor?.alerts ?? []).map((a) => a.example).filter(Boolean),
        reason: tr('marks.alertTrigger') }

  return (
    <Modal open onClose={onClose}
      title={<span className="flex min-w-0 items-center gap-2">
        <SeverityBadge severity={worst} />
        <Icon size={15} className="shrink-0 text-[var(--muted)]" />
        <span className="mono truncate">{kind === 'file' && root ? rel : artifact.artifact}</span>
        <TriageBadge state={state} label={tr(`triage.${state}`)} />
      </span>}>
      <div className="flex flex-col gap-4">
        {collected.length > 0 && (
          <div className="rounded-lg border border-[var(--ok)]/40 bg-[rgba(12,163,12,0.08)] px-3 py-2 animate-fade-up">
            <div className="mb-1 text-[12px] font-semibold text-[var(--ok)]">
              {tr('artifact.collected')}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {collected.map((c, i) => (
                <Tag key={i} tone="accent">
                  {c.type}: {c.value.length > 40 ? `…${c.value.slice(-38)}` : c.value}
                  {c.hits != null && ` (${c.hits}×)`}
                </Tag>
              ))}
            </div>
          </div>
        )}

        <div className="grid gap-4 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] lg:items-start">
          {/* ============== left: what to decide, and why ================== */}
          <div className="flex flex-col gap-4">
            {/* ---- the decision ---- */}
            <div className="rounded-xl border border-[var(--line)] bg-[var(--panel-2)] px-3 py-3">
              <div className="mb-2 text-[12.5px]">
                {tr('artifact.question', {
                  what: tr(KIND_THIS[kind] ?? 'artifact.this.generic'),
                })}{' '}
                <span className="font-semibold">{tr('artifact.question.tail')}</span>{' '}
                <span className="text-[var(--muted)]">
                  {tr('artifact.question.scope', {
                    n: formatCount(findings.length),
                    findings: plural(tr, findings.length, 'artifact.finding.one', 'artifact.finding.many'),
                  })}
                </span>
              </div>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={2}
                placeholder={tr('artifact.note.placeholder')}
                className="mb-2 w-full rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-2 text-[13px] outline-none focus:border-[var(--accent)]/70"
              />
              <div className="flex flex-wrap gap-2">
                <Button variant="primary" onClick={() => onTriage('confirmed', note)}>
                  <Check size={14} /> {tr('artifact.truePositiveCollect')}
                </Button>
                <Button onClick={() => onTriage('reviewed', note)}>
                  <Eye size={14} /> {tr('triage.reviewed')}
                </Button>
                <Button variant="danger" onClick={() => onTriage('dismissed', note)}>
                  <X size={14} /> False Positive
                </Button>
                {ctx?.triaged_at && (
                  <span className="self-center text-[11px] text-[var(--muted)]">
                    {tr('artifact.lastDecided')}: {absoluteTime(ctx.triaged_at)}
                  </span>
                )}
              </div>
              <p className="mt-2 text-[11px] text-[var(--muted)]">
                {tr('artifact.triage.explain')}
              </p>
            </div>

            {/* ---- what the artifact IS ---- */}
            <Block title={tr(`kind.${kind}`)}>
              <div className="mono flex items-center gap-2 break-all rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[12px]">
                <span className="min-w-0 flex-1">{artifact.artifact}</span>
                <CopyButton value={artifact.artifact} label={tr('copy.path')}
                  className="shrink-0" />
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {kind === 'file' && file?.exists && (
                  <Button onClick={() => onView(artifact.artifact,
                                                findings.find((f) => f.line)?.line ?? null)}>
                    <FileSearch size={14} /> {tr('artifact.viewFile')}
                  </Button>
                )}
                {kind === 'client' && (
                  <Button onClick={() => onTrace([artifact.artifact], marks)}>
                    <Crosshair size={14} /> {tr('artifact.openTrace')}
                  </Button>
                )}
              </div>
            </Block>

            {/* ---- Datei-Kontext ---- */}
            {file && (
              <div className="grid grid-cols-2 gap-2">
                <MetaCell label={tr('artifact.size')}>{file.exists ? formatBytes(file.size) : tr('artifact.fileMissing')}</MetaCell>
                <MetaCell label={tr('artifact.modified')}
                  explain={tr('artifact.mtime.hint')}>
                  <Tooltip title={absoluteTime(file.mtime)}>
                    <span>{relativeTime(file.mtime)}</span>
                  </Tooltip>
                </MetaCell>
                <MetaCell label={tr('artifact.cmsGuard')} explain={tr('field.cms_guard')}>
                  {file.cms_guard == null ? '—' : file.cms_guard ? (
                    <span className="flex items-center gap-1 text-[var(--ok)]">
                      <ShieldCheck size={12} /> {tr('artifact.guard.present')}
                    </span>
                  ) : (
                    <span className="flex items-center gap-1 text-[var(--sev-high)]">
                      <ShieldOff size={12} /> fehlt
                    </span>
                  )}
                </MetaCell>
                <MetaCell label={tr('artifact.uploadDir')} explain={tr('field.upload_dir')}>
                  {file.in_upload_dir
                    ? <span className="text-[var(--sev-medium)]">{tr('artifact.uploadDirYes')}</span>
                    : 'nein'}
                </MetaCell>
                {file.sha256 && (
                  <div className="col-span-2">
                    <MetaCell label="SHA-256" explain={tr('field.sha256')}>
                      <span className="mono flex items-center gap-2 break-all text-[11px]">
                        <span className="min-w-0 flex-1">{file.sha256}</span>
                        <CopyButton value={file.sha256} label={tr('copy.hash')}
                          className="shrink-0" />
                      </span>
                    </MetaCell>
                  </div>
                )}
              </div>
            )}

            {/* ---- WHY it is here: every finding on this artifact ---- */}
            <Block title={tr('artifact.whyFlagged', { n: formatCount(findings.length) })}>
              <div className="flex flex-col gap-1.5">
                {findings.map((f) => {
                  const e = explainRule(tr, f.rule)
                  return (
                    <div key={f.fingerprint}
                      className="rounded-lg border-l-2 bg-[var(--panel-2)] px-3 py-2"
                      style={{ borderLeftColor: SEVERITY_VAR[f.severity] }}>
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-[12.5px] font-semibold">{f.rule}</span>
                        {f.line != null && f.line !== 0 && (
                          <button
                            className="cursor-pointer text-[11px] text-[var(--accent-text)] hover:underline"
                            onClick={() => onView(artifact.artifact, f.line)}>
                            {tr('artifact.line')} {f.line}
                          </button>
                        )}
                      </div>
                      {e && (
                        <div className="mt-1 text-[12px] leading-snug">
                          {e.what}
                          {e.why && <span className="text-[var(--muted)]"> {e.why}</span>}
                        </div>
                      )}
                      {f.evidence && (
                        <pre className="mono mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-[var(--code-bg)] px-2 py-1 text-[11px] leading-relaxed text-[#e6edf3]">
                          {f.evidence}
                        </pre>
                      )}
                    </div>
                  )
                })}
              </div>
            </Block>
          </div>

          {/* ============== right: what one looks at for it ================ */}
          <div className="flex flex-col gap-4">
            {preview && !preview.error && !preview.binary && preview.lines && (
              <Block title={<>
                {tr('artifact.fileContent')}{' '}
                {preview.focus ? tr('artifact.aroundLine', { n: preview.focus }) : tr('artifact.fromStart')}
                {preview.truncated && ` — ${tr('artifact.readTruncated')}`}
              </>}>
                <pre className="mono max-h-[26rem] overflow-auto rounded-lg bg-[var(--code-bg)] px-0 py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
                  {preview.lines.map((l, i) => {
                    const n = (preview.from_line ?? 1) + i
                    const hit = n === preview.focus
                    return (
                      <div key={n} className={clsx('flex px-3', hit && 'bg-[rgba(208,59,59,0.18)]')}>
                        <span className={clsx('w-10 shrink-0 select-none pr-3 text-right',
                          hit ? 'text-[#ff8b8b]' : 'text-[#4b5566]')}>{n}</span>
                        <span className="whitespace-pre-wrap break-all">{l || ' '}</span>
                      </div>
                    )
                  })}
                </pre>
              </Block>
            )}
            {preview?.binary && (
              <div className="text-[12px] text-[var(--muted)]">
                {tr('artifact.binaryNoPreview')}
              </div>
            )}

            {/* ---- Actor-Kontext ---- */}
            {kind === 'client' && actor && (
              <div className="flex flex-col gap-2">
                <div className="grid grid-cols-2 gap-2">
                  <MetaCell label={tr('table.requests')}>{formatCount(actor.actor.requests)}</MetaCell>
                  <MetaCell label={tr('field.period')}>
                    {formatDay(actor.actor.first_epoch, actor.actor.tz)} → {formatDay(actor.actor.last_epoch, actor.actor.tz)}
                  </MetaCell>
                  <MetaCell label={tr('artifact.errors')}>
                    {formatCount(actor.actor.err4 + actor.actor.err5)}
                  </MetaCell>
                  <MetaCell label={tr('artifact.loginPosts')}>
                    {formatCount(actor.actor.login_posts)}
                    {actor.actor.login_redirects > 0 &&
                      <span className="text-[var(--sev-high)]"> · {actor.actor.login_redirects} Redirects!</span>}
                  </MetaCell>
                </div>
                {actor.alerts.length > 0 && (
                  <div className="flex flex-col gap-1">
                    {actor.alerts.map((a, i) => (
                      <div key={i} className="rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[12px]">
                        <SeverityBadge severity={a.severity} />{' '}
                        <span className="ml-1">{a.detail}</span>
                        {a.example && <div className="mono mt-0.5 truncate text-[11px] text-[var(--muted)]">{a.example}</div>}
                      </div>
                    ))}
                  </div>
                )}
                <Block title={tr('artifact.topUris')}>
                  <div className="flex flex-col gap-0.5">
                    {actor.top_paths.map((p) => (
                      <div key={p.uri} className="flex items-center gap-2 text-[12px]">
                        <span className="mono min-w-0 flex-1 truncate" title={p.uri}>{p.uri}</span>
                        <span className="shrink-0 text-[var(--muted)] tabular">{p.n}× · {p.ok}× 2xx</span>
                      </div>
                    ))}
                  </div>
                </Block>
                {actor.top_agents.length > 0 && (
                  <div className="text-[11px] text-[var(--muted)]">
                    User agents: {actor.top_agents.map((a) => `${a.agent || tr('artifact.emptyAgent')} (${a.n}×)`).join(' · ')}
                  </div>
                )}
              </div>
            )}

            {/* ---- the IPs on this artifact, each traceable at once ---- */}
            <Block
              title={<span className="flex items-center gap-1.5">
                <Crosshair size={12} /> {tr('artifact.clientsHere')} ({ips.length})
              </span>}
              right={ips.length > 1 && (
                <button
                  className="cursor-pointer text-[11px] text-[var(--accent-text)] hover:underline"
                  onClick={() => onTrace(ips.map((i) => i.ip), marks)}>
                  {tr('artifact.traceAll')}
                </button>
              )}>
              {ips.length ? (
                <div className="flex max-h-80 flex-col gap-1 overflow-y-auto">
                  {ips.map((h) => (
                    <div key={h.ip}
                      className="flex items-center gap-2 rounded-lg bg-[var(--panel-2)] px-3 py-1.5 text-[12px]">
                      <IpFlag ip={h.ip} />
                      <span className="mono font-medium">{h.ip}</span>
                      {h.in_box && <Tag tone="accent" explain={tr('artifact.ipInBox')}>IOC</Tag>}
                      <span className="min-w-0 flex-1 truncate text-[11.5px] text-[var(--muted)]"
                        title={h.why}>
                        {h.why}
                      </span>
                      {h.hits != null && (
                        <span className="shrink-0 text-[var(--muted)] tabular">
                          {formatCount(h.hits)}× · {formatCount(h.ok_hits)}× 2xx
                        </span>
                      )}
                      <Button variant="ghost" className="shrink-0"
                        onClick={() => onTrace([h.ip], marks)}>
                        <Crosshair size={12} /> Trace
                      </Button>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-[12px] text-[var(--muted)]">
                  {tr('artifact.noClients')}
                </div>
              )}
            </Block>

            {/* ---- Tabellen-/Dump-Kontext ---- */}
            {ctx?.table && (
              <div className="grid grid-cols-2 gap-2">
                <MetaCell label={tr('artifact.rowsInDump')}>{formatCount(ctx.table.rows)}</MetaCell>
                <MetaCell label={tr('artifact.columns')}>{ctx.table.columns}</MetaCell>
                <MetaCell label={tr('artifact.dumpBytes')}>{formatBytes(ctx.table.bytes)}</MetaCell>
                <MetaCell label="CMS">{ctx.table.cms || '—'}</MetaCell>
                {ctx.table.col_list && (
                  <div className="col-span-2">
                    <MetaCell label={tr('artifact.columnsInDump')}>
                      <span className="mono break-all text-[11px]">{ctx.table.col_list}</span>
                    </MetaCell>
                  </div>
                )}
              </div>
            )}
            {ctx?.dump && (
              <div className="grid grid-cols-2 gap-2">
                <MetaCell label="Statements">{formatCount(ctx.dump.statements)}</MetaCell>
                <MetaCell label={tr('artifact.size')}>{formatBytes(ctx.dump.size)}</MetaCell>
                <MetaCell label="CMS">{ctx.dump.cms || '—'}</MetaCell>
                <MetaCell label={tr('database.fact.created')}>{ctx.dump.meta?.created || '—'}</MetaCell>
              </div>
            )}
          </div>
        </div>
      </div>
    </Modal>
  )
}
