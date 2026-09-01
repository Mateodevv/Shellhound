import { useEffect, useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Check, CloudUpload, PackageCheck, Plus, Radar, RefreshCw, ShieldCheck, Trash2,
} from "lucide-react"
import {
  api, post, put, type OpenCtiContextEntry, type OpenCtiDraft,
  type OpenCtiDraftItem, type OpenCtiPreview, type OpenCtiPublication,
  type SettingsInfo,
} from "../api"
import { formatBytes, formatCount } from "../format"
import { useT } from "../i18n"
import { Button, Card, Modal, Tag } from "./ui"
import { useOpenCtiAvailable } from "./useOpenCti"

const caseApi = (slug: string, tail: string) =>
  "/api/cases/" + encodeURIComponent(slug) + "/opencti/" + tail

function sameItem(a: OpenCtiDraftItem, b: OpenCtiDraftItem) {
  if (a.kind !== b.kind) return false
  if (a.kind === "ioc" || a.kind === "finding") return a.id === b.id
  if (a.kind === "actor") return a.value === b.value
  return a.path === b.path
}

function itemName(item: OpenCtiDraftItem) {
  if (item.kind === "actor") return item.value
  if (item.kind === "file") {
    const parts = (item.path ?? "").split(String.fromCharCode(92)).join("/").split("/")
    return parts[parts.length - 1]
  }
  return item.kind + " #" + item.id
}

export function AddToOpenCtiButton({ slug, item, compact = false }: {
  slug: string; item: OpenCtiDraftItem; compact?: boolean
}) {
  const tr = useT()
  const qc = useQueryClient()
  const available = useOpenCtiAvailable()
  const draft = useQuery({
    queryKey: ["opencti-draft", slug],
    queryFn: () => api<OpenCtiDraft>(caseApi(slug, "draft")),
    enabled: available,
  })
  const selected = draft.data?.items.some((row) => sameItem(row, item)) ?? false
  const save = useMutation({
    mutationFn: () => {
      const current = draft.data ?? { items: [], summary: "", marking_id: "" }
      const items = selected
        ? current.items.filter((row) => !sameItem(row, item))
        : [...current.items, item]
      return put<OpenCtiDraft>(caseApi(slug, "draft"), { ...current, items })
    },
    onSuccess: (value) => qc.setQueryData(["opencti-draft", slug], value),
  })
  if (!available) return null
  return <Button variant={selected ? "primary" : "ghost"} disabled={save.isPending}
    title={selected ? tr("opencti.package.remove") : tr("opencti.package.add")}
    onClick={() => save.mutate()}>
    {selected ? <Check size={13} /> : <Plus size={13} />}
    {!compact && (selected ? tr("opencti.package.selected") : tr("opencti.package.add"))}
  </Button>
}

export function OpenCtiPackageButton({ slug }: { slug: string }) {
  const tr = useT()
  const available = useOpenCtiAvailable()
  const [open, setOpen] = useState(false)
  const draft = useQuery({
    queryKey: ["opencti-draft", slug],
    queryFn: () => api<OpenCtiDraft>(caseApi(slug, "draft")),
    enabled: available,
  })
  if (!available) return null
  return <>
    <Button variant="ghost" onClick={() => setOpen(true)}>
      <CloudUpload size={14} /> {tr("opencti.package.title")}
      {(draft.data?.items.length ?? 0) > 0 &&
        <Tag tone="accent">{formatCount(draft.data!.items.length)}</Tag>}
    </Button>
    <OpenCtiPackageModal slug={slug} open={open} onClose={() => setOpen(false)} />
  </>
}

function OpenCtiPackageModal({ slug, open, onClose }: {
  slug: string; open: boolean; onClose: () => void
}) {
  const tr = useT()
  const qc = useQueryClient()
  const settings = useQuery({
    queryKey: ["settings"], queryFn: () => api<SettingsInfo>("/api/settings"),
    enabled: open,
  })
  const draftQuery = useQuery({
    queryKey: ["opencti-draft", slug],
    queryFn: () => api<OpenCtiDraft>(caseApi(slug, "draft")),
    enabled: open,
  })
  const publications = useQuery({
    queryKey: ["opencti-publications", slug],
    queryFn: () => api<{ entries: OpenCtiPublication[] }>(caseApi(slug, "publications")),
    enabled: open,
  })
  const [summary, setSummary] = useState("")
  const [marking, setMarking] = useState("")
  const [preview, setPreview] = useState<OpenCtiPreview | null>(null)
  const [duplicateArmed, setDuplicateArmed] = useState(false)

  useEffect(() => {
    if (!draftQuery.data) return
    setSummary(draftQuery.data.summary)
    setMarking(draftQuery.data.marking_id
      || settings.data?.opencti?.default_marking_id || "")
  }, [draftQuery.data, settings.data?.opencti?.default_marking_id])

  const current = (): OpenCtiDraft => ({
    items: draftQuery.data?.items ?? [], summary, marking_id: marking,
  })
  const save = useMutation({
    mutationFn: (value: OpenCtiDraft) => put<OpenCtiDraft>(caseApi(slug, "draft"), value),
    onSuccess: (value) => qc.setQueryData(["opencti-draft", slug], value),
  })
  const makePreview = useMutation({
    mutationFn: async () => {
      const saved = await put<OpenCtiDraft>(caseApi(slug, "draft"), current())
      qc.setQueryData(["opencti-draft", slug], saved)
      return post<OpenCtiPreview>(caseApi(slug, "preview"), {
        publication_id: preview?.publication_id,
      })
    },
    onSuccess: (value) => { setPreview(value); setDuplicateArmed(false) },
  })
  const publish = useMutation({
    mutationFn: () => post<OpenCtiPublication>(caseApi(slug, "publish"), {
      publication_id: preview!.publication_id,
      expected_fingerprint: preview!.fingerprint,
      confirm_duplicate: duplicateArmed,
    }),
    onSuccess: () => {
      setPreview(null)
      qc.invalidateQueries({ queryKey: ["opencti-publications", slug] })
      qc.invalidateQueries({ queryKey: ["opencti-draft", slug] })
    },
    onError: (error) => {
      if (String(error).toLowerCase().includes("identical")) setDuplicateArmed(true)
    },
  })
  const retry = useMutation({
    mutationFn: (id: string) => post(caseApi(
      slug, "publications/" + encodeURIComponent(id) + "/retry")),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["opencti-publications", slug] }),
  })
  const caseLookup = useMutation({
    mutationFn: () => post<{ checked: number; omitted: number }>(
      caseApi(slug, "lookups"), { targets: [] }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["opencti-context", slug] }),
  })

  const updateItem = (index: number, patch: Partial<OpenCtiDraftItem> | null) => {
    const items = [...(draftQuery.data?.items ?? [])]
    if (patch) items[index] = { ...items[index], ...patch }
    else items.splice(index, 1)
    setPreview(null)
    save.mutate({ ...current(), items })
  }

  return <Modal open={open} onClose={onClose}
    title={<span className="flex items-center gap-2"><CloudUpload size={16} />
      {tr("opencti.package.title")}</span>}>
    <div className="grid min-h-[560px] gap-4 p-5 lg:grid-cols-[minmax(0,1.15fr)_minmax(360px,0.85fr)]">
      <div className="flex min-w-0 flex-col gap-4">
        <Card className="overflow-hidden">
          <div className="flex items-start gap-3 border-b border-[var(--line)] px-4 py-3">
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-semibold">{tr("opencti.package.selection")}</div>
              <div className="mt-0.5 text-[11px] text-[var(--muted)]">
                {tr("opencti.package.selection.sub")}
              </div>
            </div>
            <Button variant="ghost" disabled={caseLookup.isPending}
              onClick={() => caseLookup.mutate()}>
              <Radar size={13} className={caseLookup.isPending ? "animate-pulse" : ""} />
              {caseLookup.isPending ? tr("common.loading") : tr("opencti.case.lookup")}
            </Button>
          </div>
          <div className="max-h-56 overflow-y-auto">
            {(draftQuery.data?.items ?? []).map((item, index) =>
              <div key={item.kind + "-" + (item.id ?? item.value ?? item.path)}
                className="flex items-center gap-3 border-b border-[var(--line-soft)] px-4 py-2.5 last:border-0">
                <Tag tone="accent">{item.kind}</Tag>
                <span className="mono min-w-0 flex-1 truncate text-[12px]" title={itemName(item)}>
                  {itemName(item)}
                </span>
                {item.kind !== "finding" &&
                  <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-[var(--muted)]">
                    <input type="checkbox" checked={item.indicator}
                      onChange={(event) => updateItem(index, { indicator: event.target.checked })} />
                    {tr("opencti.package.indicator")}
                  </label>}
                <Button variant="ghost" onClick={() => updateItem(index, null)}
                  title={tr("common.remove")}><Trash2 size={13} /></Button>
              </div>)}
            {draftQuery.data && draftQuery.data.items.length === 0 &&
              <div className="p-8 text-center text-[12px] text-[var(--muted)]">
                {tr("opencti.package.empty")}
              </div>}
          </div>
        </Card>

        <label className="flex flex-col gap-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr("opencti.package.summary")}
          </span>
          <textarea value={summary}
            onChange={(event) => { setSummary(event.target.value); setPreview(null) }}
            rows={7} placeholder={tr("opencti.package.summary.placeholder")}
            className="rounded-xl border border-[var(--line)] bg-[var(--panel-2)] p-3 text-[12.5px] outline-none focus:border-[var(--accent)]/70" />
        </label>
        <label className="flex flex-col gap-1.5">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr("opencti.package.marking")}
          </span>
          <select value={marking}
            onChange={(event) => { setMarking(event.target.value); setPreview(null) }}
            className="rounded-lg border border-[var(--line)] bg-[var(--panel-2)] px-3 py-2 text-[12px]">
            <option value="">{tr("opencti.package.marking.select")}</option>
            {(settings.data?.opencti?.markings ?? []).map((row) =>
              <option key={row.id} value={row.id}>{row.name}</option>)}
          </select>
        </label>
        <div className="flex items-center gap-2">
          <Button variant="primary"
            disabled={!draftQuery.data?.items.length || !marking || makePreview.isPending}
            onClick={() => makePreview.mutate()}>
            <ShieldCheck size={14} />
            {makePreview.isPending ? tr("common.loading") : tr("opencti.package.preview")}
          </Button>
          {makePreview.isError &&
            <span className="text-[11px] text-[var(--danger-text)]">{String(makePreview.error)}</span>}
        </div>
      </div>

      <div className="flex min-w-0 flex-col gap-4">
        <Card className="min-h-72 p-4">
          <div className="mb-3 flex items-center gap-2 text-[13px] font-semibold">
            <PackageCheck size={15} /> {tr("opencti.package.transmission")}
          </div>
          {!preview && <p className="text-[12px] leading-relaxed text-[var(--muted)]">
            {tr("opencti.package.transmission.empty")}
          </p>}
          {preview && <div className="flex flex-col gap-3 text-[12px]">
            <div className="grid grid-cols-2 gap-2">
              <Metric label={tr("opencti.package.objects")} value={formatCount(preview.object_count)} />
              <Metric label={tr("opencti.package.files")} value={formatCount(preview.files.length)} />
            </div>
            <div className="rounded-lg bg-[var(--panel-2)] p-3">
              <div className="text-[10px] uppercase tracking-wider text-[var(--muted)]">
                {tr("opencti.package.marking")}
              </div>
              <div className="mt-1 font-semibold">{preview.marking.name}</div>
            </div>
            <div className="max-h-56 overflow-y-auto rounded-lg border border-[var(--line)]">
              {preview.objects.map((object) => <details key={object.id}
                className="border-b border-[var(--line-soft)] last:border-0">
                <summary className="mono cursor-pointer px-3 py-2 text-[10.5px]">
                  {object.type} · {object.id}
                </summary>
                <pre className="mono overflow-x-auto whitespace-pre-wrap break-all bg-[var(--code-bg)] px-3 py-2 text-[9.5px] leading-relaxed">
                  {JSON.stringify(object, null, 2)}
                </pre>
              </details>)}
            </div>
            {preview.files.map((file) => <div key={file.artifact_stix_id}
              className="rounded-lg border border-[var(--line)] p-3">
              <div className="mono truncate font-semibold">{file.relative_path}</div>
              <div className="mt-1 text-[11px] text-[var(--muted)]">
                {formatBytes(file.size)} · {file.mime_type} · SHA-256 {file.hashes["SHA-256"]?.slice(0, 12)}…
              </div>
              <div className="mt-1 text-[10px] text-[var(--sev-low)]">
                {tr("opencti.package.file.always")}
              </div>
            </div>)}
            <Button variant={duplicateArmed ? "danger" : "primary"} disabled={publish.isPending}
              onClick={() => publish.mutate()}>
              <CloudUpload size={14} />
              {publish.isPending ? tr("opencti.package.publishing")
                : duplicateArmed ? tr("opencti.package.duplicate.confirm")
                  : tr("opencti.package.publish")}
            </Button>
            {publish.isError &&
              <div className="text-[11px] text-[var(--danger-text)]">{String(publish.error)}</div>}
          </div>}
        </Card>

        {(publications.data?.entries ?? []).length > 0 && <Card className="overflow-hidden">
          <div className="border-b border-[var(--line)] px-4 py-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
            {tr("opencti.publications")}
          </div>
          {publications.data!.entries.slice(0, 5).map((row) =>
            <div key={row.id}
              className="flex items-center gap-2 border-b border-[var(--line-soft)] px-4 py-2 last:border-0">
              <Tag tone={row.status === "published" ? "accent"
                : row.status === "partial" ? "warn" : undefined}>{row.status}</Tag>
              <span className="mono min-w-0 flex-1 truncate text-[10px]">{row.report_stix_id}</span>
              {(row.status === "partial" || row.status === "failed") &&
                <Button variant="ghost" disabled={retry.isPending}
                  onClick={() => retry.mutate(row.id)}>
                  <RefreshCw size={12} /> {tr("opencti.retry")}
                </Button>}
            </div>)}
        </Card>}
      </div>
    </div>
  </Modal>
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="rounded-lg bg-[var(--panel-2)] p-3">
    <div className="text-lg font-bold tabular">{value}</div>
    <div className="text-[9px] uppercase tracking-wider text-[var(--muted)]">{label}</div>
  </div>
}

export function OpenCtiContextPanel({ slug, kind, value, item, compact = false }: {
  slug: string; kind: string; value: string; item?: OpenCtiDraftItem; compact?: boolean
}) {
  const tr = useT()
  const qc = useQueryClient()
  const available = useOpenCtiAvailable()
  const settings = useQuery({
    queryKey: ["settings"], queryFn: () => api<SettingsInfo>("/api/settings"),
  })
  const query = useQuery({
    queryKey: ["opencti-context", slug, kind, value],
    queryFn: () => api<{ entries: OpenCtiContextEntry[] }>(
      caseApi(slug, "context") + "?kind=" + encodeURIComponent(kind)
      + "&key=" + encodeURIComponent(value)),
    enabled: available && Boolean(value),
  })
  const lookup = useMutation({
    mutationFn: () => post(caseApi(slug, "lookups"), { targets: [{ kind, value }] }),
    onSuccess: () => qc.invalidateQueries({
      queryKey: ["opencti-context", slug, kind, value],
    }),
  })
  const promote = useMutation({
    mutationFn: (candidate: {
      snapshot: number; id: string; value: string; ioc_type: string
    }) => post(caseApi(slug, "context/promote"), {
      snapshot_id: candidate.snapshot, external_id: candidate.id,
      value: candidate.value, type: candidate.ioc_type,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["iocs"] }),
  })
  if (!available) return null
  const entry = query.data?.entries[0]
  return <div className={compact
    ? "flex items-center gap-1"
    : "rounded-xl border border-[var(--line)] bg-[var(--panel-2)] p-3"}>
    {!compact && <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">
      <Radar size={13} /> {tr("opencti.context")}
      {entry && <span className="ml-auto normal-case font-normal">{entry.fetched_at}</span>}
    </div>}
    {entry && compact && <Tag tone={entry.result.matched ? "accent" : undefined}
      hint={`${tr("opencti.context")} · ${entry.fetched_at}`}>
      OpenCTI{entry.result.matched
        ? ` · ${String(entry.result.matches[0]?.score ?? tr("opencti.context.match"))}` : " · —"}
    </Tag>}
    {entry && !compact && <div className="mb-2 flex flex-col gap-2">
      <Tag tone={entry.result.matched ? "accent" : undefined}>
        {entry.result.matched ? tr("opencti.context.match") : tr("opencti.context.noMatch")}
      </Tag>
      {entry.result.matches.map((match) => <div key={match.id}
        className="flex flex-wrap items-center gap-1.5 rounded-lg border border-[var(--line)] px-2 py-1.5 text-[10.5px]">
        <Tag tone="accent">score {String(match.score ?? "—")}</Tag>
        {(match.labels ?? []).map((label) => <Tag key={label}>{label}</Tag>)}
        {(match.markings ?? []).map((marking) =>
          <Tag key={marking.id ?? marking.standard_id}>{marking.name ?? marking.standard_id}</Tag>)}
        {(match.indicators ?? []).map((indicator) =>
          <Tag key={indicator.id} tone="warn">Indicator · {indicator.name ?? indicator.id}</Tag>)}
        {settings.data?.opencti?.url && <a
          className="ml-auto text-[var(--accent-text)] hover:underline"
          href={settings.data.opencti.url.replace(/\/$/, "")
            + "/dashboard/search?search=" + encodeURIComponent(match.id)}
          target="_blank" rel="noreferrer noopener">OpenCTI</a>}
      </div>)}
      <div className="flex flex-wrap gap-1.5">{entry.result.related.map((related) =>
        <span key={related.id}
          className="inline-flex items-center gap-1 rounded-md border border-[var(--line)] px-2 py-1 text-[10.5px]">
          {related.relationship} · {related.type} · {related.value ?? related.name ?? related.id}
          {!related.promotable && settings.data?.opencti?.url &&
            <a className="text-[var(--accent-text)] hover:underline"
              href={settings.data.opencti.url.replace(/\/$/, "")
                + "/dashboard/search?search=" + encodeURIComponent(related.id)}
              target="_blank" rel="noreferrer noopener">OpenCTI</a>}
          {related.promotable && related.value && related.ioc_type &&
            <button className="cursor-pointer text-[var(--accent-text)] hover:underline"
              onClick={() => promote.mutate({
                snapshot: entry.id, id: related.id, value: related.value!,
                ioc_type: related.ioc_type!,
              })}>{tr("opencti.context.promote")}</button>}
        </span>)}</div>
    </div>}
    {value && <Button variant="ghost" disabled={lookup.isPending}
      aria-label={compact
        ? (entry ? tr("opencti.context.refresh") : tr("opencti.context.lookup"))
        : undefined}
      title={compact
        ? (entry ? tr("opencti.context.refresh") : tr("opencti.context.lookup"))
        : undefined}
      onClick={() => lookup.mutate()}>
      <RefreshCw size={12} className={lookup.isPending ? "animate-spin" : ""} />
      {!compact && (entry ? tr("opencti.context.refresh") : tr("opencti.context.lookup"))}
    </Button>}
    {item && <AddToOpenCtiButton slug={slug} item={item} compact={compact} />}
  </div>
}
