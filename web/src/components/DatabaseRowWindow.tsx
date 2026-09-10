import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, type DatabaseRow, type DatabaseRowSource, type Finding } from '../api'
import { useT } from '../i18n'
import { Modal } from './ui'

/** Existing table findings can combine observations from several exports.
 * Ask for a source instead of claiming the first export produced the finding. */
export function DatabaseRowWindow({ slug, finding, sources, onClose }: {
  slug: string
  finding: Finding
  sources: DatabaseRowSource[]
  onClose: () => void
}) {
  const tr = useT()
  const [sourceId, setSourceId] = useState<number | null>(
    sources.length === 1 ? sources[0].dump_id : null)
  const { data, isPending, error } = useQuery({
    queryKey: ['database-row', slug, finding.id, sourceId],
    queryFn: () => api<DatabaseRow>(
      `/api/cases/${slug}/database/row?finding_id=${finding.id}&dump_id=${sourceId}`),
    enabled: sourceId != null,
  })
  return (
    <Modal open onClose={onClose} layer={2} contained
      title={tr('database.row.title', { table: finding.artifact, row: finding.line ?? 0 })}>
      <div className="flex min-h-0 flex-col gap-4 text-[13px]">
        <p className="text-[var(--muted)]">{tr('database.row.explain')}</p>
        {sources.length > 0 ? (
          <label className="flex min-w-0 flex-col gap-1 font-medium">
            {tr('database.row.source')}
            <select value={sourceId ?? ''} onChange={(event) => setSourceId(Number(event.target.value) || null)}
              className="w-full min-w-0 rounded-lg border border-[var(--line)] bg-[var(--panel-2)] p-2 text-[var(--fg)]">
              <option value="" disabled>{tr('database.row.choose')}</option>
              {sources.map((source) => <option key={source.dump_id} value={source.dump_id}>
                {source.dump_path}
              </option>)}
            </select>
          </label>
        ) : <p role="status">{tr('database.row.noSource')}</p>}
        {sources.length > 1 && <p className="text-[var(--muted)]">{tr('database.row.multiple')}</p>}
        {sourceId != null && isPending && <p role="status">{tr('common.loading')}</p>}
        {error && <p role="alert" className="rounded-lg bg-[var(--danger-soft)] p-3 text-[var(--danger-text)]">
          {error.message}
        </p>}
        {data && <>
          <p className="mono break-all text-[11px] text-[var(--muted)]">{data.dump_path}</p>
          {data.truncated && <p role="status" className="text-[var(--warn)]">{tr('database.row.truncated')}</p>}
          <dl className="flex flex-col gap-2">
            {data.columns.map((column, index) => (
              <div key={index} className="rounded-lg bg-[var(--panel-2)] p-3">
                <dt className="mono mb-1 break-all font-semibold">{column.name}</dt>
                <dd className="mono whitespace-pre-wrap break-all text-[12px]">
                  {column.value === null ? <span className="text-[var(--muted)]">NULL</span> : column.value}
                  {column.truncated && <span className="ml-2 text-[var(--muted)]">{tr('database.row.valueTruncated')}</span>}
                </dd>
              </div>
            ))}
          </dl>
        </>}
      </div>
    </Modal>
  )
}
