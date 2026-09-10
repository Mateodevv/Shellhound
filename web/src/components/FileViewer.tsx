// FileViewer.tsx -- looking at the file in question: raw and hex.
//
// The content comes from the server as JSON data and is rendered here as
// TEXT. It is never loaded as a document: a malicious .html from a
// compromised webroot is a string in a <pre> here, not a page the browser
// executes.
//
// Large files are read page by page (256 KB raw, 16 KB hex), so that a
// 200 MB log does not kill the browser. The page always says which BYTE
// RANGE is currently visible -- with evidence, "I am looking at part X of Y"
// is a statement one has to be able to back up.
import { useT } from '../i18n'
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ChevronLeft, ChevronRight, FileCode2 } from 'lucide-react'
import { api, type FileContent } from '../api'
import { formatBytes, formatCount } from '../format'
import { Button, CopyButton, Modal, Tag } from './ui'

export function FileContentPane({ slug, path, focusLine, showPath = true, className }: {
  slug: string
  path: string
  focusLine?: number | null
  showPath?: boolean
  className?: string
}) {
  const tr = useT()
  const [mode, setMode] = useState<'raw' | 'hex'>('raw')
  const [offset, setOffset] = useState<number | null>(null)
  const requestedLine = mode === 'raw' && offset == null && focusLine != null && focusLine > 0
    ? focusLine : null

  useEffect(() => { setOffset(null); setMode('raw') }, [slug, path, focusLine])

  const { data, isFetching, isError, error } = useQuery({
    queryKey: ['file', slug, path, mode, offset, requestedLine],
    queryFn: () => api<FileContent>(
      `/api/cases/${slug}/file?path=${encodeURIComponent(path!)}&mode=${mode}&offset=${offset ?? 0}` +
      (requestedLine == null ? '' : `&line=${requestedLine}`)),
    enabled: Boolean(path),
  })

  const copyableContent = data?.mode === 'raw'
    ? data.lines?.join('\n')
    : data?.rows?.map((row) =>
      `${row.offset.toString(16).padStart(8, '0')}  ${row.hex.padEnd(47, ' ')}  ${row.ascii}`)
      .join('\n')

  return (
      <div className={clsx('flex h-full min-h-0 flex-col gap-3', className)}>
        {showPath && <div className="mono break-all rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[11.5px] text-[var(--muted)]">
          {path}
        </div>}

        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex overflow-hidden rounded-lg border border-[var(--line)]">
            {(['raw', 'hex'] as const).map((m) => (
              <button key={m}
                onClick={() => { setMode(m); setOffset(null) }}
                className={clsx(
                  'cursor-pointer px-3 py-1.5 text-[12px] font-medium uppercase transition-colors',
                  mode === m
                    ? 'bg-[var(--accent)] text-white'
                    : 'bg-[var(--panel-2)] text-[var(--muted)] hover:text-[var(--fg)]')}>
                {m}
              </button>
            ))}
          </div>

          {data && (data.offset > 0 || !data.eof) && (
            <div className="flex items-center gap-1.5 text-[12px] text-[var(--muted)]">
              <Button variant="ghost" disabled={data.offset === 0 || isFetching}
                title={tr('viewer.previous')}
                onClick={() => setOffset(Math.max(0, data.offset - data.window))}>
                <ChevronLeft size={14} />
              </Button>
              <Button variant="ghost" disabled={data.eof || isFetching}
                title={tr('viewer.next')}
                onClick={() => setOffset(data.offset + data.length)}>
                <ChevronRight size={14} />
              </Button>
            </div>
          )}
          {mode === 'raw' && focusLine != null && focusLine > 0 && offset != null && (
            <Button variant="ghost" onClick={() => setOffset(null)}>{tr('viewer.reference', { n: focusLine })}</Button>
          )}

          {data && (
            <span className="tabular text-[11.5px] text-[var(--muted)]">
              {tr('viewer.byte')} {formatCount(data.offset)}–{formatCount(data.offset + data.length)}
              {' '}{tr('viewer.of')}{' '}{formatCount(data.size)}
              {isFetching && ` · ${tr('common.loading')}`}
            </span>
          )}

          <span className="ml-auto">
            <span className="flex items-center gap-1">
              {copyableContent != null && (
                <CopyButton value={copyableContent}
                  label={data?.eof && data.offset === 0 ? tr('copy.content') : tr('copy.loadedContent')} />
              )}
              <CopyButton value={path} label={tr('copy.path')} />
            </span>
          </span>
        </div>

        {data && (
          <div className="flex flex-wrap items-center gap-2">
            <Tag>{formatBytes(data.size)}</Tag>
            {data.binary && <Tag tone="warn" explain={tr('viewer.binary.hint')}>{tr('viewer.binary')}</Tag>}
          </div>
        )}

        {isFetching && !data && <p role="status" className="text-[13px] text-[var(--muted)]">{tr('common.loading')}</p>}
        {data?.focus_found === false && <p role="status" className="rounded-lg bg-[var(--panel-2)] p-3 text-[13px] text-[var(--warn)]">
          {tr('viewer.lineMissing', { n: focusLine ?? 0 })}
        </p>}
        {isError && (
          <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)]">
            {String((error as Error)?.message ?? error)}
          </div>
        )}

        {data?.mode === 'raw' && data.lines && (
          <pre className="mono min-h-0 flex-1 overflow-auto rounded-lg bg-[var(--code-bg)] py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
            {data.lines.map((line, i) => {
              const n = data.from_line != null ? data.from_line + i : null
              const hit = n != null && n === focusLine
              return (
                <div key={i} className={clsx('flex px-3', hit && 'bg-[rgba(208,59,59,0.18)]')}>
                  <span className={clsx('w-12 shrink-0 select-none pr-3 text-right',
                    hit ? 'text-[#ff8b8b]' : 'text-[#4b5566]')}>
                    {n ?? '·'}
                  </span>
                  <span className="whitespace-pre-wrap break-all">{line || ' '}</span>
                </div>
              )
            })}
          </pre>
        )}

        {data?.mode === 'hex' && data.rows && (
          <pre className="mono min-h-0 flex-1 overflow-auto rounded-lg bg-[var(--code-bg)] py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
            {data.rows.map((r) => (
              <div key={r.offset} className="flex gap-4 px-3">
                <span className="w-20 shrink-0 select-none text-right text-[#4b5566]">
                  {r.offset.toString(16).padStart(8, '0')}
                </span>
                <span className="shrink-0 whitespace-pre text-[#9ec5f4]">
                  {r.hex.padEnd(47, ' ')}
                </span>
                <span className="whitespace-pre text-[#c3c2b7]">{r.ascii}</span>
              </div>
            ))}
          </pre>
        )}

        {data && data.starts_mid_line && data.mode === 'raw' && (
          <p className="text-[11px] text-[var(--muted)]">
            {tr('viewer.partialLine')}
          </p>
        )}
      </div>
  )
}

export function FileViewer({ slug, path, focusLine, onClose, layer = 2 }: {
  slug: string
  path: string | null
  focusLine?: number | null
  onClose: () => void
  /** In front by default: the viewer is almost always opened FROM an
   *  artifact detail and has to lie above it. */
  layer?: number
}) {
  if (!path) return null
  const name = path.replace(/\\/g, '/').split('/').pop()
  return (
    <Modal open onClose={onClose} layer={layer} contained
      title={<span className="flex min-w-0 items-center gap-2">
        <FileCode2 size={16} className="shrink-0 text-[var(--accent)]" />
        <span className="mono truncate">{name}</span>
      </span>}>
      <FileContentPane slug={slug} path={path} focusLine={focusLine} />
    </Modal>
  )
}
