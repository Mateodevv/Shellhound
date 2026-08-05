// FileViewer.tsx — die betroffene Datei ansehen: Raw und Hex.
//
// Der Inhalt kommt als JSON-Daten vom Server und wird hier als TEXT
// gerendert. Er wird nie als Dokument geladen: eine bösartige .html aus
// einem kompromittierten Webroot ist hier eine Zeichenkette in einem <pre>,
// keine Seite, die der Browser ausführt.
//
// Große Dateien werden seitenweise gelesen (256 KB Raw, 16 KB Hex), damit
// ein 200-MB-Log den Browser nicht umbringt. Die Seite sagt immer, welcher
// BYTE-BEREICH gerade zu sehen ist — bei Evidence ist "ich sehe Teil X von
// Y" eine Aussage, die man belegen können muss.
import { useT } from '../i18n'
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import clsx from 'clsx'
import { ChevronLeft, ChevronRight, FileCode2 } from 'lucide-react'
import { api, type FileContent } from '../api'
import { formatBytes, formatCount } from '../format'
import { Button, CopyButton, Modal, Tag } from './ui'

export function FileViewer({ slug, path, focusLine, onClose, layer = 2 }: {
  slug: string
  path: string | null
  focusLine?: number | null
  onClose: () => void
  /** Standardmäßig ganz vorne: der Viewer wird fast immer AUS einem
   *  Artefakt-Detail heraus geöffnet und muss darüber liegen. */
  layer?: number
}) {
  const tr = useT()
  const [mode, setMode] = useState<'raw' | 'hex'>('raw')
  const [offset, setOffset] = useState(0)

  useEffect(() => { setOffset(0); setMode('raw') }, [path])

  const { data, isFetching, isError, error } = useQuery({
    queryKey: ['file', slug, path, mode, offset],
    queryFn: () => api<FileContent>(
      `/api/cases/${slug}/file?path=${encodeURIComponent(path!)}&mode=${mode}&offset=${offset}`),
    enabled: !!path,
  })

  if (!path) return null

  const name = path.replace(/\\/g, '/').split('/').pop()
  const pages = data ? Math.max(1, Math.ceil(data.size / data.window)) : 1
  const page = data ? Math.floor(data.offset / data.window) + 1 : 1

  return (
    <Modal open onClose={onClose} layer={layer}
      title={
        <span className="flex min-w-0 items-center gap-2">
          <FileCode2 size={16} className="shrink-0 text-[var(--accent)]" />
          <span className="mono truncate">{name}</span>
          {data && <Tag>{formatBytes(data.size)}</Tag>}
          {data?.binary && <Tag tone="warn" explain={tr('viewer.binary.hint')}>{tr('viewer.binary')}</Tag>}
        </span>
      }>
      <div className="flex flex-col gap-3">
        <div className="mono break-all rounded-lg bg-[var(--panel-2)] px-3 py-2 text-[11.5px] text-[var(--muted)]">
          {path}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="inline-flex overflow-hidden rounded-lg border border-[var(--line)]">
            {(['raw', 'hex'] as const).map((m) => (
              <button key={m}
                onClick={() => { setMode(m); setOffset(0) }}
                className={clsx(
                  'cursor-pointer px-3 py-1.5 text-[12px] font-medium uppercase transition-colors',
                  mode === m
                    ? 'bg-[var(--accent)] text-white'
                    : 'bg-[var(--panel-2)] text-[var(--muted)] hover:text-[var(--fg)]')}>
                {m}
              </button>
            ))}
          </div>

          {data && data.size > data.window && (
            <div className="flex items-center gap-1.5 text-[12px] text-[var(--muted)]">
              <Button variant="ghost" disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - data.window))}>
                <ChevronLeft size={14} />
              </Button>
              <span className="tabular whitespace-nowrap">
                Seite {page} / {pages}
              </span>
              <Button variant="ghost" disabled={data.eof}
                onClick={() => setOffset(offset + data.window)}>
                <ChevronRight size={14} />
              </Button>
            </div>
          )}

          {data && (
            <span className="tabular text-[11.5px] text-[var(--muted)]">
              Byte {formatCount(data.offset)}–{formatCount(data.offset + data.length)}
              {' von '}{formatCount(data.size)}
              {isFetching && ' · lädt…'}
            </span>
          )}

          <span className="ml-auto">
            <CopyButton value={path} label="Pfad kopieren" />
          </span>
        </div>

        {isError && (
          <div className="rounded-lg border border-[var(--sev-high)]/40 bg-[var(--danger-soft)] px-3 py-2 text-[13px] text-[var(--danger-text)]">
            {String((error as Error)?.message ?? error)}
          </div>
        )}

        {data?.mode === 'raw' && data.lines && (
          <pre className="mono max-h-[65vh] overflow-auto rounded-lg bg-[var(--code-bg)] py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
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
          <pre className="mono max-h-[65vh] overflow-auto rounded-lg bg-[var(--code-bg)] py-2 text-[11.5px] leading-relaxed text-[#e6edf3]">
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

        {data && data.from_line == null && data.mode === 'raw' && (
          <p className="text-[11px] text-[var(--muted)]">
            Diese Seite beginnt mitten in der Datei — Zeilennummern wären geraten
            und werden deshalb nicht angezeigt. Die Byte-Angabe oben ist exakt.
          </p>
        )}
      </div>
    </Modal>
  )
}
