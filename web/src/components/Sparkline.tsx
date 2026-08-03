// Sparkline.tsx — tiny inline activity histogram (one series, no legend:
// the row's IP names it). Bars, not a line: buckets are counts.
export function Sparkline({ data, width = 120, height = 24, color = 'var(--accent)' }: {
  data: number[]; width?: number; height?: number; color?: string
}) {
  if (!data.length || data.every((v) => v === 0)) {
    return <div style={{ width, height }} className="opacity-30 text-[10px] text-[var(--muted)]">—</div>
  }
  const max = Math.max(...data)
  const barW = width / data.length
  return (
    <svg width={width} height={height} className="block" aria-hidden>
      {data.map((v, i) => {
        if (v === 0) return null
        const h = Math.max(1.5, (v / max) * (height - 2))
        return (
          <rect
            key={i}
            x={i * barW + 0.5}
            y={height - h}
            width={Math.max(1, barW - 1)}
            height={h}
            rx={1}
            fill={color}
            opacity={0.85}
          />
        )
      })}
    </svg>
  )
}
