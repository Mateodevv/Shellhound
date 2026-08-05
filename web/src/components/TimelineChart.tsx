// TimelineChart.tsx -- the timeline: bars for ALL requests, above them two
// curves for the answered (2xx) and the rejected (4xx/5xx) ones.
//
// Why three series instead of one: the total says HOW MUCH was going on, the
// ratio says WHAT was going on. 500 requests with 20 successes are probing,
// 500 with 480 successes are business as usual -- and a success curve that
// rises in the middle of a wave of errors is the moment something worked
// that had not worked before.
//
// The colours come from the theme variables (SVG understands `var()`), so
// the chart follows the chosen theme instead of standing in hard-wired blue.
// 2xx carries the OK colour, errors the warning colour -- the same meaning
// as everywhere else in the interface.
import {
  Bar, ComposedChart, CartesianGrid, Legend, Line, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { formatCount } from '../format'
import { useT } from '../i18n'

export interface TimelinePoint {
  day: string
  requests: number
  errors: number
  new_clients?: number
  /** Answered with 2xx. `null` on an index from an older version that does
   *  not know the column yet -- the curve then stays away. */
  ok?: number | null
}

const LABEL: Record<string, string> = {
  requests: 'chart.requests',
  ok: 'chart.ok',
  errors: 'chart.errors',
  new_clients: 'chart.newClients',
}

export function TimelineChart({ data, height = 220 }: {
  data: TimelinePoint[]
  height?: number
}) {
  const tr = useT()
  const label = (k: string) => (LABEL[k] ? tr(LABEL[k]) : k)
  const hasOk = data.some((d) => d.ok != null)
  if (!data.length) return null
  return (
    <ResponsiveContainer width="100%" height={height}>
      <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
        barCategoryGap="18%">
        <CartesianGrid stroke="var(--line)" strokeDasharray="0" vertical={false} />
        <XAxis
          dataKey="day"
          tick={{ fill: 'var(--muted)', fontSize: 11 }}
          tickFormatter={(d: string) => d.slice(5)}
          axisLine={{ stroke: 'var(--line)' }}
          tickLine={false}
          minTickGap={24}
        />
        <YAxis
          tick={{ fill: 'var(--muted)', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={52}
          tickFormatter={(v: number) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : String(v))}
        />
        <Tooltip
          cursor={{ fill: 'var(--accent-soft)' }}
          contentStyle={{
            background: 'var(--panel-2)', border: '1px solid var(--line)',
            borderRadius: 10, fontSize: 12, color: 'var(--fg)',
          }}
          labelStyle={{ color: 'var(--muted)', fontWeight: 600 }}
          formatter={(value, name) =>
            [formatCount(value as number), label(name as string)]}
        />
        <Legend
          wrapperStyle={{ fontSize: 12, color: 'var(--muted)' }}
          formatter={(v: string) => label(v)}
        />
        <Bar dataKey="requests" fill="var(--accent)" radius={[3, 3, 0, 0]}
          maxBarSize={26} fillOpacity={0.55} />
        {hasOk && (
          <Line
            dataKey="ok" stroke="var(--ok)" strokeWidth={2} dot={false}
            activeDot={{ r: 4, strokeWidth: 2, stroke: 'var(--bg)' }}
          />
        )}
        <Line
          dataKey="errors" stroke="var(--sev-medium)" strokeWidth={2} dot={false}
          activeDot={{ r: 4, strokeWidth: 2, stroke: 'var(--bg)' }}
        />
      </ComposedChart>
    </ResponsiveContainer>
  )
}
