// TimelineChart.tsx — requests + errors per day (same unit, one axis).
// Colors: series-1 blue / series-2 orange (validated dark-palette slots 1+2);
// legend present (2 series), tooltip on hover, recessive grid.
import {
  Bar, ComposedChart, CartesianGrid, Legend, Line, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { formatCount } from '../format'

const BLUE = '#3987e5'
const ORANGE = '#d95926'

export function TimelineChart({ data }: {
  data: { day: string; requests: number; errors: number; new_clients: number }[]
}) {
  if (!data.length) return null
  return (
    <ResponsiveContainer width="100%" height={220}>
      <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }} barCategoryGap="18%">
        <CartesianGrid stroke="#212836" strokeDasharray="0" vertical={false} />
        <XAxis
          dataKey="day"
          tick={{ fill: '#8b96a8', fontSize: 11 }}
          tickFormatter={(d: string) => d.slice(5)}
          axisLine={{ stroke: '#383835' }}
          tickLine={false}
          minTickGap={24}
        />
        <YAxis
          tick={{ fill: '#8b96a8', fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={52}
          tickFormatter={(v: number) => (v >= 1000 ? `${(v / 1000).toFixed(0)}k` : String(v))}
        />
        <Tooltip
          cursor={{ fill: 'rgba(57,135,229,0.08)' }}
          contentStyle={{
            background: '#161b25', border: '1px solid #212836', borderRadius: 10,
            fontSize: 12, color: '#e8edf4',
          }}
          labelStyle={{ color: '#8b96a8', fontWeight: 600 }}
          formatter={(value, name) => [formatCount(value as number),
            name === 'requests' ? 'Requests' : name === 'errors' ? 'Fehler (4xx/5xx)' : 'Neue Clients']}
        />
        <Legend
          wrapperStyle={{ fontSize: 12, color: '#8b96a8' }}
          formatter={(v: string) =>
            v === 'requests' ? 'Requests' : v === 'errors' ? 'Fehler (4xx/5xx)' : v}
        />
        <Bar dataKey="requests" fill={BLUE} radius={[3, 3, 0, 0]} maxBarSize={26} />
        <Line
          dataKey="errors" stroke={ORANGE} strokeWidth={2} dot={false}
          activeDot={{ r: 4, strokeWidth: 2, stroke: '#0b0e14' }}
        />
      </ComposedChart>
    </ResponsiveContainer>
  )
}
