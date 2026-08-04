// TimelineChart.tsx — der Verlauf: Balken für ALLE Anfragen, darüber zwei
// Kurven für die beantworteten (2xx) und die abgewiesenen (4xx/5xx).
//
// Warum drei Reihen statt einer: die Gesamtzahl sagt, WIE VIEL los war, das
// Verhältnis sagt, WAS los war. 500 Anfragen mit 20 Erfolgen sind ein
// Abklopfen, 500 mit 480 Erfolgen sind Betrieb — und eine Erfolgskurve, die
// mitten in einer Fehlerwelle nach oben geht, ist der Moment, in dem etwas
// funktioniert hat, das vorher nicht funktionierte.
//
// Die Farben kommen aus den Theme-Variablen (SVG versteht `var()`), damit
// das Diagramm dem gewählten Theme folgt statt in fest verdrahtetem Blau zu
// stehen. 2xx trägt die OK-Farbe, Fehler die Warnfarbe — dieselbe Bedeutung
// wie überall sonst in der Oberfläche.
import {
  Bar, ComposedChart, CartesianGrid, Legend, Line, ResponsiveContainer,
  Tooltip, XAxis, YAxis,
} from 'recharts'
import { formatCount } from '../format'

export interface TimelinePoint {
  day: string
  requests: number
  errors: number
  new_clients?: number
  /** Mit 2xx beantwortet. `null` bei einem Index aus einer älteren Version,
   *  der die Spalte noch nicht kennt — dann bleibt die Kurve weg. */
  ok?: number | null
}

const LABEL: Record<string, string> = {
  requests: 'Anfragen gesamt',
  ok: 'beantwortet (2xx)',
  errors: 'abgewiesen (4xx/5xx)',
  new_clients: 'neue Clients',
}

export function TimelineChart({ data, height = 220 }: {
  data: TimelinePoint[]
  height?: number
}) {
  if (!data.length) return null
  const hasOk = data.some((d) => d.ok != null)
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
            [formatCount(value as number), LABEL[name as string] ?? name]}
        />
        <Legend
          wrapperStyle={{ fontSize: 12, color: 'var(--muted)' }}
          formatter={(v: string) => LABEL[v] ?? v}
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
