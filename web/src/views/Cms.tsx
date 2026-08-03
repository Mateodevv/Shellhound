// Cms.tsx — CMS-Installationen mit Extension-Inventar. Unbekannte Versionen
// werden hervorgehoben: manipulierte Extensions haben oft keine Manifeste.
import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Puzzle, Server, TriangleAlert } from 'lucide-react'
import { api, type CmsInstall } from '../api'
import { formatCount, shortPath } from '../format'
import { Card, Chip, EmptyState, SearchInput, Section, Tag } from '../components/ui'
import { Tooltip } from '../components/Tooltip'
import { FIELD_EXPLAIN } from '../explain'
import type { ViewId } from '../App'

export function Cms({ slug }: { slug: string; gotoView: (v: ViewId) => void }) {
  const { data } = useQuery({
    queryKey: ['cms', slug],
    queryFn: () => api<{ installs: CmsInstall[] }>(`/api/cases/${slug}/cms`),
  })
  const [search, setSearch] = useState('')
  const [onlyUnknown, setOnlyUnknown] = useState(false)

  const installs = data?.installs ?? []

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-2">
        <Tooltip title="CMS Inventory"
          body="Welche CMS-Installationen im Webroot stecken und welche Erweiterungen (Plugins, Themes, Komponenten) mit welcher Version installiert sind."
          hint="Der Ausgangspunkt der meisten Fälle: Gleiche jede Version gegen bekannte Sicherheitslücken ab (WPScan, Joomla VEL).">
          <h1 className="mr-2 text-lg font-bold">CMS Inventory</h1>
        </Tooltip>
        <Tooltip hint={FIELD_EXPLAIN.unknown_version}>
          <Chip active={onlyUnknown} onClick={() => setOnlyUnknown(!onlyUnknown)}>
            <TriangleAlert size={12} /> Nur unbekannte Versionen
          </Chip>
        </Tooltip>
        <div className="ml-auto">
          <SearchInput value={search} onChange={setSearch} placeholder="Extension suchen…" />
        </div>
      </div>

      {installs.map((inst) => (
        <InstallCard key={inst.id} install={inst} search={search} onlyUnknown={onlyUnknown} />
      ))}

      {data && !installs.length && (
        <EmptyState icon={<Puzzle size={36} />} title="Noch kein CMS erfasst"
          sub="Das Inventar entsteht aus dem Webroot. Registriere die Webroot-Kopie als Evidence und starte die Analyse — WordPress- und Joomla-Installationen werden mitsamt ihren Erweiterungen automatisch erkannt." />
      )}
    </div>
  )
}

function InstallCard({ install, search, onlyUnknown }: {
  install: CmsInstall; search: string; onlyUnknown: boolean
}) {
  const items = useMemo(() => install.items.filter((i) =>
    (!onlyUnknown || i.version === '(unknown)') &&
    (!search || i.name.toLowerCase().includes(search.toLowerCase()) ||
      i.slug.toLowerCase().includes(search.toLowerCase()))),
    [install.items, search, onlyUnknown])

  const unknown = install.items.filter((i) => i.version === '(unknown)').length
  const byType = useMemo(() => {
    const out = new Map<string, typeof items>()
    for (const i of items) {
      const list = out.get(i.type) ?? []
      list.push(i)
      out.set(i.type, list)
    }
    return out
  }, [items])

  return (
    <Section
      title={`${install.cms} ${install.version}`}
      sub={install.root}
      right={
        <div className="flex items-center gap-2 text-[12px] text-[var(--muted)]">
          <Server size={14} />
          {formatCount(install.items.length)} Einträge
          {unknown > 0 && <Tag tone="warn" hint={FIELD_EXPLAIN.unknown_version}>{unknown} ohne Version</Tag>}
        </div>
      }
    >
      <div className="grid gap-3 lg:grid-cols-2">
        {[...byType.entries()].map(([type, list]) => (
          <Card key={type} className="overflow-hidden">
            <div className="border-b border-[var(--line)] bg-[var(--panel-2)] px-4 py-2 text-[12px] font-semibold">
              {type} <span className="text-[var(--muted)]">({list.length})</span>
            </div>
            <table className="w-full border-collapse text-[13px]">
              <tbody>
                {list.map((item) => (
                  <tr key={item.id}
                    className="border-b border-[var(--line-soft)] last:border-0 hover:bg-[var(--panel-2)]">
                    <td className="px-4 py-1.5">
                      <div className="font-medium">{item.name}</div>
                      <div className="mono text-[11px] text-[var(--muted)]" title={item.path}>
                        {item.slug} · {shortPath(item.path, 46)}
                      </div>
                    </td>
                    <td className="w-32 px-4 py-1.5 text-right">
                      {item.version === '(unknown)'
                        ? <Tag tone="warn" hint={FIELD_EXPLAIN.unknown_version}>unbekannt</Tag>
                        : <span className="mono text-[12px]">{item.version}</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        ))}
      </div>
      {!items.length && (
        <div className="text-[13px] text-[var(--muted)]">Kein Eintrag entspricht dem Filter.</div>
      )}
    </Section>
  )
}
