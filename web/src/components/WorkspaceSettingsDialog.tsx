import { useState } from 'react'
import { useT } from '../i18n'
import { THEMES, applyTheme, currentTheme } from '../theme'
import { GeoSettings } from './GeoSettings'
import { OpenCtiSettings } from './OpenCtiSettings'
import { Modal, Section, Tabs } from './ui'

type SettingsTab = 'themes' | 'opencti' | 'geoip'

export function WorkspaceSettingsDialog({ onClose, initialTab = 'themes' }: { onClose: () => void; initialTab?: SettingsTab }) {
  const tr = useT()
  const [tab, setTab] = useState<SettingsTab>(initialTab)
  const [visited, setVisited] = useState<SettingsTab[]>([initialTab])
  const tabs = [
    { id: 'themes' as const, label: tr('settings.themes') },
    { id: 'opencti' as const, label: tr('cti.title') },
    { id: 'geoip' as const, label: tr('settings.tab.geoip') },
  ]
  return <Modal open contained onClose={onClose} title={tr('settings.title')} bodyClassName="flex min-h-0 flex-1 flex-col gap-5 p-5">
    <div className="shrink-0 overflow-x-auto"><Tabs tabs={tabs} active={tab} onChange={value => {
      setTab(value); setVisited(previous => previous.includes(value) ? previous : [...previous, value])
    }} /></div>
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className="mx-auto w-full max-w-3xl">
        {tabs.map(item => visited.includes(item.id) && <div key={item.id} role="tabpanel" aria-label={item.label} hidden={tab !== item.id}>
          {item.id === 'themes' ? <ThemeSettings /> : item.id === 'opencti' ? <OpenCtiSettings /> : <GeoSettings />}
        </div>)}
      </div>
    </div>
  </Modal>
}

function ThemeSettings() {
  const tr = useT()
  const [active, setActive] = useState(currentTheme)
  return <Section title={tr('settings.themes')} sub={tr('settings.themesHint')}>
    <div className="grid gap-3 sm:grid-cols-2" role="radiogroup" aria-label={tr('theme.choose')}>
      {THEMES.map(theme => <label key={theme.id} className={`cursor-pointer rounded-xl border p-4 transition-colors ${active === theme.id ? 'border-[var(--accent)] bg-[var(--accent-soft)]' : 'border-[var(--line)] bg-[var(--panel)] hover:bg-[var(--panel-2)]'}`}>
        <div className="mb-4 flex h-20 items-center justify-center gap-3 rounded-lg border border-[var(--line)]" style={{ background: theme.preview[0] }} aria-hidden="true">
          <span className="h-7 w-7 rounded-full" style={{ background: theme.preview[1] }} />
          <span className="h-7 w-7 rounded-full" style={{ background: theme.preview[2] }} />
        </div>
        <span className="flex items-center gap-2 text-sm font-semibold"><input type="radio" name="workspace-theme" checked={active === theme.id} onChange={() => { applyTheme(theme.id); setActive(theme.id) }} />{theme.label}</span>
      </label>)}
    </div>
  </Section>
}
