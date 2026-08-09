// Keep flags local without importing flag-icons' stylesheet. That stylesheet
// references both the 4:3 and 1:1 sets, so every country was shipped twice.
import { useEffect, useState } from 'react'

const modules = import.meta.glob('../node_modules/flag-icons/flags/4x3/*.svg', {
  query: '?url',
  import: 'default',
}) as Record<string, () => Promise<string>>

const loaders = new Map<string, () => Promise<string>>()
for (const [path, load] of Object.entries(modules)) {
  const code = path.match(/\/([a-z]{2})\.svg$/)?.[1]
  if (code) loaders.set(code, load)
}

export function useFlagUrl(iso?: string): string | undefined {
  const [loaded, setLoaded] = useState<{ iso: string; url: string }>()
  const key = iso?.toLowerCase()

  useEffect(() => {
    let active = true
    if (!key) return () => { active = false }
    const requested = key
    const load = loaders.get(requested)
    if (load) load().then((url) => {
      if (active) setLoaded({ iso: requested, url })
    })
    return () => { active = false }
  }, [key])

  return loaded && loaded.iso === key ? loaded.url : undefined
}
