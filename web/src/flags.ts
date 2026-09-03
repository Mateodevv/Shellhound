// Keep flags local without importing flag-icons' stylesheet. That stylesheet
// references both the 4:3 and 1:1 sets, so every country was shipped twice.
// The URL map is one lazy chunk: flags stay local, the entry stays lean, and
// we avoid one JavaScript wrapper chunk per country.
import { useEffect, useState } from 'react'

let urlsPromise: Promise<Map<string, string>> | null = null
const loadUrls = () => {
  urlsPromise ??= import('./flagUrls').then((module) => module.flagUrls)
  return urlsPromise
}

export function useFlagUrl(iso?: string): string | undefined {
  const [loaded, setLoaded] = useState<{ iso: string; url: string }>()
  const key = iso?.toLowerCase()

  useEffect(() => {
    let active = true
    if (!key) return () => { active = false }
    const requested = key
    loadUrls().then((urls) => {
      const url = urls.get(requested)
      if (active && url) setLoaded({ iso: requested, url })
    })
    return () => { active = false }
  }, [key])

  return loaded && loaded.iso === key ? loaded.url : undefined
}
