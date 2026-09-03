// A single lazily loaded map of locally bundled 4:3 flag assets.
const modules = import.meta.glob('../node_modules/flag-icons/flags/4x3/*.svg', {
  eager: true,
  query: '?url',
  import: 'default',
}) as Record<string, string>

export const flagUrls = new Map<string, string>()
for (const [path, url] of Object.entries(modules)) {
  const code = path.match(/\/([a-z]{2})\.svg$/)?.[1]
  if (code) flagUrls.set(code, url)
}
