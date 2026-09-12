import type { Ioc } from '../api'

/** Parse components for display only; the original IOC identity stays intact. */
export function valueAttributes(object: Ioc): [string, string][] {
  const value = object.value.trim()
  if (object.type === 'hash') {
    const algorithm = /^[a-f\d]+$/i.test(value) ? ({ 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' } as Record<number, string>)[value.length] : undefined
    return [['algorithm', algorithm || '']]
  }
  if (object.type === 'email') {
    const at = value.lastIndexOf('@')
    return [['emailDomain', at > 0 && at < value.length - 1 && !/\s/.test(value.slice(at + 1)) ? value.slice(at + 1) : '']]
  }
  if (object.type === 'url' || object.type === 'domain') {
    try {
      if (object.type === 'domain' && /[\s/:@?#\\]/.test(value)) return [['dnsName', '']]
      const url = new URL(object.type === 'domain' ? `https://${value}` : value)
      if (!url.hostname) throw new Error('Missing host')
      if (object.type === 'domain') return [['dnsName', url.hostname]]
      // Preserve original path spelling, including encoded characters and dot segments.
      // Credentials, query values and fragments are not copied into separate fields.
      const parts = value.match(/^[a-z][a-z\d+.-]*:\/\/([^/?#]*)([^?#]*)/i)
      if (!parts) throw new Error('Missing authority')
      const port = parts[1].split('@').pop()?.match(/:(\d+)$/)?.[1]
      const path = parts[2]
      return [['scheme', url.protocol.slice(0, -1)], ['host', url.hostname],
        ...(port ? [['port', port] as [string, string]] : []), ['requestPath', path || '/']]
    } catch { return [[object.type === 'domain' ? 'dnsName' : 'urlParts', '']] }
  }
  return []
}
