// geo.ts -- country attribution for IPs, queried in batches and cached
// globally.
//
// Every view shows addresses, and none should fire a request per row: calls
// collect for the blink of an eye and go out as ONE batch to /api/geo. The
// cache lives at module level -- the same IP is the same answer in Actors,
// Trace and the IOC box.
import { useEffect, useState } from 'react'
import { post } from './api'

export interface GeoInfo {
  iso: string | null
  name: string
  special: boolean
}

interface GeoResponse {
  available: boolean
  source: string
  why: string
  results: Record<string, GeoInfo>
}

const cache = new Map<string, GeoInfo | null>()
let pending = new Map<string, ((g: GeoInfo | null) => void)[]>()
let timer: number | undefined

// The state of the database, known after the first answer -- so that the
// interface can say WHY no flags are coming.
export let geoStatus: { available: boolean; source: string; why: string } | null = null

function flush() {
  timer = undefined
  const batch = pending
  pending = new Map()
  const ips = [...batch.keys()]
  post<GeoResponse>('/api/geo', { ips }).then((res) => {
    geoStatus = { available: res.available, source: res.source, why: res.why }
    for (const ip of ips) {
      const info = res.results[ip] ?? null
      cache.set(ip, info)
      for (const cb of batch.get(ip) ?? []) cb(info)
    }
  }, () => {
    // An error means "no statement", not "no country" -- cache nothing, the
    // next look asks again.
    for (const ip of ips) for (const cb of batch.get(ip) ?? []) cb(null)
  })
}

function request(ip: string, cb: (g: GeoInfo | null) => void) {
  const list = pending.get(ip)
  if (list) list.push(cb)
  else pending.set(ip, [cb])
  if (timer === undefined) timer = window.setTimeout(flush, 40)
}

// Registered hooks -- so that fetching the database refreshes the visible
// flags at once instead of waiting for a change of view.
const listeners = new Set<() => void>()

/** After the database was fetched: forget everything answered without it,
 *  and let every visible place ask again. */
export function clearGeoCache() {
  cache.clear()
  listeners.forEach((l) => l())
}

/** The attribution of an IP -- undefined while it is in flight, null when
 *  there is none (no database and no special range). */
export function useGeo(ip?: string | null): GeoInfo | null | undefined {
  const key = (ip ?? '').trim()
  const [info, setInfo] = useState<GeoInfo | null | undefined>(
    () => (key && cache.has(key) ? cache.get(key) : undefined))
  useEffect(() => {
    if (!key) { setInfo(null); return }
    let alive = true
    const load = () => {
      if (cache.has(key)) setInfo(cache.get(key))
      else request(key, (g) => { if (alive) setInfo(g) })
    }
    load()
    const onClear = () => { setInfo(undefined); load() }
    listeners.add(onClear)
    return () => { alive = false; listeners.delete(onClear) }
  }, [key])
  return key ? info : null
}
