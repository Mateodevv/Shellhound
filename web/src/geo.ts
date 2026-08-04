// geo.ts — Länderzuordnung für IPs, gebündelt abgefragt und global gecacht.
//
// Jede Ansicht zeigt Adressen, und keine soll je Zeile einen Request
// abschicken: Aufrufe sammeln sich für einen Wimpernschlag und gehen als
// EIN Batch an /api/geo. Der Cache lebt auf Modul-Ebene — dieselbe IP ist
// in Actors, Trace und IOC Box dieselbe Antwort.
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

// Der Zustand der Datenbank, nach der ersten Antwort bekannt — damit die
// Oberfläche sagen kann, WARUM keine Flaggen kommen.
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
    // Fehler heißt „keine Aussage", nicht „kein Land" — nichts cachen,
    // der nächste Blick fragt neu.
    for (const ip of ips) for (const cb of batch.get(ip) ?? []) cb(null)
  })
}

function request(ip: string, cb: (g: GeoInfo | null) => void) {
  const list = pending.get(ip)
  if (list) list.push(cb)
  else pending.set(ip, [cb])
  if (timer === undefined) timer = window.setTimeout(flush, 40)
}

// Angemeldete Hooks — damit ein Nachladen der Datenbank die sichtbaren
// Flaggen sofort erneuert, statt bis zum Ansichtswechsel zu warten.
const listeners = new Set<() => void>()

/** Nach dem Nachladen der Datenbank: alles vergessen, was ohne sie
 *  beantwortet wurde, und jede sichtbare Stelle neu fragen lassen. */
export function clearGeoCache() {
  cache.clear()
  listeners.forEach((l) => l())
}

/** Die Zuordnung einer IP — undefined solange sie unterwegs ist, null wenn
 *  es keine gibt (keine Datenbank und kein Sonderbereich). */
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
