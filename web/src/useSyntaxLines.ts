import { useEffect, useState } from 'react'
import { syntaxLanguage, type SyntaxLines } from './syntax'

/** Parsing is interruptible and off the UI thread; plain text is always ready. */
export function useSyntaxLines(path: string, lines?: string[], enabled = true) {
  const language = syntaxLanguage(path, lines?.slice(0, 8).join('\n'))
  const [result, setResult] = useState<{ lines: string[]; path: string; tokens: SyntaxLines | null } | null>(null)
  useEffect(() => {
    if (!enabled || !lines?.length || !language || typeof Worker === 'undefined') return
    let worker: Worker | undefined
    let timeout: ReturnType<typeof setTimeout> | undefined
    let active = true
    try {
      worker = new Worker(new URL('./syntax.worker.ts', import.meta.url), { type: 'module' })
      const finish = (tokens: SyntaxLines | null) => {
        if (!active) return
        active = false
        setResult({ lines, path, tokens })
        worker?.terminate()
        clearTimeout(timeout)
      }
      worker.onmessage = event => finish(event.data)
      worker.onerror = () => finish(null)
      timeout = setTimeout(() => finish(null), 2000)
      worker.postMessage({ language, lines })
    } catch { worker?.terminate() }
    return () => { active = false; worker?.terminate(); clearTimeout(timeout) }
  }, [path, lines, language, enabled])
  return { language, tokens: enabled && result?.path === path && result.lines === lines ? result.tokens : null }
}
