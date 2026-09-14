import { highlightLines } from './syntaxHighlight'
self.onmessage = (event: MessageEvent<{ language: string; lines: string[] }>) => {
  try { self.postMessage(highlightLines(event.data.language, event.data.lines)) }
  catch { self.postMessage(null) }
}
