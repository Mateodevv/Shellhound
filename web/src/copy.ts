// copy.ts — in die Zwischenablage, mit Rückfallweg.
//
// `navigator.clipboard` gibt es nur in einem "secure context". Localhost
// zählt dazu, ein LAN-Bind über http NICHT — und genau den unterstützt
// dieses Werkzeug (`--host 0.0.0.0 --token …`, wenn die Forensik-VM von
// einem anderen Rechner aus bedient wird). Ohne den Rückfallweg täte jeder
// Kopier-Knopf dort wortlos nichts.
export async function copyText(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
      return true
    }
  } catch {
    // weiter zum alten Weg — auch ein verweigertes Recht landet hier
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = value
    ta.setAttribute('readonly', '')
    ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}
