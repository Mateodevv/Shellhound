// copy.ts -- to the clipboard, with a fallback.
//
// `navigator.clipboard` only exists in a "secure context". Localhost counts
// as one, a LAN bind over http does NOT -- and that is exactly what this
// tool supports (`--host 0.0.0.0 --token …`, when the forensic VM is
// operated from another machine). Without the fallback every copy button
// there would silently do nothing.
export async function copyText(value: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
      return true
    }
  } catch {
    // on to the old route -- a denied permission also lands here
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
