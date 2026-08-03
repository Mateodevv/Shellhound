// theme.ts — the theme registry: which themes exist, which one is active.
// The colors themselves live in index.css as [data-theme] variable blocks;
// this file only switches the attribute and remembers the choice.
// index.html applies the stored theme before first paint (no flash).

export const THEME_KEY = 'shellhound.theme'
export const DEFAULT_THEME = 'synthwave'

export interface Theme {
  id: string
  label: string
  /** [background, accent, foreground] — the preview swatch in the picker. */
  preview: [string, string, string]
}

export const THEMES: Theme[] = [
  { id: 'synthwave', label: 'Synthwave', preview: ['#0e0716', '#d84df0', '#f2e9ff'] },
  { id: 'shellhound', label: 'Shellhound', preview: ['#0b0e14', '#3987e5', '#e8edf4'] },
]

export function currentTheme(): string {
  try {
    const stored = localStorage.getItem(THEME_KEY)
    if (stored && THEMES.some((t) => t.id === stored)) return stored
  } catch { /* storage blocked: fall through to default */ }
  return DEFAULT_THEME
}

export function applyTheme(id: string) {
  document.documentElement.dataset.theme = id
  try { localStorage.setItem(THEME_KEY, id) } catch { /* non-fatal */ }
}
