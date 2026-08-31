// setup.ts -- what every test file in web/src can assume.
//
// The interface reaches for browser facilities that jsdom does not implement,
// and a component that throws on mount fails a test for a reason that has
// nothing to do with what the test is about. The stands-in below are
// each guarded, so a jsdom version that grows the real thing keeps it: a
// stub that shadows a working implementation is a second way to be wrong.
import '@testing-library/jest-dom/vitest'
import { createElement, type ReactElement, type ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, vi } from 'vitest'
import { I18nProvider } from '../i18n'

// The token is read once at module scope in api.ts, before any test can set
// it, so it has to exist before the first import of that module.
window.__SHELLHOUND_TOKEN__ = 'test-token'

// The command palette focuses its input from a frame callback. Without one,
// the palette mounts but never takes the keyboard, and a test about what
// typing does has nothing to type into.
if (!window.requestAnimationFrame) {
  window.requestAnimationFrame = ((cb: FrameRequestCallback) =>
    setTimeout(() => cb(performance.now()), 0) as unknown as number)
  window.cancelAnimationFrame = ((h: number) => clearTimeout(h))
}

// The timeline chart and the row virtualiser both measure their container,
// and throw on mount where nothing can be observed. jsdom has no layout, so
// the measurement is meaningless either way -- what matters is that the
// component around them renders.
if (!window.ResizeObserver) {
  window.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

// The theme follows the operating system when no theme was chosen. Answering
// "no" keeps every test in one appearance, which is the only way an assertion
// about a class name means anything.
if (!window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia
}

// Cross-links can move the matching forensic entry into view after opening
// its section. jsdom has no layout and therefore omits this harmless browser
// method, but the delayed call still needs a callable stand-in.
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = () => {}
}

beforeEach(() => {
  // Remembered choices (language, theme, time mode) live in localStorage, and
  // one test's choice leaking into the next is a failure that only appears in
  // a particular file order.
  localStorage.clear()
})

afterEach(() => {
  cleanup()
  // Both, and in this order: `restore` puts spied-on originals back, while
  // `clear` empties the call history of the stand-ins a module mock is made
  // of. Without the second one, "was this endpoint asked at all" reads the
  // calls of every earlier test in the file.
  vi.restoreAllMocks()
  vi.clearAllMocks()
})

/** A query client for ONE test. Isolation comes from building a fresh one
 *  per test, not from collecting garbage: an entry seeded to check that a
 *  decision invalidates it has no observer, and a client that collects those
 *  reports the entry as absent rather than as stale -- which reads exactly
 *  like the invalidation having worked. Retries are off so that a failing
 *  assertion names the call the component actually made. */
export function testQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, staleTime: 0, gcTime: Infinity },
      mutations: { retry: false },
    },
  })
}

/** The providers every view in this application is mounted under. Rendering
 *  a component without them throws inside `useT`, which fails the test for a
 *  reason that has nothing to do with what it is checking. */
export function renderWithProviders(ui: ReactElement, qc = testQueryClient()) {
  const wrap = ({ children }: { children: ReactNode }) =>
    createElement(I18nProvider, null,
      createElement(QueryClientProvider, { client: qc }, children))
  return { qc, ...render(ui, { wrapper: wrap }) }
}
