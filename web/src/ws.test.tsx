import { act, renderHook } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { testQueryClient } from './test/setup'
import { useLiveEvents } from './ws'

afterEach(() => vi.unstubAllGlobals())

describe('analysis receipt updates', () => {
  it.each(['yara', 'sigma', 'errorlog', 'cms'])('refreshes evidence when %s finishes last', (kind) => {
    let receive: ((event: { data: string }) => void) | undefined
    class Socket {
      set onmessage(handler: (event: { data: string }) => void) { receive = handler }
      close() {}
    }
    vi.stubGlobal('WebSocket', Socket)
    const qc = testQueryClient()
    const invalidate = vi.spyOn(qc, 'invalidateQueries')
    const { unmount } = renderHook(() => useLiveEvents(), {
      wrapper: ({ children }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>,
    })
    act(() => receive?.({ data: JSON.stringify({
      type: 'job', job: { id: 1, kind, state: 'done' },
    }) }))
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['case'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['dashboard'] })
    unmount()
  })
})
