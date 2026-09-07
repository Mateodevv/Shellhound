import { act, renderHook } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { testQueryClient } from './test/setup'
import { useLiveEvents } from './ws'
import type { Job } from './api'

afterEach(() => vi.unstubAllGlobals())

describe('analysis receipt updates', () => {
  it('merges live phases only into the matching case and preserves omitted job details', () => {
    let receive: ((event: { data: string }) => void) | undefined
    class Socket {
      set onmessage(handler: (event: { data: string }) => void) { receive = handler }
      close() {}
    }
    vi.stubGlobal('WebSocket', Socket)
    const qc = testQueryClient()
    const job: Job = { id: 1, run_id: 'original', kind: 'webshell', state: 'running',
      progress: 0, message: '', error: '', created: '', stats: { scanned: 12 } }
    qc.setQueryData(['jobs', 'first'], [job])
    qc.setQueryData(['jobs', 'second'], [job])
    const { unmount } = renderHook(() => useLiveEvents(), {
      wrapper: ({ children }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>,
    })
    const update = { id: 1, state: 'running', progress: 0.2,
      progress_details: { phase: 'discovering', completed: 42, total: null } }
    act(() => receive?.({ data: JSON.stringify({ type: 'job', case_slug: 'first', job: update }) }))
    expect(qc.getQueryData<Job[]>(['jobs', 'first'])?.[0]).toMatchObject({ ...job, ...update })
    expect(qc.getQueryData(['jobs', 'second'])).toEqual([job])
    act(() => receive?.({ data: JSON.stringify({ type: 'job', job: { ...update, progress: 0.8 } }) }))
    expect(qc.getQueryData<Job[]>(['jobs', 'first'])?.[0].progress).toBe(0.2)
    qc.setQueryData(['jobs', 'first'], [{ ...job, state: 'done', progress: 1 }])
    act(() => receive?.({ data: JSON.stringify({ type: 'job', case_slug: 'first', job: update }) }))
    expect(qc.getQueryData<Job[]>(['jobs', 'first'])?.[0].state).toBe('done')
    unmount()
  })
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
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['job-skips'] })
    unmount()
  })
})
