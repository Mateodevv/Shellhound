import { expect, it, vi } from 'vitest'
import { api, post, reportClientError } from './api'

it('records a failed file request with its server correlation ID and preserves the error', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(new Response(JSON.stringify({ detail: 'File unavailable' }), {
      status: 400, headers: { 'x-request-id': 'request-123' },
    }))
    .mockResolvedValueOnce(new Response('{}'))
  await expect(api('/api/cases/synthetic/file?path=synthetic.txt')).rejects.toThrow('File unavailable')
  expect(fetcher).toHaveBeenCalledTimes(2)
  expect(fetcher.mock.calls[1][0]).toBe('/api/diagnostics/client-error')
  const event = JSON.parse(String(fetcher.mock.calls[1][1]?.body))
  expect(event.request_id).toBe('request-123')
  expect(event.action).toBe('file-content-open')
  expect(event.stack).toBeTruthy()
})

it('does not recursively report failed logging or duplicate the same exception', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Offline'))
  const error = new Error('File read failed')
  reportClientError('file-content-open', error)
  reportClientError('browser-exception', error)
  await Promise.resolve()
  expect(fetcher).toHaveBeenCalledTimes(1)
})

it('passes cancellation to fetch without recording an expected abort as an error', async () => {
  const controller = new AbortController()
  controller.abort()
  const fetcher = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new DOMException('Aborted', 'AbortError'))
  await expect(post('/api/cases/synthetic/access/search', {}, { signal: controller.signal })).rejects.toThrow('Aborted')
  expect(fetcher).toHaveBeenCalledTimes(1)
  expect(fetcher.mock.calls[0][1]?.signal).toBe(controller.signal)
})
