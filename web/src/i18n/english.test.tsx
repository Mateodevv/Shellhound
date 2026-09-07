import { screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { CaseNavigation } from '../App'
import { api, downloadUrl } from '../api'
import { formatCount, formatSpan, relativeTime, setActiveTimeMode } from '../format'
import { renderWithProviders } from '../test/setup'
import { translate } from './index'

describe('English interface', () => {
  it('ignores a previously saved German preference', () => {
    localStorage.setItem('shellhound.lang', 'de')
    renderWithProviders(<CaseNavigation view="dashboard" openArtifacts={0}
      onNavigate={vi.fn()} onSearch={vi.fn()} />)
    expect(screen.getByText('Investigation tools')).toBeInTheDocument()
    expect(formatCount(12345)).toBe('12,345')
    expect(formatSpan(1, 3601)).toBe('1 hour')
    vi.spyOn(Date, 'now').mockReturnValue(Date.UTC(2026, 0, 1, 12, 5))
    expect(relativeTime('2026-01-01T12:00:00Z')).toBe('5 minutes ago')
  })

  it('formats shared copy without a language provider', () => {
    expect(translate('nav.jobsRunning', { n: 3 })).toBe('3 job(s) running…')
    expect(translate('missing.key')).toBe('missing.key')
  })

  it('keeps authentication and time reading without sending language preferences', async () => {
    localStorage.setItem('shellhound.lang', 'de')
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true, json: async () => ({ ok: true }),
    } as Response)
    setActiveTimeMode('utc')
    await api('/api/state')
    const headers = new Headers(fetchMock.mock.calls[0][1]?.headers)
    expect(headers.get('X-Token')).toBe('test-token')
    expect(headers.get('X-TZ')).toBe('utc')
    expect(headers.has('X-Lang')).toBe(false)
    const url = new URL(downloadUrl('/api/report?section=notes'), 'http://localhost')
    expect(url.searchParams.get('token')).toBe('test-token')
    expect(url.searchParams.get('tz')).toBe('utc')
    expect(url.searchParams.get('section')).toBe('notes')
    expect(url.searchParams.has('lang')).toBe(false)
  })
})
