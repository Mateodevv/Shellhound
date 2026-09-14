import { useQuery } from '@tanstack/react-query'
import { api } from '../api'
import type { LogSourcesResponse } from '../logApi'

export function useLogSources(slug: string) {
  return useQuery({ queryKey: ['log-sources', slug], queryFn: () => api<LogSourcesResponse>(`/api/cases/${slug}/log-sources`), refetchInterval: 5000 })
}
