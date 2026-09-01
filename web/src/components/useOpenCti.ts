import { useQuery } from '@tanstack/react-query'
import { api, type SettingsInfo } from '../api'

/** Case actions stay absent until connection, author and marking were tested. */
export function useOpenCtiAvailable() {
  const query = useQuery({
    queryKey: ['settings'],
    queryFn: () => api<SettingsInfo>('/api/settings'),
  })
  const value = query.data?.opencti
  return Boolean(value?.configured && value.verified
    && value.author_id && value.default_marking_id)
}
