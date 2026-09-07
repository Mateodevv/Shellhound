// queryClient.ts — the one query cache of the application.
//
// Shared with the time switcher, which refreshes server-generated timestamps.
import { QueryClient } from '@tanstack/react-query'

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 5000, retry: 1, refetchOnWindowFocus: false },
  },
})
