// queryClient.ts — the one query cache of the application.
//
// Its own module rather than a constant inside App: the i18n provider sits
// ABOVE the QueryClientProvider (it has to, the whole tree reads the
// language from it) and therefore cannot reach the client through a hook.
// It needs to, because switching the language has to drop every cached
// answer: part of the case narrative is assembled on the server, and those
// texts were fetched in the old language.
import { QueryClient } from '@tanstack/react-query'

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 5000, retry: 1, refetchOnWindowFocus: false },
  },
})
