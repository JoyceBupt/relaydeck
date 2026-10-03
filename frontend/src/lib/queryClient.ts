import { QueryClient } from '@tanstack/vue-query'
import { ApiError } from '../api/client'

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 2_000,
      refetchOnWindowFocus: true,
      retry: (count, error) => {
        // A read overtaken by a mutation is simply re-read; real failures surface at once.
        if (error instanceof ApiError && error.code === 'stale_read') return count < 3
        if (error instanceof ApiError && error.code === 'network_error') return count < 1
        return false
      },
      retryDelay: 300,
    },
    mutations: { retry: false },
  },
})
