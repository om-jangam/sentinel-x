import { QueryClient } from "@tanstack/react-query";

import { ApiError } from "@/api/errors";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      // Client errors (auth, permission, validation) won't succeed on retry.
      retry: (failureCount, error) => !(error instanceof ApiError && error.status < 500) && failureCount < 2,
    },
  },
});
