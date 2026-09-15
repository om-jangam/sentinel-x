/** RFC 9457 problem document returned by every Sentinel-X API error. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  detail: string;
  instance?: string;
  correlation_id?: string | null;
  errors?: { loc?: (string | number)[]; msg: string; type?: string }[];
}

export class ApiError extends Error {
  readonly problem: Problem;

  constructor(problem: Problem) {
    super(problem.detail || problem.title);
    this.name = "ApiError";
    this.problem = problem;
  }

  get status(): number {
    return this.problem.status;
  }

  /** Human-readable summary including field-level messages. */
  describe(): string {
    const fields = (this.problem.errors ?? []).map((e) => e.msg).filter(Boolean);
    return fields.length ? `${this.message}: ${fields.join("; ")}` : this.message;
  }
}

function isProblem(value: unknown): value is Problem {
  return typeof value === "object" && value !== null && "status" in value && "title" in value;
}

export function toApiError(error: unknown, response: Response): ApiError {
  if (isProblem(error)) return new ApiError(error);
  return new ApiError({
    type: "about:blank",
    title: response.statusText || "Request failed",
    status: response.status,
    detail: `Request failed with status ${response.status}`,
  });
}

interface FetchResult<T> {
  data?: T;
  error?: unknown;
  response: Response;
}

/** Returns the data of a successful openapi-fetch call, throwing an ApiError otherwise. */
export function unwrap<T>(result: FetchResult<T>): T {
  if (result.error !== undefined || !result.response.ok) {
    throw toApiError(result.error, result.response);
  }
  return result.data as T;
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.describe();
  if (error instanceof Error) return error.message;
  return "Something went wrong";
}
