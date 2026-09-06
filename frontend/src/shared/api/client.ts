const DEFAULT_API_BASE_URL = 'http://localhost:8000/api/v1'
const apiBaseUrl = (import.meta.env.VITE_API_BASE_URL || DEFAULT_API_BASE_URL).replace(
  /\/+$/,
  '',
)

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function apiUrl(path: string): string {
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('://')) {
    throw new Error('API path must be application-relative')
  }
  return `${apiBaseUrl}${path}`
}

function safeErrorMessage(body: unknown, fallback: string): string {
  if (
    typeof body === 'object' &&
    body !== null &&
    'detail' in body &&
    typeof body.detail === 'string'
  ) {
    return body.detail
  }
  if (
    typeof body === 'object' &&
    body !== null &&
    'detail' in body &&
    typeof body.detail === 'object' &&
    body.detail !== null &&
    'message' in body.detail &&
    typeof body.detail.message === 'string'
  ) {
    return body.detail.message
  }
  return fallback
}

async function parseJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') ?? ''
  if (!contentType.toLowerCase().includes('application/json')) {
    return undefined
  }
  try {
    return await response.json()
  } catch {
    return undefined
  }
}

export async function apiRequest(
  path: string,
  init: RequestInit = {},
): Promise<unknown> {
  const headers = new Headers(init.headers)
  if (
    init.body !== undefined &&
    !(init.body instanceof FormData) &&
    !headers.has('Content-Type')
  ) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(apiUrl(path), {
    ...init,
    headers,
    credentials: 'include',
  })

  if (response.status === 204) {
    return undefined
  }

  const body = await parseJson(response)
  if (!response.ok) {
    throw new ApiError(
      response.status,
      safeErrorMessage(body, response.statusText || 'API request failed'),
    )
  }
  return body
}
