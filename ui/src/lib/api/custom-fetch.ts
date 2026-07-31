/**
 * Custom fetch wrapper for the Kargo REST API.
 *
 * This mutator is used by orval-generated hooks to:
 * - Add the base URL from environment/config
 * - Include authentication headers
 * - Handle common error scenarios
 *
 * Orval generates hooks that expect a response envelope:
 * { data: T, status: number, headers: Headers }
 */

import { authTokenKey, redirectToQueryParam, refreshTokenKey } from '@ui/config/auth';
import { withBasePath } from '@ui/config/base-path';
import { paths } from '@ui/config/paths';

import { getBaseUrl } from './base-url';
import { clearTokens, getValidToken, refreshOnce } from './token-refresh';

const logout = () => {
  clearTokens();
  const { pathname } = window.location;
  // Omit redirectTo when it would point the login page back at itself.
  const redirect =
    pathname === withBasePath(paths.login)
      ? ''
      : `?${redirectToQueryParam}=${encodeURIComponent(pathname)}`;
  window.location.replace(`${withBasePath(paths.login)}${redirect}`);
};

// Reduces a request URL to just its lowercased path, so that neither a query
// string, a fragment, a dot segment, nor casing can silently defeat an
// exemption. Resolving against the current origin is what the browser does
// with these paths anyway, so the result is the path the server receives.
const normalizePath = (url: string): string => {
  try {
    return new URL(url, window.location.origin).pathname.toLowerCase();
  } catch {
    // Unparseable, so it cannot match a known path. Returning the input
    // unchanged fails closed: the caller treats it as requiring auth.
    return url;
  }
};

// The endpoints the UI calls that require no authentication. Their requests
// must not be blocked by the token expiry check, or the renewal and login
// pages could never fetch the public config they depend on. Every entry here
// must be on the server's exempt list (exemptPaths in
// pkg/server/auth_middleware.go). Each is registered both bare and with a
// trailing slash, the two forms a caller could reasonably write. Entries are
// written pre-normalized because normalizePath reads window, which is not
// available when this module is first evaluated.
const authExemptPaths = new Set(
  ['/v1beta1/system/public-server-config', '/v1beta1/login'].flatMap((path) => [path, `${path}/`])
);

/**
 * Custom fetch function used by all generated API hooks.
 *
 * Returns a response envelope { data, status, headers } as expected
 * by orval-generated hooks.
 *
 * @param url - The API endpoint path (e.g., "/v1beta1/projects")
 * @param options - The fetch options (method, body, headers, etc.)
 * @returns Promise resolving to the response envelope
 */
export const customFetch = async <T>(
  url: string,
  options?: RequestInit,
  isRetry = false
): Promise<T> => {
  const baseUrl = getBaseUrl();
  const fullUrl = `${baseUrl}${url}`;

  const requiresAuth = !authExemptPaths.has(normalizePath(url));
  const hadToken = requiresAuth && !!localStorage.getItem(authTokenKey);
  // Renews in place when the stored token has expired.
  const token = requiresAuth ? await getValidToken() : null;

  if (hadToken && !token) {
    logout();
    throw new ApiError(401, 'Unauthorized', 'Token expired');
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json'
  };

  // Preserve any explicitly passed headers (may override Content-Type for text/plain bodies)
  if (options?.headers) {
    const incoming = options.headers;
    if (incoming instanceof Headers) {
      incoming.forEach((value, key) => {
        headers[key] = value;
      });
    } else if (Array.isArray(incoming)) {
      for (const [key, value] of incoming) {
        headers[key] = value;
      }
    } else {
      Object.assign(headers, incoming);
    }
  }

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(fullUrl, {
    ...options,
    headers
  });

  if (requiresAuth && response.status === 401) {
    // The server may reject a token this client still considers live.
    if (!isRetry && localStorage.getItem(refreshTokenKey)) {
      if (await refreshOnce()) {
        return customFetch<T>(url, options, true);
      }
    }
    logout();
  }

  if (!response.ok) {
    let errorBody: unknown;
    try {
      errorBody = await response.json();
    } catch {
      errorBody = await response.text();
    }
    throw new ApiError(response.status, response.statusText, errorBody);
  }

  if (response.status === 204) {
    return { data: undefined, status: 204, headers: response.headers } as T;
  }

  const contentType = response.headers.get('content-type') ?? '';
  let data: unknown;
  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    data = await response.text();
  }

  return { data, status: response.status, headers: response.headers } as T;
};

/**
 * Custom error class for API errors.
 */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly statusText: string,
    public readonly body: unknown
  ) {
    super(`API Error: ${status} ${statusText}`);
    this.name = 'ApiError';
  }

  is(status: number): boolean {
    return this.status === status;
  }

  isClientError(): boolean {
    return this.status >= 400 && this.status < 500;
  }

  isServerError(): boolean {
    return this.status >= 500;
  }

  isUnauthorized(): boolean {
    return this.status === 401;
  }

  isForbidden(): boolean {
    return this.status === 403;
  }

  isNotFound(): boolean {
    return this.status === 404;
  }
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export type ErrorType<Error> = ApiError;

export default customFetch;
