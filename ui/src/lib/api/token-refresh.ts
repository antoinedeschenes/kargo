// OIDC token refresh, shared between concurrent callers.

import {
  allowInsecureRequests,
  AuthorizationServer,
  Client,
  discoveryRequest,
  processDiscoveryResponse,
  processRefreshTokenResponse,
  refreshTokenGrantRequest
} from 'oauth4webapi';

import { authTokenKey, refreshTokenKey } from '@ui/config/auth';
import { oidcClientAuth, shouldAllowIdpHttpRequest } from '@ui/features/auth/oidc-utils';
import { parseJwtPayload } from '@ui/utils/jwt-payload';

import { getBaseUrl } from './base-url';

// Treat a token this close to expiring as already expired.
const expiryMarginSeconds = 10;

type PublicConfig = {
  oidcConfig?: { issuerUrl?: string; clientId?: string };
};

// Throws if the token cannot be parsed.
export const isTokenExpired = (token: string): boolean => {
  const payload = parseJwtPayload<{ exp?: number }>(token);
  if (typeof payload.exp !== 'number') {
    return false;
  }
  return Date.now() >= (payload.exp - expiryMarginSeconds) * 1000;
};

const subscribers = new Set<(token: string | null) => void>();

const notifySubscribers = (token: string | null) => {
  for (const fn of subscribers) {
    fn(token);
  }
};

let listeningForOtherTabs = false;

// Returns an unsubscribe function.
export const subscribeToAuthToken = (fn: (token: string | null) => void): (() => void) => {
  if (!listeningForOtherTabs) {
    listeningForOtherTabs = true;
    window.addEventListener('storage', (event) => {
      if (event.key === authTokenKey) {
        notifySubscribers(event.newValue);
      }
    });
  }

  subscribers.add(fn);
  return () => subscribers.delete(fn);
};

export const storeTokens = (token: string, refreshToken?: string) => {
  localStorage.setItem(authTokenKey, token);
  if (refreshToken) {
    localStorage.setItem(refreshTokenKey, refreshToken);
  }
  notifySubscribers(token);
};

export const clearTokens = () => {
  localStorage.removeItem(authTokenKey);
  localStorage.removeItem(refreshTokenKey);
  notifySubscribers(null);
};

// Cached for the page's lifetime; the issuer's metadata does not change.
let authServerPromise: Promise<{ as: AuthorizationServer; client: Client } | null> | null = null;

const loadAuthServer = async (): Promise<{ as: AuthorizationServer; client: Client } | null> => {
  const response = await fetch(`${getBaseUrl()}/v1beta1/system/public-server-config`);
  if (!response.ok) {
    throw new Error(`could not load public server config: ${response.status}`);
  }

  const config: PublicConfig = await response.json();
  const issuerUrl = config.oidcConfig?.issuerUrl;
  const clientId = config.oidcConfig?.clientId;
  if (!issuerUrl || !clientId) {
    return null;
  }

  const issuer = new URL(issuerUrl);
  const discovery = await discoveryRequest(issuer, {
    [allowInsecureRequests]: shouldAllowIdpHttpRequest()
  });
  const as = await processDiscoveryResponse(issuer, discovery);

  return {
    as,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    client: { client_id: clientId, token_endpoint_auth_method: 'none' as any }
  };
};

const getAuthServer = () => {
  authServerPromise ??= loadAuthServer().catch((err) => {
    authServerPromise = null;
    throw err;
  });
  return authServerPromise;
};

// A live token another tab stored while our refresh was in flight. Under refresh
// token rotation, one of two racing tabs has its grant rejected.
const tokenFromAnotherTab = (staleToken: string | null): string | null => {
  const current = localStorage.getItem(authTokenKey);
  if (!current || current === staleToken) {
    return null;
  }
  try {
    return isTokenExpired(current) ? null : current;
  } catch (_) {
    return null;
  }
};

const doRefresh = async (staleToken: string | null): Promise<string | null> => {
  const refreshToken = localStorage.getItem(refreshTokenKey);
  // Admin login issues no refresh token.
  if (!refreshToken) {
    return null;
  }

  try {
    const server = await getAuthServer();
    if (!server) {
      return null;
    }

    const response = await refreshTokenGrantRequest(
      server.as,
      server.client,
      oidcClientAuth,
      refreshToken,
      {
        [allowInsecureRequests]: shouldAllowIdpHttpRequest(),
        additionalParameters: [['client_id', server.client.client_id]]
      }
    );
    const result = await processRefreshTokenResponse(server.as, server.client, response);

    if (!result.id_token) {
      return tokenFromAnotherTab(staleToken);
    }

    storeTokens(result.id_token, result.refresh_token);
    return result.id_token;
  } catch (_) {
    return tokenFromAnotherTab(staleToken);
  }
};

let inflight: Promise<string | null> | null = null;

// Resolves to the new token, or null when renewal is not possible.
export const refreshOnce = (): Promise<string | null> => {
  inflight ??= doRefresh(localStorage.getItem(authTokenKey)).finally(() => {
    inflight = null;
  });
  return inflight;
};

// Refreshes first if the stored token has expired. Resolves to null when there
// is no token or renewal is not possible.
export const getValidToken = async (): Promise<string | null> => {
  const token = localStorage.getItem(authTokenKey);
  if (!token) {
    return null;
  }

  let expired: boolean;
  try {
    expired = isTokenExpired(token);
  } catch (_) {
    return null;
  }

  if (!expired) {
    return token;
  }

  return refreshOnce();
};
