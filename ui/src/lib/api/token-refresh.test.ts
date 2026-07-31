import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { authTokenKey, refreshTokenKey } from '../../config/auth';

// The module keeps the in-flight refresh and the cached discovery response in
// module scope, so each case loads a fresh copy of it.
type TokenRefresh = typeof import('./token-refresh');

// The tests run in Vitest's default node environment, which has no localStorage.
const fakeLocalStorage = () => {
  const store = new Map<string, string>();
  return {
    getItem: (key: string) => (store.has(key) ? (store.get(key) as string) : null),
    setItem: (key: string, value: string) => void store.set(key, String(value)),
    removeItem: (key: string) => void store.delete(key),
    clear: () => store.clear(),
    key: (index: number) => [...store.keys()][index] ?? null,
    get length() {
      return store.size;
    }
  };
};

// Builds an unsigned JWT whose exp is `offsetSeconds` from now. The refresh path
// only ever parses the payload, so a real signature is unnecessary.
const jwt = (offsetSeconds: number, extra: Record<string, unknown> = {}) => {
  const payload = { exp: Math.floor(Date.now() / 1000) + offsetSeconds, ...extra };
  return `header.${btoa(JSON.stringify(payload))}.signature`;
};

const validToken = () => jwt(3600);
const expiredToken = () => jwt(-60);

const publicConfig = {
  oidcConfig: { issuerUrl: 'https://idp.example.com/dex', clientId: 'kargo' }
};

// Stands in for the two GETs the refresh performs before the grant itself: the
// public server config and the issuer's discovery document.
const stubDiscovery = (fetchMock: ReturnType<typeof vi.fn>) => {
  fetchMock.mockImplementation((url: string) => {
    if (String(url).includes('public-server-config')) {
      return Promise.resolve(new Response(JSON.stringify(publicConfig), { status: 200 }));
    }
    return Promise.resolve(
      new Response(
        JSON.stringify({
          issuer: 'https://idp.example.com/dex',
          token_endpoint: 'https://idp.example.com/dex/token',
          jwks_uri: 'https://idp.example.com/dex/keys'
        }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    );
  });
};

const grantMock = vi.fn();
const processMock = vi.fn();
let discoveryCalls = 0;

vi.mock('oauth4webapi', () => ({
  allowInsecureRequests: Symbol('allowInsecureRequests'),
  discoveryRequest: (...args: unknown[]) => {
    discoveryCalls++;
    return (globalThis.fetch as unknown as (...a: unknown[]) => Promise<Response>)(
      'https://idp.example.com/dex/.well-known/openid-configuration',
      args
    );
  },
  processDiscoveryResponse: () => Promise.resolve({ issuer: 'https://idp.example.com/dex' }),
  refreshTokenGrantRequest: (...args: unknown[]) => grantMock(...args),
  processRefreshTokenResponse: (...args: unknown[]) => processMock(...args)
}));

describe('token-refresh', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let getValidToken: TokenRefresh['getValidToken'];
  let isTokenExpired: TokenRefresh['isTokenExpired'];
  let refreshOnce: TokenRefresh['refreshOnce'];
  let subscribeToAuthToken: TokenRefresh['subscribeToAuthToken'];

  beforeEach(async () => {
    vi.stubGlobal('localStorage', fakeLocalStorage());
    // basePath() reads window.__KARGO_BASE_PATH__ to compose the API base URL.
    vi.stubGlobal('window', { __KARGO_BASE_PATH__: '', addEventListener: () => {} });
    discoveryCalls = 0;
    grantMock.mockReset();
    processMock.mockReset();
    fetchMock = vi.fn();
    stubDiscovery(fetchMock);
    vi.stubGlobal('fetch', fetchMock);

    vi.resetModules();
    ({ getValidToken, isTokenExpired, refreshOnce, subscribeToAuthToken } =
      await import('./token-refresh'));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('isTokenExpired', () => {
    test('reports a token well inside its lifetime as live', () => {
      expect(isTokenExpired(validToken())).toBe(false);
    });

    test('reports an expired token as expired', () => {
      expect(isTokenExpired(expiredToken())).toBe(true);
    });

    test('treats a token expiring within the margin as expired', () => {
      expect(isTokenExpired(jwt(5))).toBe(true);
    });

    test('treats a token with no exp claim as live', () => {
      expect(isTokenExpired(`header.${btoa(JSON.stringify({ sub: 'a' }))}.sig`)).toBe(false);
    });

    test('throws on a token whose payload cannot be parsed', () => {
      expect(() => isTokenExpired('not-a-jwt')).toThrow();
    });
  });

  describe('getValidToken', () => {
    test('returns null when no token is stored', async () => {
      await expect(getValidToken()).resolves.toBeNull();
      expect(grantMock).not.toHaveBeenCalled();
    });

    test('returns a live token without attempting a refresh', async () => {
      const token = validToken();
      localStorage.setItem(authTokenKey, token);
      localStorage.setItem(refreshTokenKey, 'refresh-1');

      await expect(getValidToken()).resolves.toBe(token);
      expect(grantMock).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    test('returns null for an unparseable token rather than refreshing', async () => {
      localStorage.setItem(authTokenKey, 'not-a-jwt');
      localStorage.setItem(refreshTokenKey, 'refresh-1');

      await expect(getValidToken()).resolves.toBeNull();
      expect(grantMock).not.toHaveBeenCalled();
    });

    test('refreshes an expired token and stores both new tokens', async () => {
      const fresh = validToken();
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockResolvedValue({ id_token: fresh, refresh_token: 'refresh-2' });

      await expect(getValidToken()).resolves.toBe(fresh);
      expect(localStorage.getItem(authTokenKey)).toBe(fresh);
      expect(localStorage.getItem(refreshTokenKey)).toBe('refresh-2');
    });

    test('keeps the existing refresh token when the grant does not rotate it', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockResolvedValue({ id_token: validToken() });

      await getValidToken();

      expect(localStorage.getItem(refreshTokenKey)).toBe('refresh-1');
    });

    test('does not attempt a refresh for an admin session, which has no refresh token', async () => {
      localStorage.setItem(authTokenKey, expiredToken());

      await expect(getValidToken()).resolves.toBeNull();
      expect(grantMock).not.toHaveBeenCalled();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    test('resolves to null when OIDC is not configured', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      fetchMock.mockResolvedValue(new Response(JSON.stringify({}), { status: 200 }));

      await expect(getValidToken()).resolves.toBeNull();
      expect(grantMock).not.toHaveBeenCalled();
    });

    test('resolves to null when the grant returns no id_token', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockResolvedValue({ refresh_token: 'refresh-2' });

      await expect(getValidToken()).resolves.toBeNull();
    });
  });

  describe('refreshOnce sharing', () => {
    test('uses one grant request for concurrent callers', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');

      let release: (v: unknown) => void = () => {};
      const gate = new Promise((resolve) => {
        release = resolve;
      });
      const fresh = validToken();
      processMock.mockImplementation(async () => {
        await gate;
        return { id_token: fresh, refresh_token: 'refresh-2' };
      });

      const results = Promise.all([getValidToken(), getValidToken(), getValidToken()]);
      release(undefined);

      expect(await results).toEqual([fresh, fresh, fresh]);
      expect(grantMock).toHaveBeenCalledTimes(1);
      expect(discoveryCalls).toBe(1);
    });

    test('allows a later refresh after the in-flight one settles', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockResolvedValue({ id_token: validToken() });

      await refreshOnce();
      localStorage.setItem(authTokenKey, expiredToken());
      await refreshOnce();

      expect(grantMock).toHaveBeenCalledTimes(2);
    });

    test('reuses cached discovery across separate refreshes', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockResolvedValue({ id_token: validToken() });

      await refreshOnce();
      await refreshOnce();

      expect(discoveryCalls).toBe(1);
    });

    test('clears the in-flight slot when the refresh rejects, so a retry is possible', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockRejectedValue(new Error('boom'));

      await expect(refreshOnce()).resolves.toBeNull();

      processMock.mockResolvedValue({ id_token: validToken() });
      await expect(refreshOnce()).resolves.not.toBeNull();
    });
  });

  describe('multi-tab refresh token rotation', () => {
    test('adopts a token another tab stored when our own grant is rejected', async () => {
      const stale = expiredToken();
      const winner = validToken();
      localStorage.setItem(authTokenKey, stale);
      localStorage.setItem(refreshTokenKey, 'refresh-1');

      // The other tab claimed the rotated refresh token first, so ours is
      // rejected, but it stored a good token before we gave up.
      processMock.mockImplementation(async () => {
        localStorage.setItem(authTokenKey, winner);
        throw new Error('refresh token claimed twice');
      });

      await expect(refreshOnce()).resolves.toBe(winner);
    });

    test('does not adopt an expired token from localStorage', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockImplementation(async () => {
        localStorage.setItem(authTokenKey, expiredToken());
        throw new Error('refresh token claimed twice');
      });

      await expect(refreshOnce()).resolves.toBeNull();
    });

    test("does not mistake the unchanged stale token for another tab's work", async () => {
      const stale = expiredToken();
      localStorage.setItem(authTokenKey, stale);
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockRejectedValue(new Error('nope'));

      await expect(refreshOnce()).resolves.toBeNull();
    });
  });

  describe('subscribeToAuthToken', () => {
    test('notifies subscribers when a refresh stores a new token', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      const fresh = validToken();
      processMock.mockResolvedValue({ id_token: fresh });

      const seen: (string | null)[] = [];
      subscribeToAuthToken((t) => seen.push(t));

      await refreshOnce();

      expect(seen).toEqual([fresh]);
    });

    test('stops notifying after unsubscribe', async () => {
      localStorage.setItem(authTokenKey, expiredToken());
      localStorage.setItem(refreshTokenKey, 'refresh-1');
      processMock.mockResolvedValue({ id_token: validToken() });

      const seen: (string | null)[] = [];
      const unsubscribe = subscribeToAuthToken((t) => seen.push(t));
      unsubscribe();

      await refreshOnce();

      expect(seen).toEqual([]);
    });
  });
});
