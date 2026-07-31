import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { authTokenKey, refreshTokenKey } from '../../config/auth';

import { customFetch } from './custom-fetch';
import { clearTokens, getValidToken, refreshOnce } from './token-refresh';

vi.mock('./token-refresh', () => ({
  clearTokens: vi.fn(),
  getValidToken: vi.fn(),
  refreshOnce: vi.fn()
}));

const getValidTokenMock = vi.mocked(getValidToken);
const refreshOnceMock = vi.mocked(refreshOnce);
const clearTokensMock = vi.mocked(clearTokens);

// The tests run in Vitest's default node environment, which has neither
// localStorage nor window.
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

const unauthorizedResponse = () =>
  new Response('{"error":"invalid token"}', {
    status: 401,
    headers: { 'content-type': 'application/json' }
  });

describe('customFetch', () => {
  let fetchMock: ReturnType<typeof vi.fn>;
  let replaceMock: ReturnType<typeof vi.fn>;

  const stubWindow = (pathname: string) => {
    replaceMock = vi.fn();
    vi.stubGlobal('window', {
      __KARGO_BASE_PATH__: '',
      location: { origin: 'http://localhost:3333', pathname, replace: replaceMock }
    });
  };

  beforeEach(() => {
    vi.stubGlobal('localStorage', fakeLocalStorage());
    fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    stubWindow('/');
    getValidTokenMock.mockReset().mockResolvedValue(null);
    refreshOnceMock.mockReset().mockResolvedValue(null);
    clearTokensMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test('attaches the renewed token to authenticated requests', async () => {
    localStorage.setItem(authTokenKey, 'stored-token');
    getValidTokenMock.mockResolvedValue('fresh-token');

    await customFetch('/v1beta1/projects');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1].headers).toMatchObject({
      Authorization: 'Bearer fresh-token'
    });
    expect(replaceMock).not.toHaveBeenCalled();
  });

  test('ends the session when a stored token cannot be renewed', async () => {
    localStorage.setItem(authTokenKey, 'stored-token');
    getValidTokenMock.mockResolvedValue(null);

    await expect(customFetch('/v1beta1/projects')).rejects.toMatchObject({ status: 401 });
    expect(clearTokensMock).toHaveBeenCalled();
    expect(replaceMock).toHaveBeenCalledWith('/login?redirectTo=%2F');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('does not renew or attach a token for exempt endpoints', async () => {
    localStorage.setItem(authTokenKey, 'stored-token');

    await customFetch('/v1beta1/system/public-server-config');

    expect(getValidTokenMock).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1].headers).not.toHaveProperty('Authorization');
    expect(replaceMock).not.toHaveBeenCalled();
  });

  test.for([
    ['a query string', '/v1beta1/system/public-server-config?ts=1'],
    ['a fragment', '/v1beta1/system/public-server-config#section'],
    ['a fragment ahead of a query string', '/v1beta1/system/public-server-config#a?ts=1'],
    ['a trailing slash', '/v1beta1/system/public-server-config/'],
    ['upper case', '/V1BETA1/SYSTEM/PUBLIC-SERVER-CONFIG'],
    ['a trailing slash and a query string', '/v1beta1/system/public-server-config/?ts=1'],
    ['dot segments', '/v1beta1/projects/../system/./public-server-config']
  ])('matches an exempt endpoint written with %s', async ([, url]) => {
    localStorage.setItem(authTokenKey, 'stored-token');

    await customFetch(url);

    expect(getValidTokenMock).not.toHaveBeenCalled();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1].headers).not.toHaveProperty('Authorization');
  });

  test('does not treat a non-exempt endpoint as exempt because of a shared prefix', async () => {
    localStorage.setItem(authTokenKey, 'stored-token');
    getValidTokenMock.mockResolvedValue('fresh-token');

    await customFetch('/v1beta1/login/extra');

    expect(getValidTokenMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][1].headers).toMatchObject({
      Authorization: 'Bearer fresh-token'
    });
  });

  test('does not end the session on a 401 from an exempt endpoint', async () => {
    localStorage.setItem(authTokenKey, 'stored-token');
    localStorage.setItem(refreshTokenKey, 'refresh-1');
    fetchMock.mockImplementation(() => Promise.resolve(unauthorizedResponse()));

    await expect(customFetch('/v1beta1/login')).rejects.toMatchObject({ status: 401 });
    expect(refreshOnceMock).not.toHaveBeenCalled();
    expect(clearTokensMock).not.toHaveBeenCalled();
    expect(replaceMock).not.toHaveBeenCalled();
  });

  test('renews and retries once when the server rejects the token', async () => {
    localStorage.setItem(authTokenKey, 'stored-token');
    localStorage.setItem(refreshTokenKey, 'refresh-1');
    getValidTokenMock.mockResolvedValue('stale-token');
    refreshOnceMock.mockResolvedValue('fresh-token');
    fetchMock
      .mockResolvedValueOnce(unauthorizedResponse())
      .mockResolvedValueOnce(new Response('{}', { status: 200 }));

    await customFetch('/v1beta1/projects');

    expect(refreshOnceMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(clearTokensMock).not.toHaveBeenCalled();
    expect(replaceMock).not.toHaveBeenCalled();
  });

  test('ends the session when a 401 persists after renewal', async () => {
    localStorage.setItem(authTokenKey, 'stored-token');
    localStorage.setItem(refreshTokenKey, 'refresh-1');
    getValidTokenMock.mockResolvedValue('stale-token');
    refreshOnceMock.mockResolvedValue('fresh-token');
    fetchMock.mockImplementation(() => Promise.resolve(unauthorizedResponse()));

    await expect(customFetch('/v1beta1/projects')).rejects.toMatchObject({ status: 401 });
    expect(refreshOnceMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(clearTokensMock).toHaveBeenCalled();
    expect(replaceMock).toHaveBeenCalledWith('/login?redirectTo=%2F');
  });

  test('ends the session on a 401 when no refresh token exists', async () => {
    localStorage.setItem(authTokenKey, 'stored-token');
    getValidTokenMock.mockResolvedValue('admin-token');
    fetchMock.mockImplementation(() => Promise.resolve(unauthorizedResponse()));

    await expect(customFetch('/v1beta1/projects')).rejects.toMatchObject({ status: 401 });
    expect(refreshOnceMock).not.toHaveBeenCalled();
    expect(clearTokensMock).toHaveBeenCalled();
    expect(replaceMock).toHaveBeenCalledWith('/login?redirectTo=%2F');
  });

  test('omits redirectTo when logging out on the login page', async () => {
    stubWindow('/login');
    localStorage.setItem(authTokenKey, 'stored-token');
    getValidTokenMock.mockResolvedValue(null);

    await expect(customFetch('/v1beta1/projects')).rejects.toMatchObject({ status: 401 });
    expect(replaceMock).toHaveBeenCalledWith('/login');
  });
});
