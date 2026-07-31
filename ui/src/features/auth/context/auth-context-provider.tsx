import React, { PropsWithChildren, useMemo } from 'react';

import { authTokenKey } from '@ui/config/auth';
import { clearTokens, storeTokens, subscribeToAuthToken } from '@ui/lib/api/token-refresh';

import { extractInfoFromJWT, JWTInfo } from '../jwt-utils';

import { AuthContext, AuthContextType } from './auth-context';

export const AuthContextProvider = ({ children }: PropsWithChildren) => {
  const [token, setToken] = React.useState(localStorage.getItem(authTokenKey));

  // Tokens also change from a refresh in the fetch layer or in another tab.
  React.useEffect(() => subscribeToAuthToken(setToken), []);

  const login = React.useCallback((token: string, refreshToken?: string) => {
    storeTokens(token, refreshToken);
  }, []);

  const logout = React.useCallback(clearTokens, []);

  const jwtInfo: JWTInfo | null = useMemo(() => {
    if (token) {
      try {
        return extractInfoFromJWT(token);
      } catch {
        // if "something" is off with token (assume isLoggedIn is true because it just check whether token is present or not ie. not validity of token)
        // authHandler interceptor will find before any API call and redirect to login page anyways
        // consumer will decide whats the best UX at that point
        return null;
      }
    }

    return null;
  }, [token]);

  const ctx: AuthContextType = React.useMemo(
    () => ({
      isLoggedIn: !!token,
      login,
      logout,
      JWTInfo: jwtInfo
    }),
    [login, logout, token, jwtInfo]
  );

  return <AuthContext.Provider value={ctx}>{children}</AuthContext.Provider>;
};
