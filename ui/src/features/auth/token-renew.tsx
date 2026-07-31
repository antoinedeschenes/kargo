import React from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import { isSafeRedirectPath, redirectToQueryParam } from '@ui/config/auth';
import { paths } from '@ui/config/paths';
import { refreshOnce } from '@ui/lib/api/token-refresh';

import { LoadingState } from '../common';

import { useAuthContext } from './context/use-auth-context';

export const TokenRenew = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { logout } = useAuthContext();

  React.useEffect(() => {
    const redirectQuery = searchParams.get(redirectToQueryParam);
    const target =
      isSafeRedirectPath(redirectQuery) && redirectQuery !== paths.tokenRenew
        ? redirectQuery
        : null;

    (async () => {
      if (await refreshOnce()) {
        if (target) {
          // target is an absolute path that already carries the deployed
          // basePath, so go through window.location to avoid react-router
          // applying its basename a second time.
          window.location.replace(window.location.origin + target);
        } else {
          navigate(paths.home);
        }
        return;
      }

      logout();
      navigate(`${paths.login}${target ? `?${redirectToQueryParam}=${target}` : ''}`);
    })();
  }, []);

  return (
    <div className='pt-40'>
      <LoadingState />
    </div>
  );
};
