import { basePath } from '@ui/config/base-path';

export const getBaseUrl = (): string => {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }
  return basePath();
};
