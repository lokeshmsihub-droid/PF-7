import React from 'react';
import { ProviderType } from '../types';

interface ProviderIconProps {
  provider: ProviderType | string;
  className?: string;
  size?: number;
}

export const ProviderIcon: React.FC<ProviderIconProps> = ({ provider, className = '', size = 20 }) => {
  const normalized = provider.toLowerCase();

  if (normalized === 'github') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="currentColor"
        className={`text-[#24292F] shrink-0 ${className}`}
      >
        <path
          fillRule="evenodd"
          clipRule="evenodd"
          d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
        />
      </svg>
    );
  }

  if (normalized === 'gitlab') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="currentColor"
        className={`text-[#FC6D26] shrink-0 ${className}`}
      >
        <path d="m23.6 9.6-1.2-3.8c-.1-.4-.5-.7-.9-.7-.4 0-.8.3-.9.7l-2.4 7.4H5.8L3.4 5.8c-.1-.4-.5-.7-.9-.7-.4 0-.8.3-.9.7L.4 9.6c-.2.5 0 1.1.4 1.4l11.2 8.2 11.2-8.2c.4-.3.6-.9.4-1.4z" />
      </svg>
    );
  }

  if (normalized === 'bitbucket') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="currentColor"
        className={`text-[#0052CC] shrink-0 ${className}`}
      >
        <path d="M2.61 3.25A1.25 1.25 0 0 0 1.36 4.7l2.87 15.35c.13.72.76 1.25 1.5 1.25h12.54c.74 0 1.36-.53 1.5-1.25L22.64 4.7a1.25 1.25 0 0 0-1.25-1.45H2.61zm11.27 12.5H10.1l-1.07-5.75h5.93l-1.08 5.75z" />
      </svg>
    );
  }

  if (normalized === 'jira') {
    return (
      <svg
        width={size}
        height={size}
        viewBox="0 0 24 24"
        fill="currentColor"
        className={`text-[#0052CC] shrink-0 ${className}`}
      >
        <path d="M11.53 2c0 2.4-1.97 4.35-4.4 4.35H2.8v4.35h4.33c4.8 0 8.7-3.9 8.7-8.7H11.53zm0 7.82c0 2.4-1.97 4.35-4.4 4.35H2.8v4.35h4.33c4.8 0 8.7-3.9 8.7-8.7H11.53zm0 7.83c0 2.4-1.97 4.35-4.4 4.35H2.8V22h4.33c4.8 0 8.7-3.9 8.7-8.7H11.53z" />
      </svg>
    );
  }

  return (
    <div
      style={{ width: size, height: size }}
      className={`rounded bg-gray-100 flex items-center justify-center text-xs font-semibold text-gray-700 shrink-0 ${className}`}
    >
      {provider.charAt(0).toUpperCase()}
    </div>
  );
};
