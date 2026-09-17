import React from 'react';
import { CheckCircle2, AlertCircle, AlertTriangle, Info, X } from 'lucide-react';
import { ToastNotification } from '../types';

interface ToastContainerProps {
  toasts: ToastNotification[];
  onDismiss: (id: string) => void;
}

export const ToastContainer: React.FC<ToastContainerProps> = ({ toasts, onDismiss }) => {
  if (toasts.length === 0) return null;

  return (
    <div
      id="toast-container"
      className="fixed top-4 right-4 z-50 flex flex-col space-y-2 max-w-sm w-full pointer-events-none"
    >
      {toasts.map((toast) => {
        let icon = <CheckCircle2 className="w-4 h-4 text-[#3FA76C] shrink-0" />;
        let borderColor = 'border-[#EAF7EF]';
        let bgColor = 'bg-[#FFFFFF]';

        if (toast.type === 'error') {
          icon = <AlertCircle className="w-4 h-4 text-[#D96B6B] shrink-0" />;
          borderColor = 'border-[#FDEEEE]';
        } else if (toast.type === 'warning') {
          icon = <AlertTriangle className="w-4 h-4 text-[#C99532] shrink-0" />;
          borderColor = 'border-[#FFF7E6]';
        } else if (toast.type === 'info') {
          icon = <Info className="w-4 h-4 text-[#5876D8] shrink-0" />;
          borderColor = 'border-[#EEF2FF]';
        }

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto flex items-start gap-2.5 p-3 rounded-lg border shadow-sm ${borderColor} ${bgColor} transition-all duration-200`}
            role="alert"
          >
            {icon}
            <div className="flex-1 min-w-0">
              {toast.title && (
                <p className="text-[12px] font-semibold text-[#24262B] leading-tight">
                  {toast.title}
                </p>
              )}
              <p className="text-[12px] text-[#666A73] leading-snug">
                {toast.message}
              </p>
            </div>
            <button
              onClick={() => onDismiss(toast.id)}
              className="text-[#8B8F98] hover:text-[#24262B] p-0.5 rounded transition-colors"
              aria-label="Dismiss toast"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
