import React from 'react';
import { AlertTriangle, ShieldAlert, X } from 'lucide-react';
import {
  ErrorSeverity,
  selectActiveBannerError,
} from '../core/errorManager';
import { RouteId } from '../core/routeManager';
import { ActionType, AppAction, AppState } from '../core/stateManager';

interface ErrorBannerProps {
  readonly state: AppState;
  readonly dispatch: (action: AppAction) => void;
}

export const ErrorBanner: React.FC<ErrorBannerProps> = ({
  state,
  dispatch,
}) => {
  const activeError = selectActiveBannerError(state.errorManager);
  if (!activeError) {
    return null;
  }

  const isSecurityBlock =
    activeError.severity === ErrorSeverity.SecurityBlock ||
    activeError.severity === ErrorSeverity.Critical;

  return (
    <div
      role="alert"
      className={`border-b px-4 sm:px-6 lg:px-8 py-3 transition-opacity ${
        isSecurityBlock
          ? 'bg-red-950/70 border-red-800/80 text-red-100'
          : 'bg-amber-950/70 border-amber-800/80 text-amber-100'
      }`}
    >
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-start gap-3">
          {isSecurityBlock ? (
            <ShieldAlert className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          )}
          <div className="space-y-1 text-xs sm:text-sm">
            <div className="flex flex-wrap items-center gap-2 font-semibold">
              <span>{activeError.title}</span>
              <span aria-hidden="true">·</span>
              <span className="font-mono text-xs opacity-90">
                {activeError.code}
              </span>
              {activeError.cweReference && (
                <>
                  <span aria-hidden="true">·</span>
                  <span className="font-mono text-xs opacity-90">
                    {activeError.cweReference}
                  </span>
                </>
              )}
            </div>
            <p className="text-slate-200 leading-relaxed">
              {activeError.message}
            </p>
            <p className="text-xs text-slate-300">
              Remediation: {activeError.remediation}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-center shrink-0">
          <button
            type="button"
            onClick={() =>
              dispatch({
                type: ActionType.Navigate,
                routeId: RouteId.SecurityAudit,
              })
            }
            className="min-h-[40px] px-3 py-1.5 text-xs font-medium underline underline-offset-4 hover:opacity-80 whitespace-nowrap cursor-pointer"
          >
            Inspect Audit Log
          </button>
          <button
            type="button"
            aria-label="Dismiss error alert"
            onClick={() =>
              dispatch({
                type: ActionType.DismissError,
                errorId: activeError.id,
              })
            }
            className="min-h-[44px] min-w-[44px] flex items-center justify-center rounded-lg hover:bg-white/10 transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
