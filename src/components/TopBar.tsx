import React from 'react';
import {
  FileCode2,
  FolderLock,
  ShieldAlert,
  Terminal,
  FlaskConical,
} from 'lucide-react';
import { ROUTE_REGISTRY, RouteId } from '../core/routeManager';
import { ActionType, AppAction, AppState } from '../core/stateManager';

interface NavigationProps {
  readonly state: AppState;
  readonly dispatch: (action: AppAction) => void;
}

const getMobileRouteIcon = (routeId: RouteId) => {
  switch (routeId) {
    case RouteId.Workspace:
      return <Terminal className="w-5 h-5" />;
    case RouteId.FileSandbox:
      return <FolderLock className="w-5 h-5" />;
    case RouteId.CArchitecture:
      return <FileCode2 className="w-5 h-5" />;
    case RouteId.SecurityAudit:
      return <ShieldAlert className="w-5 h-5" />;
    case RouteId.TestRunner:
      return <FlaskConical className="w-5 h-5" />;
  }
};

export const TopBar: React.FC<NavigationProps> = ({ state, dispatch }) => {
  const { currentRoute } = state.route;
  const { connected } = state.tlsSession;

  const handleNavigate = (routeId: RouteId, hash: string) => {
    if (typeof window !== 'undefined' && window.location.hash !== hash) {
      window.history.pushState(null, '', hash);
    }
    dispatch({ type: ActionType.Navigate, routeId });
  };

  return (
    <>
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="sticky top-0 z-30 h-14 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80 px-4 sm:px-6 lg:px-8 flex items-center justify-between">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#/workspace"
          onClick={(e) => {
            e.preventDefault();
            handleNavigate(RouteId.Workspace, '#/workspace');
          }}
          className="font-display text-lg font-semibold tracking-tight text-slate-100 whitespace-nowrap focus-visible:outline-2 focus-visible:outline-emerald-400"
        >
          SecAdminC
        </a>

        {/* Zone 2: 5 clean text navigation links */}
        <nav
          aria-label="Primary Navigation"
          className="hidden md:flex items-center gap-6 text-sm font-medium"
        >
          {ROUTE_REGISTRY.map((route) => {
            const isActive = currentRoute === route.id;
            return (
              <a
                key={route.id}
                href={route.hash}
                onClick={(e) => {
                  e.preventDefault();
                  handleNavigate(route.id, route.hash);
                }}
                className={`py-1 whitespace-nowrap shrink-0 transition-colors border-b-2 ${
                  isActive
                    ? 'border-emerald-400 text-slate-100 font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                {route.label}
              </a>
            );
          })}
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => dispatch({ type: ActionType.ToggleTlsConnection })}
            className={`min-h-[40px] px-4 py-2 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              connected
                ? 'bg-emerald-500 text-slate-950 hover:bg-emerald-400'
                : 'bg-amber-500 text-slate-950 hover:bg-amber-400'
            }`}
          >
            {connected ? 'mTLS 1.3 Active' : 'Reconnect mTLS 1.3'}
          </button>
        </div>
      </header>

      {/* Mobile-First Fixed Bottom Tab Bar (Thumb Zone) */}
      <nav
        aria-label="Mobile Bottom Navigation"
        className="md:hidden fixed bottom-0 left-0 right-0 z-40 h-16 bg-slate-950/95 backdrop-blur-md border-t border-slate-800 grid grid-cols-5 items-center px-1"
      >
        {ROUTE_REGISTRY.map((route) => {
          const isActive = currentRoute === route.id;
          return (
            <button
              key={route.id}
              type="button"
              onClick={() => handleNavigate(route.id, route.hash)}
              className={`min-h-[48px] min-w-[44px] flex flex-col items-center justify-center rounded-lg transition-colors cursor-pointer ${
                isActive
                  ? 'text-emerald-400 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {getMobileRouteIcon(route.id)}
              <span className="text-[11px] leading-tight mt-1 whitespace-nowrap truncate max-w-[68px]">
                {route.shortLabel}
              </span>
            </button>
          );
        })}
      </nav>
    </>
  );
};
