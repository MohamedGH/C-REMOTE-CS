/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect } from 'react';
import { CSourceView } from './components/CSourceView';
import { CommandConsoleView } from './components/CommandConsoleView';
import { ErrorBanner } from './components/ErrorBanner';
import { SandboxFileView } from './components/SandboxFileView';
import { SecurityAuditView } from './components/SecurityAuditView';
import { TestSuiteView } from './components/TestSuiteView';
import { TopBar } from './components/TopBar';
import { RouteId, selectCurrentRouteMetadata } from './core/routeManager';
import { ActionType, AppAction, AppState, useAppState } from './core/stateManager';

const renderActiveRouteView = (
  state: AppState,
  dispatch: (action: AppAction) => void
) => {
  switch (state.route.currentRoute) {
    case RouteId.Workspace:
      return <CommandConsoleView state={state} dispatch={dispatch} />;
    case RouteId.FileSandbox:
      return <SandboxFileView state={state} dispatch={dispatch} />;
    case RouteId.CArchitecture:
      return <CSourceView state={state} dispatch={dispatch} />;
    case RouteId.SecurityAudit:
      return <SecurityAuditView state={state} dispatch={dispatch} />;
    case RouteId.TestRunner:
      return <TestSuiteView />;
  }
};

export default function App() {
  const [state, dispatch] = useAppState();
  const routeMeta = selectCurrentRouteMetadata(state.route);

  useEffect(() => {
    const syncHash = () => {
      if (window.location.hash) {
        dispatch({
          type: ActionType.NavigateHash,
          rawHash: window.location.hash,
        });
      }
    };
    syncHash();
    window.addEventListener('hashchange', syncHash);
    return () => window.removeEventListener('hashchange', syncHash);
  }, [dispatch]);

  return (
    <div className="min-h-screen flex flex-col bg-[#090d16] text-slate-100 pb-20 md:pb-8">
      <TopBar state={state} dispatch={dispatch} />
      <ErrorBanner state={state} dispatch={dispatch} />

      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-6 sm:pt-8">
        {renderActiveRouteView(state, dispatch)}
      </main>

      <footer className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-12 pb-4 border-t border-slate-900 mt-12 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs text-slate-500">
        <span>
          SecAdminC — Defensive C11 &amp; OpenSSL 3.x Remote Administration
          Architecture
        </span>
        <span>Current View: {routeMeta.label}</span>
      </footer>
    </div>
  );
}

