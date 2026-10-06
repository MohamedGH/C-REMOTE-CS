/**
 * Pure Functional Centralized State Manager
 * Combines RouteManager, ErrorManager, TlsSession, SandboxFs, and CommandConsole
 * into a single immutable state tree with a pure reducer and React 19 hook bindings.
 */

import { useSyncExternalStore } from 'react';
import {
  CommandLogEntry,
  createInitialTlsSession,
  dispatchAllowlistedCommand,
  TlsSessionState,
} from './commandEngine';
import {
  clearAllErrors,
  createInitialErrorState,
  dismissErrorById,
  ErrorManagerState,
  ErrorSeverity,
  recordError,
} from './errorManager';
import { isOk } from './fp';
import {
  createInitialRouteState,
  navigateBack,
  navigateToRoute,
  parseRouteFromHash,
  RouteId,
  RouteManagerState,
} from './routeManager';
import {
  changeSandboxDirectory,
  createInitialSandboxFsState,
  createSandboxAuditNote,
  readSandboxFile,
  SandboxFsState,
} from './sandboxFs';

export interface AppState {
  readonly route: RouteManagerState;
  readonly errorManager: ErrorManagerState;
  readonly tlsSession: TlsSessionState;
  readonly sandboxFs: SandboxFsState;
  readonly commandHistory: ReadonlyArray<CommandLogEntry>;
  readonly errorSeverityFilter: ErrorSeverity | 'ALL';
}

export enum ActionType {
  Navigate = 'ROUTE/NAVIGATE',
  NavigateHash = 'ROUTE/NAVIGATE_HASH',
  NavigateBack = 'ROUTE/NAVIGATE_BACK',
  SelectCSourceFile = 'CSOURCE/SELECT_FILE',
  ToggleTlsConnection = 'TLS/TOGGLE_CONNECTION',
  ExecuteCommand = 'CONSOLE/EXECUTE_COMMAND',
  ClearConsole = 'CONSOLE/CLEAR_HISTORY',
  ChangeDirectory = 'FS/CHANGE_DIRECTORY',
  SelectFile = 'FS/SELECT_FILE',
  SetFsSearchQuery = 'FS/SET_SEARCH_QUERY',
  CreateAuditNote = 'FS/CREATE_AUDIT_NOTE',
  DismissError = 'ERROR/DISMISS_BY_ID',
  ClearErrors = 'ERROR/CLEAR_ALL',
  SetErrorFilter = 'ERROR/SET_SEVERITY_FILTER',
}

export type AppAction =
  | { readonly type: ActionType.Navigate; readonly routeId: RouteId }
  | { readonly type: ActionType.NavigateHash; readonly rawHash: string }
  | { readonly type: ActionType.NavigateBack }
  | { readonly type: ActionType.SelectCSourceFile; readonly filename: string }
  | { readonly type: ActionType.ToggleTlsConnection }
  | { readonly type: ActionType.ExecuteCommand; readonly rawCommand: string }
  | { readonly type: ActionType.ClearConsole }
  | { readonly type: ActionType.ChangeDirectory; readonly targetPath: string }
  | { readonly type: ActionType.SelectFile; readonly targetPath: string }
  | { readonly type: ActionType.SetFsSearchQuery; readonly query: string }
  | {
      readonly type: ActionType.CreateAuditNote;
      readonly filename: string;
      readonly content: string;
    }
  | { readonly type: ActionType.DismissError; readonly errorId: string }
  | { readonly type: ActionType.ClearErrors }
  | {
      readonly type: ActionType.SetErrorFilter;
      readonly filter: ErrorSeverity | 'ALL';
    };

export const createInitialAppState = (): AppState => {
  const initialSession = createInitialTlsSession();
  const initialFs = createInitialSandboxFsState();
  const bootCmd = dispatchAllowlistedCommand(
    'sysinfo',
    initialFs,
    initialSession,
    '2026-10-06T00:50:00Z'
  );

  const initialHistory: ReadonlyArray<CommandLogEntry> = isOk(bootCmd)
    ? Object.freeze([bootCmd.value.entry])
    : Object.freeze([]);

  return Object.freeze({
    route: createInitialRouteState(RouteId.Workspace),
    errorManager: createInitialErrorState(),
    tlsSession: isOk(bootCmd)
      ? bootCmd.value.nextSessionState
      : initialSession,
    sandboxFs: initialFs,
    commandHistory: initialHistory,
    errorSeverityFilter: 'ALL',
  });
};

/**
 * Pure Root Reducer: (AppState, AppAction) => AppState
 * Zero side effects; all state transitions return newly frozen state objects.
 */
export const appReducer = (state: AppState, action: AppAction): AppState => {
  switch (action.type) {
    case ActionType.Navigate:
      return Object.freeze({
        ...state,
        route: navigateToRoute(state.route, action.routeId),
      });

    case ActionType.NavigateHash: {
      const parsed = parseRouteFromHash(action.rawHash);
      if (isOk(parsed)) {
        return Object.freeze({
          ...state,
          route: navigateToRoute(state.route, parsed.value),
        });
      }
      return Object.freeze({
        ...state,
        route: navigateToRoute(state.route, RouteId.Workspace),
        errorManager: recordError(state.errorManager, parsed.error),
      });
    }

    case ActionType.NavigateBack:
      return Object.freeze({
        ...state,
        route: navigateBack(state.route),
      });

    case ActionType.SelectCSourceFile:
      return Object.freeze({
        ...state,
        route: Object.freeze({
          ...state.route,
          activeCFileTab: action.filename,
        }),
      });

    case ActionType.ToggleTlsConnection:
      return Object.freeze({
        ...state,
        tlsSession: Object.freeze({
          ...state.tlsSession,
          connected: !state.tlsSession.connected,
        }),
      });

    case ActionType.ExecuteCommand: {
      const outcome = dispatchAllowlistedCommand(
        action.rawCommand,
        state.sandboxFs,
        state.tlsSession
      );
      if (isOk(outcome)) {
        return Object.freeze({
          ...state,
          tlsSession: outcome.value.nextSessionState,
          sandboxFs: outcome.value.nextFsState,
          commandHistory: Object.freeze(
            [...state.commandHistory, outcome.value.entry].slice(-40)
          ),
        });
      }

      const blockedEntry: CommandLogEntry = Object.freeze({
        id: `blocked_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        rawInput: action.rawCommand,
        timestampIso: outcome.error.timestampIso,
        status: 'BLOCKED',
        outputLines: Object.freeze([
          `[SECURITY POLICY BLOCK] ${outcome.error.title}`,
          `Reason      : ${outcome.error.message}`,
          `Remediation : ${outcome.error.remediation}`,
        ]),
        errorCode: outcome.error.code,
      });

      const isTraversal =
        outcome.error.code === 'ERR_CWE22_PATH_TRAVERSAL';

      return Object.freeze({
        ...state,
        sandboxFs: isTraversal
          ? Object.freeze({
              ...state.sandboxFs,
              traversalAttemptsBlocked:
                state.sandboxFs.traversalAttemptsBlocked + 1,
            })
          : state.sandboxFs,
        errorManager: recordError(state.errorManager, outcome.error),
        commandHistory: Object.freeze(
          [...state.commandHistory, blockedEntry].slice(-40)
        ),
      });
    }

    case ActionType.ClearConsole:
      return Object.freeze({
        ...state,
        commandHistory: Object.freeze([]),
      });

    case ActionType.ChangeDirectory: {
      const res = changeSandboxDirectory(state.sandboxFs, action.targetPath);
      if (isOk(res)) {
        return Object.freeze({
          ...state,
          sandboxFs: res.value,
        });
      }
      const isTraversal = res.error.code === 'ERR_CWE22_PATH_TRAVERSAL';
      return Object.freeze({
        ...state,
        sandboxFs: isTraversal
          ? Object.freeze({
              ...state.sandboxFs,
              traversalAttemptsBlocked:
                state.sandboxFs.traversalAttemptsBlocked + 1,
            })
          : state.sandboxFs,
        errorManager: recordError(state.errorManager, res.error),
      });
    }

    case ActionType.SelectFile: {
      const res = readSandboxFile(state.sandboxFs, action.targetPath);
      if (isOk(res)) {
        return Object.freeze({
          ...state,
          sandboxFs: res.value.state,
        });
      }
      return Object.freeze({
        ...state,
        errorManager: recordError(state.errorManager, res.error),
      });
    }

    case ActionType.SetFsSearchQuery:
      return Object.freeze({
        ...state,
        sandboxFs: Object.freeze({
          ...state.sandboxFs,
          searchQuery: action.query,
        }),
      });

    case ActionType.CreateAuditNote: {
      const res = createSandboxAuditNote(
        state.sandboxFs,
        action.filename,
        action.content
      );
      if (isOk(res)) {
        return Object.freeze({
          ...state,
          sandboxFs: res.value,
        });
      }
      return Object.freeze({
        ...state,
        errorManager: recordError(state.errorManager, res.error),
      });
    }

    case ActionType.DismissError:
      return Object.freeze({
        ...state,
        errorManager: dismissErrorById(state.errorManager, action.errorId),
      });

    case ActionType.ClearErrors:
      return Object.freeze({
        ...state,
        errorManager: clearAllErrors(),
      });

    case ActionType.SetErrorFilter:
      return Object.freeze({
        ...state,
        errorSeverityFilter: action.filter,
      });

    default:
      return state;
  }
};

export interface FunctionalStore {
  readonly getState: () => AppState;
  readonly dispatch: (action: AppAction) => void;
  readonly subscribe: (listener: () => void) => () => void;
}

export const createFunctionalStore = (
  initialState: AppState = createInitialAppState()
): FunctionalStore => {
  let currentState = initialState;
  const listeners = new Set<() => void>();

  const getState = (): AppState => currentState;

  const dispatch = (action: AppAction): void => {
    const nextState = appReducer(currentState, action);
    if (nextState !== currentState) {
      currentState = nextState;
      listeners.forEach((listener) => listener());
    }
  };

  const subscribe = (listener: () => void): (() => void) => {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  };

  return Object.freeze({ getState, dispatch, subscribe });
};

export const globalAppStore = createFunctionalStore();

export const useAppState = (): readonly [AppState, (action: AppAction) => void] => {
  const state = useSyncExternalStore(
    globalAppStore.subscribe,
    globalAppStore.getState,
    globalAppStore.getState
  );
  return [state, globalAppStore.dispatch] as const;
};
