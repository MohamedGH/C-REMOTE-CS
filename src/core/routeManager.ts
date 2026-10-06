/**
 * Pure Functional Route Manager
 * Handles declarative route parsing, hash URL synchronization, route history,
 * and breadcrumb derivation using pure functions.
 */

import {
  AppError,
  createAppError,
  ErrorCode,
  ErrorSeverity,
} from './errorManager';
import { err, ok, Result } from './fp';

export enum RouteId {
  Workspace = 'workspace',
  FileSandbox = 'files',
  CArchitecture = 'c-source',
  SecurityAudit = 'security-audit',
  TestRunner = 'tests',
}

export interface RouteMetadata {
  readonly id: RouteId;
  readonly label: string;
  readonly shortLabel: string;
  readonly hash: string;
  readonly description: string;
}

export interface RouteManagerState {
  readonly currentRoute: RouteId;
  readonly previousRoute: RouteId | null;
  readonly history: ReadonlyArray<RouteId>;
  readonly activeCFileTab: string;
}

export const ROUTE_REGISTRY: ReadonlyArray<RouteMetadata> = Object.freeze([
  Object.freeze({
    id: RouteId.Workspace,
    label: 'Command Console',
    shortLabel: 'Console',
    hash: '#/workspace',
    description:
      'Allowlisted POSIX system telemetry dispatcher over simulated mutual TLS 1.3 frames.',
  }),
  Object.freeze({
    id: RouteId.FileSandbox,
    label: 'Sandboxed File Browser',
    shortLabel: 'Files',
    hash: '#/files',
    description:
      'Strict chroot / realpath() canonicalized directory inspector preventing CWE-22 path traversal.',
  }),
  Object.freeze({
    id: RouteId.CArchitecture,
    label: 'C11 TLS Source & Protocol',
    shortLabel: 'C11 Source',
    hash: '#/c-source',
    description:
      'Defensive C11 + OpenSSL 3.x client/server implementation with binary framing and zero shell invocation.',
  }),
  Object.freeze({
    id: RouteId.SecurityAudit,
    label: 'Security & Error Log',
    shortLabel: 'Audit Log',
    hash: '#/security-audit',
    description:
      'Centralized Error Manager & C static analyzer verifying protection against CWE-78, CWE-22, and CWE-306.',
  }),
  Object.freeze({
    id: RouteId.TestRunner,
    label: 'Functional Test Suite',
    shortLabel: 'Tests',
    hash: '#/tests',
    description:
      'Automated functional unit and integration verification across all core modules.',
  }),
]);

export const createInitialRouteState = (
  initialRoute: RouteId = RouteId.Workspace
): RouteManagerState =>
  Object.freeze({
    currentRoute: initialRoute,
    previousRoute: null,
    history: Object.freeze([initialRoute]),
    activeCFileTab: 'tls_server.c',
  });

export const parseRouteFromHash = (
  rawHash: string
): Result<RouteId, AppError> => {
  const cleaned = rawHash.trim().replace(/^#\/?/, '').toLowerCase();
  if (!cleaned || cleaned === 'workspace' || cleaned === 'console') {
    return ok(RouteId.Workspace);
  }
  const matched = ROUTE_REGISTRY.find(
    (r) => r.id === cleaned || r.hash.replace(/^#\/?/, '') === cleaned
  );
  if (matched) {
    return ok(matched.id);
  }
  return err(
    createAppError({
      code: ErrorCode.InvalidRoute,
      severity: ErrorSeverity.Warning,
      title: 'Unknown Navigation Route',
      message: `Route "#/${cleaned}" is not registered in RouteManager. Redirected to Command Console.`,
      remediation:
        'Select one of the registered routes: workspace, files, c-source, security-audit, or tests.',
      contextInput: rawHash,
    })
  );
};

export const navigateToRoute = (
  state: RouteManagerState,
  targetRoute: RouteId
): RouteManagerState => {
  if (state.currentRoute === targetRoute) {
    return state;
  }
  return Object.freeze({
    ...state,
    previousRoute: state.currentRoute,
    currentRoute: targetRoute,
    history: Object.freeze([...state.history, targetRoute].slice(-25)),
  });
};

export const navigateBack = (state: RouteManagerState): RouteManagerState => {
  if (state.history.length <= 1) {
    return state;
  }
  const nextHistory = state.history.slice(0, -1);
  const target = nextHistory[nextHistory.length - 1] ?? RouteId.Workspace;
  return Object.freeze({
    ...state,
    previousRoute: state.currentRoute,
    currentRoute: target,
    history: Object.freeze(nextHistory),
  });
};

export const selectCurrentRouteMetadata = (
  state: RouteManagerState
): RouteMetadata =>
  ROUTE_REGISTRY.find((r) => r.id === state.currentRoute) ?? ROUTE_REGISTRY[0];
