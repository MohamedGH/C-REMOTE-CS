/**
 * Pure Functional Error Manager
 * Captures, classifies, and manages operational and security policy errors
 * with CWE mappings and immutable state transitions.
 */

export enum ErrorSeverity {
  Info = 'INFO',
  Warning = 'WARNING',
  SecurityBlock = 'SECURITY_BLOCK',
  Critical = 'CRITICAL',
}

export enum ErrorCode {
  PathTraversalBlocked = 'ERR_CWE22_PATH_TRAVERSAL',
  ShellInjectionBlocked = 'ERR_CWE78_SHELL_METACHAR',
  CommandNotAllowlisted = 'ERR_CMD_NOT_ALLOWLISTED',
  SessionDisconnected = 'ERR_TLS_NOT_ESTABLISHED',
  FileNotFound = 'ERR_FS_ENOENT',
  NotADirectory = 'ERR_FS_ENOTDIR',
  InvalidRoute = 'ERR_ROUTER_INVALID_PATH',
  InvalidFilename = 'ERR_FS_INVALID_NAME',
  StaticAuditViolation = 'ERR_C_AUDIT_VIOLATION',
}

export interface AppError {
  readonly id: string;
  readonly code: ErrorCode;
  readonly severity: ErrorSeverity;
  readonly title: string;
  readonly message: string;
  readonly remediation: string;
  readonly cweReference?: string;
  readonly contextInput?: string;
  readonly timestampIso: string;
  readonly dismissed: boolean;
}

export interface ErrorManagerState {
  readonly errors: ReadonlyArray<AppError>;
  readonly activeBannerErrorId: string | null;
}

export const createInitialErrorState = (): ErrorManagerState =>
  Object.freeze({
    errors: [],
    activeBannerErrorId: null,
  });

export const createAppError = (params: {
  readonly code: ErrorCode;
  readonly severity: ErrorSeverity;
  readonly title: string;
  readonly message: string;
  readonly remediation: string;
  readonly cweReference?: string;
  readonly contextInput?: string;
  readonly idSuffix?: string;
  readonly timestampIso?: string;
}): AppError => {
  const timestampIso = params.timestampIso ?? new Date().toISOString();
  const id = `err_${params.code}_${params.idSuffix ?? Math.random().toString(36).slice(2, 8)}`;
  return Object.freeze({
    id,
    code: params.code,
    severity: params.severity,
    title: params.title,
    message: params.message,
    remediation: params.remediation,
    cweReference: params.cweReference,
    contextInput: params.contextInput,
    timestampIso,
    dismissed: false,
  });
};

export const recordError = (
  state: ErrorManagerState,
  error: AppError
): ErrorManagerState =>
  Object.freeze({
    errors: [error, ...state.errors].slice(0, 50),
    activeBannerErrorId: error.id,
  });

export const dismissErrorById = (
  state: ErrorManagerState,
  errorId: string
): ErrorManagerState =>
  Object.freeze({
    errors: state.errors.map((item) =>
      item.id === errorId ? Object.freeze({ ...item, dismissed: true }) : item
    ),
    activeBannerErrorId:
      state.activeBannerErrorId === errorId ? null : state.activeBannerErrorId,
  });

export const clearAllErrors = (): ErrorManagerState =>
  createInitialErrorState();

export const selectActiveBannerError = (
  state: ErrorManagerState
): AppError | null =>
  state.activeBannerErrorId
    ? state.errors.find(
        (e) => e.id === state.activeBannerErrorId && !e.dismissed
      ) ?? null
    : null;

export const selectErrorsBySeverity = (
  state: ErrorManagerState,
  severity: ErrorSeverity | 'ALL'
): ReadonlyArray<AppError> =>
  severity === 'ALL'
    ? state.errors
    : state.errors.filter((e) => e.severity === severity);
