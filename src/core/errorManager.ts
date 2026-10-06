/**
 * Pure Functional Error Manager
 * Captures, classifies, and manages operational and security policy errors
 * with separated error domains (PROTOCOL vs FILESYSTEM) matching c_project/protocol.h.
 */

export enum ErrorSeverity {
  Info = 'INFO',
  Warning = 'WARNING',
  SecurityBlock = 'SECURITY_BLOCK',
  Critical = 'CRITICAL',
}

export enum ErrorDomain {
  None = 'SAC_DOMAIN_NONE',
  Protocol = 'SAC_DOMAIN_PROTOCOL',
  Filesystem = 'SAC_DOMAIN_FILESYSTEM',
  System = 'SAC_DOMAIN_SYSTEM',
  Router = 'UI_DOMAIN_ROUTER',
}

export enum ErrorCode {
  PathTraversalBlocked = 'ERR_CWE22_PATH_ESCAPE',
  ShellInjectionBlocked = 'ERR_CWE78_INVALID_ARG',
  CommandNotAllowlisted = 'ERR_BAD_OPCODE',
  SessionDisconnected = 'ERR_TLS_UNAUTHENTICATED',
  SequenceRegression = 'ERR_SEQUENCE_REGRESSION',
  PayloadTooLarge = 'ERR_PAYLOAD_TOO_LARGE',
  FileNotFound = 'ERR_FS_NOT_FOUND',
  PermissionDenied = 'ERR_FS_PERMISSION_DENIED',
  NotADirectory = 'ERR_FS_NOT_DIR',
  NotARegularFile = 'ERR_FS_NOT_REGULAR',
  BufferTooSmall = 'ERR_FS_BUFFER_TOO_SMALL',
  InvalidRoute = 'ERR_ROUTER_INVALID_PATH',
  InvalidFilename = 'ERR_FS_INVALID_NAME',
}

export interface AppError {
  readonly id: string;
  readonly code: ErrorCode;
  readonly domain: ErrorDomain;
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
  readonly domain?: ErrorDomain;
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
    domain: params.domain ?? ErrorDomain.Protocol,
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
