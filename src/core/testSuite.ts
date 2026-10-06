/**
 * Automated Functional Test Suite
 * Verifies every implemented module and functionality:
 * 1. Functional Primitives (Result Monad & pipe composition)
 * 2. Centralized Error Manager (creation, recording, dismissal, severity filtering)
 * 3. Centralized Route Manager (hash parsing, navigation, history stack, invalid route fallback)
 * 4. Sandboxed File Browser Engine (realpath canonicalization, CWE-22 traversal blocking, file read/create)
 * 5. Allowlisted Command Dispatcher & TLS Frame Engine (POSIX opcodes, CWE-78 metacharacter blocking, CWE-306 mTLS check)
 * 6. C11 Source Architecture & Static Security Auditor (verifying zero shell calls and memory-safe bounds)
 * 7. Centralized State Manager (pure reducer immutability and integrated state transitions)
 */

import { C_SOURCE_FILES, runStaticSecurityAudit } from './cCodeArch';
import {
  createInitialTlsSession,
  dispatchAllowlistedCommand,
} from './commandEngine';
import {
  createAppError,
  createInitialErrorState,
  dismissErrorById,
  ErrorCode,
  ErrorSeverity,
  recordError,
  selectActiveBannerError,
  selectErrorsBySeverity,
} from './errorManager';
import { err, isErr, isOk, mapResult, ok, pipe } from './fp';
import {
  createInitialRouteState,
  navigateBack,
  navigateToRoute,
  parseRouteFromHash,
  RouteId,
} from './routeManager';
import {
  changeSandboxDirectory,
  createInitialSandboxFsState,
  createSandboxAuditNote,
  JAIL_ROOT,
  readSandboxFile,
  resolveSandboxedPath,
} from './sandboxFs';
import {
  ActionType,
  appReducer,
  createFunctionalStore,
  createInitialAppState,
} from './stateManager';

export interface TestCaseResult {
  readonly id: string;
  readonly category:
    | 'FP Primitives'
    | 'Error Manager'
    | 'Route Manager'
    | 'Sandbox FS (CWE-22)'
    | 'Command Engine (CWE-78)'
    | 'C11 Static Auditor'
    | 'State Manager';
  readonly name: string;
  readonly assertionDescription: string;
  readonly passed: boolean;
  readonly durationMs: number;
  readonly details: string;
}

export interface TestSuiteSummary {
  readonly total: number;
  readonly passed: number;
  readonly failed: number;
  readonly totalDurationMs: number;
  readonly results: ReadonlyArray<TestCaseResult>;
}

const runSingleTest = (
  id: string,
  category: TestCaseResult['category'],
  name: string,
  assertionDescription: string,
  testFn: () => { readonly passed: boolean; readonly details: string }
): TestCaseResult => {
  const start = performance.now();
  try {
    const outcome = testFn();
    const durationMs = Math.max(0.1, Number((performance.now() - start).toFixed(2)));
    return Object.freeze({
      id,
      category,
      name,
      assertionDescription,
      passed: outcome.passed,
      durationMs,
      details: outcome.details,
    });
  } catch (e) {
    const durationMs = Math.max(0.1, Number((performance.now() - start).toFixed(2)));
    return Object.freeze({
      id,
      category,
      name,
      assertionDescription,
      passed: false,
      durationMs,
      details: `Exception thrown: ${e instanceof Error ? e.message : String(e)}`,
    });
  }
};

export const executeAllFunctionalTests = (): TestSuiteSummary => {
  const tests: ReadonlyArray<TestCaseResult> = [
    // 1. FP Primitives
    runSingleTest(
      'test_fp_01',
      'FP Primitives',
      'Result Monad (ok / err / mapResult) & pipe() Composition',
      'Verifies pure monadic transformations and left-to-right function composition.',
      () => {
        const step1 = ok(10);
        const mapped = mapResult(step1, (x) => x * 3);
        const piped = pipe(
          5,
          (n) => n + 3,
          (n) => n * 2
        );
        const errCase = mapResult(err('FAIL'), (x: number) => x + 1);
        const passed =
          isOk(mapped) &&
          mapped.value === 30 &&
          piped === 16 &&
          isErr(errCase) &&
          errCase.error === 'FAIL';
        return {
          passed,
          details: `mapResult(ok(10)) => ${isOk(mapped) ? mapped.value : 'err'}, pipe(5) => ${piped}`,
        };
      }
    ),

    // 2. Error Manager
    runSingleTest(
      'test_err_01',
      'Error Manager',
      'Error Recording, Active Banner Selection & Dismissal',
      'Verifies immutable error queuing, active banner lookup, and dismissal state update.',
      () => {
        const s0 = createInitialErrorState();
        const e1 = createAppError({
          code: ErrorCode.PathTraversalBlocked,
          severity: ErrorSeverity.SecurityBlock,
          title: 'Test CWE-22 Block',
          message: 'Blocked ../etc/passwd',
          remediation: 'Stay in /srv/sandbox',
          cweReference: 'CWE-22',
        });
        const s1 = recordError(s0, e1);
        const activeBefore = selectActiveBannerError(s1);
        const s2 = dismissErrorById(s1, e1.id);
        const activeAfter = selectActiveBannerError(s2);
        const secList = selectErrorsBySeverity(s2, ErrorSeverity.SecurityBlock);
        const passed =
          activeBefore?.id === e1.id &&
          activeAfter === null &&
          secList.length === 1 &&
          secList[0].dismissed === true;
        return {
          passed,
          details: `Recorded ${e1.code}, banner active=${Boolean(activeBefore)}, dismissed cleanly=${activeAfter === null}`,
        };
      }
    ),

    // 3. Route Manager
    runSingleTest(
      'test_route_01',
      'Route Manager',
      'Route Hash Parsing, Navigation & Back History Stack',
      'Verifies valid hash routing, invalid route error generation, and history stack back navigation.',
      () => {
        const r0 = createInitialRouteState(RouteId.Workspace);
        const r1 = navigateToRoute(r0, RouteId.FileSandbox);
        const r2 = navigateToRoute(r1, RouteId.CArchitecture);
        const rBack = navigateBack(r2);
        const validParse = parseRouteFromHash('#/security-audit');
        const invalidParse = parseRouteFromHash('#/non-existent-route');
        const passed =
          r2.currentRoute === RouteId.CArchitecture &&
          rBack.currentRoute === RouteId.FileSandbox &&
          isOk(validParse) &&
          validParse.value === RouteId.SecurityAudit &&
          isErr(invalidParse) &&
          invalidParse.error.code === ErrorCode.InvalidRoute;
        return {
          passed,
          details: `History stack transitions: workspace -> files -> c-source -> back(${rBack.currentRoute}); invalid hash returned ${isErr(invalidParse) ? invalidParse.error.code : 'none'}`,
        };
      }
    ),

    // 4. Sandbox FS (CWE-22)
    runSingleTest(
      'test_fs_01',
      'Sandbox FS (CWE-22)',
      'Canonical Path Containment & Parent Traversal Block (CWE-22)',
      'Verifies resolveSandboxedPath allows paths inside /srv/sandbox and strictly blocks ../../etc/shadow.',
      () => {
        const safeRes = resolveSandboxedPath(
          '/srv/sandbox/config',
          '../logs/audit_daemon.log',
          JAIL_ROOT
        );
        const escapeRes = resolveSandboxedPath(
          '/srv/sandbox/config',
          '../../../etc/shadow',
          JAIL_ROOT
        );
        const backslashRes = resolveSandboxedPath(
          '/srv/sandbox',
          '..\\..\\Windows\\System32',
          JAIL_ROOT
        );
        const passed =
          isOk(safeRes) &&
          safeRes.value === '/srv/sandbox/logs/audit_daemon.log' &&
          isErr(escapeRes) &&
          escapeRes.error.code === ErrorCode.PathTraversalBlocked &&
          isErr(backslashRes) &&
          backslashRes.error.code === ErrorCode.PathTraversalBlocked;
        return {
          passed,
          details: `Safe path resolved to "${isOk(safeRes) ? safeRes.value : ''}"; "../../../etc/shadow" blocked with ${isErr(escapeRes) ? escapeRes.error.code : ''}`,
        };
      }
    ),

    runSingleTest(
      'test_fs_02',
      'Sandbox FS (CWE-22)',
      'Sandboxed Directory Change, File Read & Audit Note Creation',
      'Verifies reading existing config files and creating a new validated audit file inside the jail.',
      () => {
        const fs0 = createInitialSandboxFsState();
        const cdRes = changeSandboxDirectory(fs0, 'reports');
        if (isErr(cdRes)) {
          return { passed: false, details: 'Failed to cd into reports' };
        }
        const createRes = createSandboxAuditNote(
          cdRes.value,
          'incident_check.txt',
          'Verified mTLS certificate rotation.'
        );
        if (isErr(createRes)) {
          return { passed: false, details: 'Failed to create audit note' };
        }
        const readRes = readSandboxFile(
          createRes.value,
          '/srv/sandbox/reports/incident_check.txt'
        );
        const passed =
          isOk(readRes) &&
          readRes.value.file.content === 'Verified mTLS certificate rotation.';
        return {
          passed,
          details: `Created & verified "/srv/sandbox/reports/incident_check.txt" (${isOk(readRes) ? readRes.value.file.sizeBytes : 0} bytes, SHA256:${isOk(readRes) ? readRes.value.file.sha256Short : ''})`,
        };
      }
    ),

    // 5. Command Engine (CWE-78 & CWE-306)
    runSingleTest(
      'test_cmd_01',
      'Command Engine (CWE-78)',
      'Allowlisted Opcode Execution & Binary Wire Frame Generation',
      'Verifies allowlisted commands map to SAC1 binary wire headers and increment anti-replay sequence numbers.',
      () => {
        const fs0 = createInitialSandboxFsState();
        const tls0 = createInitialTlsSession();
        const res = dispatchAllowlistedCommand('uname', fs0, tls0);
        const passed =
          isOk(res) &&
          res.value.entry.wireFrame?.opcodeName === 'OP_SYS_UNAME' &&
          res.value.nextSessionState.sequenceCounter === tls0.sequenceCounter + 1;
        return {
          passed,
          details: `Dispatched OP_SYS_UNAME -> frame "${isOk(res) ? res.value.entry.wireFrame?.rawHexPreview : ''}" seq=${isOk(res) ? res.value.nextSessionState.sequenceCounter : 0}`,
        };
      }
    ),

    runSingleTest(
      'test_cmd_02',
      'Command Engine (CWE-78)',
      'OS Command Injection & Arbitrary Binary Rejection (CWE-78)',
      'Verifies compound shell operators (; | && ` $()) and unallowlisted commands (sh, bash, wget) are blocked.',
      () => {
        const fs0 = createInitialSandboxFsState();
        const tls0 = createInitialTlsSession();
        const injectionAttempt = dispatchAllowlistedCommand(
          'uname; cat /etc/passwd',
          fs0,
          tls0
        );
        const subshellAttempt = dispatchAllowlistedCommand(
          'ls $(whoami)',
          fs0,
          tls0
        );
        const unallowlistedAttempt = dispatchAllowlistedCommand(
          'bash -i',
          fs0,
          tls0
        );
        const passed =
          isErr(injectionAttempt) &&
          injectionAttempt.error.code === ErrorCode.ShellInjectionBlocked &&
          isErr(subshellAttempt) &&
          subshellAttempt.error.code === ErrorCode.ShellInjectionBlocked &&
          isErr(unallowlistedAttempt) &&
          unallowlistedAttempt.error.code === ErrorCode.CommandNotAllowlisted;
        return {
          passed,
          details: `Blocked ";", "$()", and "bash -i" with ${isErr(injectionAttempt) ? injectionAttempt.error.code : ''} & ${isErr(unallowlistedAttempt) ? unallowlistedAttempt.error.code : ''}`,
        };
      }
    ),

    runSingleTest(
      'test_cmd_03',
      'Command Engine (CWE-78)',
      'Unauthenticated mTLS Session Rejection (CWE-306)',
      'Verifies commands are rejected when mutual TLS 1.3 session is disconnected.',
      () => {
        const fs0 = createInitialSandboxFsState();
        const disconnectedTls = { ...createInitialTlsSession(), connected: false };
        const res = dispatchAllowlistedCommand('sysinfo', fs0, disconnectedTls);
        const passed =
          isErr(res) && res.error.code === ErrorCode.SessionDisconnected;
        return {
          passed,
          details: `Disconnected session returned ${isErr(res) ? res.error.code : 'OK'} (${isErr(res) ? res.error.cweReference : ''})`,
        };
      }
    ),

    // 6. C11 Static Security Auditor
    runSingleTest(
      'test_c_audit_01',
      'C11 Static Auditor',
      'Static Security Verification of C11 Server, Client, Managers & Tests',
      'Scans all 7 C_SOURCE_FILES to confirm zero system()/popen()/gets()/strcpy() calls and active mTLS 1.3 + realpath() guards.',
      () => {
        const findings = runStaticSecurityAudit(C_SOURCE_FILES);
        const allSafe = findings.every((f) => f.status === 'VERIFIED_SAFE');
        const hasMainInServer = C_SOURCE_FILES.some(
          (f) => f.filename === 'tls_server.c' && f.code.includes('int main(')
        );
        const hasMainInClient = C_SOURCE_FILES.some(
          (f) => f.filename === 'tls_client.c' && f.code.includes('int main(')
        );
        const hasCTestSuite = C_SOURCE_FILES.some(
          (f) => f.filename === 'test_suite.c' && f.code.includes('int main(')
        );
        return {
          passed:
            allSafe &&
            findings.length === 4 &&
            C_SOURCE_FILES.length === 7 &&
            hasMainInServer &&
            hasMainInClient &&
            hasCTestSuite,
          details: `Verified ${C_SOURCE_FILES.length} C11 modules & ${findings.length}/4 static C security rules: ${findings.map((f) => `${f.ruleId}(${f.cwe})=${f.status}`).join(', ')}`,
        };
      }
    ),

    // 7. Centralized State Manager
    runSingleTest(
      'test_store_01',
      'State Manager',
      'Immutable Store Dispatch & Cross-Slice Error Coordination',
      'Verifies store.dispatch updates state immutably and coordinates SandboxFs traversal blocks with ErrorManager.',
      () => {
        const store = createFunctionalStore(createInitialAppState());
        const beforeState = store.getState();
        store.dispatch({
          type: ActionType.ExecuteCommand,
          rawCommand: 'cat ../../../etc/shadow',
        });
        const afterState = store.getState();
        const passed =
          beforeState !== afterState &&
          afterState.sandboxFs.traversalAttemptsBlocked ===
            beforeState.sandboxFs.traversalAttemptsBlocked + 1 &&
          afterState.errorManager.errors.length === 1 &&
          afterState.errorManager.errors[0].code ===
            ErrorCode.PathTraversalBlocked;
        return {
          passed,
          details: `traversalAttemptsBlocked incremented to ${afterState.sandboxFs.traversalAttemptsBlocked}; ErrorManager recorded ${afterState.errorManager.errors[0]?.code}`,
        };
      }
    ),
  ];

  const passedCount = tests.filter((t) => t.passed).length;
  const totalDurationMs = Number(
    tests.reduce((acc, t) => acc + t.durationMs, 0).toFixed(2)
  );

  return Object.freeze({
    total: tests.length,
    passed: passedCount,
    failed: tests.length - passedCount,
    totalDurationMs,
    results: Object.freeze(tests),
  });
};
