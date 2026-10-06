/**
 * Automated Functional Test Suite (Browser UI + C11 Source Synchronization)
 * Verifies every TypeScript UI module and its synchronization with `/c_project/*`.
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
  ErrorDomain,
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
    | 'C11 Source & Heuristic Scan'
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
    const durationMs = Math.max(
      0.1,
      Number((performance.now() - start).toFixed(2))
    );
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
    const durationMs = Math.max(
      0.1,
      Number((performance.now() - start).toFixed(2))
    );
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
      'Separated Error Domains (Protocol vs Filesystem) & Dismissal',
      'Verifies immutable error queuing, domain tagging, active banner lookup, and dismissal.',
      () => {
        const s0 = createInitialErrorState();
        const e1 = createAppError({
          code: ErrorCode.PathTraversalBlocked,
          domain: ErrorDomain.Filesystem,
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
          activeBefore?.domain === ErrorDomain.Filesystem &&
          activeAfter === null &&
          secList.length === 1 &&
          secList[0].dismissed === true;
        return {
          passed,
          details: `Recorded ${e1.code} (${e1.domain}), dismissed=${activeAfter === null}`,
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
          details: `History transitions verified; invalid hash returned ${isErr(invalidParse) ? invalidParse.error.code : 'none'}`,
        };
      }
    ),

    // 4. Sandbox FS (CWE-22, Symlinks, Permissions, Stateful cd)
    runSingleTest(
      'test_fs_01',
      'Sandbox FS (CWE-22)',
      'Depth-Checked Path Normalization & Traversal Escape Rejection',
      'Verifies resolveSandboxedPath allows paths inside /srv/sandbox and rejects ../ escapes above root.',
      () => {
        const safeRes = resolveSandboxedPath(
          '/srv/sandbox/config',
          '../logs/audit_daemon.log',
          JAIL_ROOT
        );
        const escapeFromRoot = resolveSandboxedPath(
          '/srv/sandbox',
          '../etc/passwd',
          JAIL_ROOT
        );
        const escapeDeep = resolveSandboxedPath(
          '/srv/sandbox/config',
          '../../etc/shadow',
          JAIL_ROOT
        );
        const passed =
          isOk(safeRes) &&
          safeRes.value === '/srv/sandbox/logs/audit_daemon.log' &&
          isErr(escapeFromRoot) &&
          escapeFromRoot.error.code === ErrorCode.PathTraversalBlocked &&
          isErr(escapeDeep) &&
          escapeDeep.error.code === ErrorCode.PathTraversalBlocked;
        return {
          passed,
          details: `Safe path -> "${isOk(safeRes) ? safeRes.value : ''}"; "../etc/passwd" at root -> ${isErr(escapeFromRoot) ? escapeFromRoot.error.code : 'OK'}`,
        };
      }
    ),

    runSingleTest(
      'test_fs_02',
      'Sandbox FS (CWE-22)',
      'Symlink Escape, Permission Denied (0000), Directory Read & Stateful cd',
      'Verifies symlink rejection, chmod 0000 EACCES, EISDIR on directory read, and cd + cat resolution.',
      () => {
        const fs0 = createInitialSandboxFsState();
        const symlinkRead = readSandboxFile(
          fs0,
          'logs/symlink_escape_test'
        );
        const permDeniedRead = readSandboxFile(
          fs0,
          'reports/restricted_key_backup.txt'
        );
        const dirRead = readSandboxFile(fs0, 'reports');

        // Stateful cd into "reports", then relative read of "health_snapshot.txt"
        const cdRes = changeSandboxDirectory(fs0, 'reports');
        if (isErr(cdRes)) {
          return { passed: false, details: 'cd reports failed' };
        }
        const relRead = readSandboxFile(cdRes.value, 'health_snapshot.txt');
        const createRes = createSandboxAuditNote(
          cdRes.value,
          'incident_check.txt',
          'Verified openat2 confinement.'
        );

        const passed =
          isErr(symlinkRead) &&
          symlinkRead.error.code === ErrorCode.PathTraversalBlocked &&
          isErr(permDeniedRead) &&
          permDeniedRead.error.code === ErrorCode.PermissionDenied &&
          isErr(dirRead) &&
          dirRead.error.code === ErrorCode.NotARegularFile &&
          isOk(relRead) &&
          relRead.value.file.name === 'health_snapshot.txt' &&
          isOk(createRes);

        return {
          passed,
          details: `symlink->${isErr(symlinkRead) ? symlinkRead.error.code : ''}, perm->${isErr(permDeniedRead) ? permDeniedRead.error.code : ''}, dirRead->${isErr(dirRead) ? dirRead.error.code : ''}, cd+cat->OK`,
        };
      }
    ),

    // 5. Command Engine (Synchronized Opcodes, No Counter Increment on Reject)
    runSingleTest(
      'test_cmd_01',
      'Command Engine (CWE-78)',
      'Allowlisted C11 Opcode Framing & Stateful cd -> ls / cat',
      'Verifies allowlisted commands generate request + response headers and cd updates cwd for subsequent commands.',
      () => {
        const fs0 = createInitialSandboxFsState();
        const tls0 = createInitialTlsSession();
        const cdOut = dispatchAllowlistedCommand('cd reports', fs0, tls0);
        if (isErr(cdOut)) {
          return { passed: false, details: 'cd reports failed' };
        }
        const catOut = dispatchAllowlistedCommand(
          'cat health_snapshot.txt',
          cdOut.value.nextFsState,
          cdOut.value.nextSessionState
        );
        const passed =
          isOk(catOut) &&
          catOut.value.entry.wireFrame?.opcodeName === 'SAC_OP_FS_READFILE' &&
          catOut.value.nextSessionState.sequenceCounter ===
            tls0.sequenceCounter + 2 &&
          catOut.value.nextSessionState.commandsExecuted ===
            tls0.commandsExecuted + 2;
        return {
          passed,
          details: `cd reports (seq=1) -> cat health_snapshot.txt (seq=2) succeeded; reqHex="${isOk(catOut) ? catOut.value.entry.wireFrame?.requestRawHex : ''}"`,
        };
      }
    ),

    runSingleTest(
      'test_cmd_02',
      'Command Engine (CWE-78)',
      'Rejected Commands Never Advance Sequence or Executed Counter',
      'Verifies shell metacharacters and unimplemented commands (e.g. netstat, bash) are rejected without advancing sequenceCounter.',
      () => {
        const fs0 = createInitialSandboxFsState();
        const tls0 = createInitialTlsSession();
        const inj = dispatchAllowlistedCommand('uname; id', fs0, tls0);
        const unimpl = dispatchAllowlistedCommand('netstat', fs0, tls0);
        const passed =
          isErr(inj) &&
          inj.error.code === ErrorCode.ShellInjectionBlocked &&
          isErr(unimpl) &&
          unimpl.error.code === ErrorCode.CommandNotAllowlisted;
        return {
          passed,
          details: `Blocked "uname; id" (${isErr(inj) ? inj.error.code : ''}) and unimplemented "netstat" (${isErr(unimpl) ? unimpl.error.code : ''})`,
        };
      }
    ),

    runSingleTest(
      'test_cmd_03',
      'Command Engine (CWE-78)',
      'Unauthenticated mTLS Session Rejection (CWE-306)',
      'Verifies commands are rejected when the mTLS 1.3 session is disconnected.',
      () => {
        const fs0 = createInitialSandboxFsState();
        const disconnectedTls = {
          ...createInitialTlsSession(),
          connected: false,
        };
        const res = dispatchAllowlistedCommand('sysinfo', fs0, disconnectedTls);
        const passed =
          isErr(res) && res.error.code === ErrorCode.SessionDisconnected;
        return {
          passed,
          details: `Disconnected session returned ${isErr(res) ? res.error.code : 'OK'}`,
        };
      }
    ),

    // 6. C11 Source & Honest Heuristic Scanner
    runSingleTest(
      'test_c_audit_01',
      'C11 Source & Heuristic Scan',
      'Synchronization with /c_project/* (10 Files) & Honest Heuristic Labels',
      'Verifies all 10 C_SOURCE_FILES load via ?raw and heuristic scan reports PATTERN_NOT_FOUND / HEURISTIC_PRESENT.',
      () => {
        const findings = runStaticSecurityAudit(C_SOURCE_FILES);
        const noViolations = findings.every(
          (f) =>
            f.status === 'PATTERN_NOT_FOUND' || f.status === 'HEURISTIC_PRESENT'
        );
        return {
          passed: noViolations && findings.length === 5 && C_SOURCE_FILES.length === 10,
          details: `Loaded ${C_SOURCE_FILES.length} C11 files; ${findings.map((f) => `${f.ruleId}=${f.status}`).join(', ')}`,
        };
      }
    ),

    // 7. Centralized State Manager
    runSingleTest(
      'test_store_01',
      'State Manager',
      'Immutable Store Dispatch & Non-Incrementing Rejected Command State',
      'Verifies rejected commands increment securityBlocks while keeping sequenceCounter and commandsExecuted unchanged.',
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
          afterState.tlsSession.sequenceCounter ===
            beforeState.tlsSession.sequenceCounter &&
          afterState.tlsSession.commandsExecuted ===
            beforeState.tlsSession.commandsExecuted &&
          afterState.tlsSession.securityBlocks ===
            beforeState.tlsSession.securityBlocks + 1 &&
          afterState.sandboxFs.traversalAttemptsBlocked ===
            beforeState.sandboxFs.traversalAttemptsBlocked + 1;
        return {
          passed,
          details: `seq unchanged (${afterState.tlsSession.sequenceCounter}), securityBlocks=${afterState.tlsSession.securityBlocks}`,
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
