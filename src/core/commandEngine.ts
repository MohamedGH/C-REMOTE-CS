/**
 * Pure Functional Allowlisted Command Dispatcher & Binary Wire Frame Simulator
 *
 * Technical Honesty & Synchronization with `c_project/protocol.h`:
 * - Only the 6 opcodes genuinely implemented in `c_project/protocol.h` and
 *   `c_project/managers.c` (`SAC_OP_SYS_UPTIME`, `SAC_OP_SYS_UNAME`,
 *   `SAC_OP_SYS_STATVFS`, `SAC_OP_FS_LISTDIR`, `SAC_OP_FS_READFILE`,
 *   `SAC_OP_FS_CHDIR`) are dispatched as RPC wire frames.
 * - `help` is explicitly marked as a local client CLI helper (`sac_parse_cli_opcode`
 *   in `tls_helpers.c`) that does not transmit a network frame.
 * - Rejected commands NEVER increment `sequenceCounter` or `commandsExecuted`
 *   (matching `sac_validate_request_header` / `sac_route_dispatch` in `managers.c`).
 * - Wire inspection displays both the 12-byte `sac_frame_header_t` request header
 *   and the 16-byte `sac_resp_header_t` response header without inventing fake
 *   application-layer HMAC fields.
 */

import {
  AppError,
  createAppError,
  ErrorCode,
  ErrorDomain,
  ErrorSeverity,
} from './errorManager';
import { err, ok, Result } from './fp';
import {
  changeSandboxDirectory,
  FsNodeType,
  readSandboxFile,
  SandboxFsState,
  selectCurrentDirectoryChildren,
} from './sandboxFs';

export enum CommandOpcode {
  SysUptime = 0x01,
  SysUname = 0x02,
  SysStatVfs = 0x03,
  FsListDir = 0x10,
  FsReadFile = 0x11,
  FsChangeDir = 0x12,
}

export interface WireFrameInspection {
  readonly magicHex: string;
  readonly version: number;
  readonly opcodeHex: string;
  readonly opcodeName: string;
  readonly sequenceNumber: number;
  readonly requestPayloadLengthBytes: number;
  readonly requestRawHex: string;
  readonly responseStatusHex: string;
  readonly responseDomain: string;
  readonly responseFsStatus: string;
  readonly responsePayloadLengthBytes: number;
  readonly responseRawHex: string;
  readonly cSyscallInvoked: string;
}

export interface CommandLogEntry {
  readonly id: string;
  readonly rawInput: string;
  readonly timestampIso: string;
  readonly status: 'SUCCESS' | 'BLOCKED' | 'LOCAL_HELP';
  readonly outputLines: ReadonlyArray<string>;
  readonly wireFrame?: WireFrameInspection;
  readonly errorCode?: ErrorCode;
  readonly errorDomain?: ErrorDomain;
}

export interface TlsSessionState {
  readonly connected: boolean;
  readonly simulationLabel: 'SIMULATED_BROWSER_SESSION';
  readonly remoteHost: string;
  readonly remotePort: number;
  readonly protocolVersion: 'TLSv1.3';
  readonly cipherSuite: 'TLS_AES_256_GCM_SHA384';
  readonly clientCertSubject: string;
  readonly expectedServerSan: string;
  readonly sequenceCounter: number;
  readonly commandsExecuted: number;
  readonly securityBlocks: number;
}

export const createInitialTlsSession = (): TlsSessionState =>
  Object.freeze({
    connected: true,
    simulationLabel: 'SIMULATED_BROWSER_SESSION',
    remoteHost: '127.0.0.1',
    remotePort: 8443,
    protocolVersion: 'TLSv1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    clientCertSubject: 'CN=admin-client (Test ECDSA P-256)',
    expectedServerSan: 'DNS:localhost, IP:127.0.0.1',
    sequenceCounter: 0,
    commandsExecuted: 0,
    securityBlocks: 0,
  });

const SHELL_METACHAR_PATTERN = /[;|&`$><\\!\n\r]/;

const formatHexByte = (n: number): string =>
  (n & 0xff).toString(16).padStart(2, '0').toUpperCase();

const formatUint32Hex = (n: number): string =>
  [
    formatHexByte((n >>> 24) & 0xff),
    formatHexByte((n >>> 16) & 0xff),
    formatHexByte((n >>> 8) & 0xff),
    formatHexByte(n & 0xff),
  ].join(' ');

export const buildWireFrame = (params: {
  readonly opcode: CommandOpcode;
  readonly opcodeName: string;
  readonly sequenceNumber: number;
  readonly requestPayload: string;
  readonly responsePayloadLength: number;
  readonly statusCode?: number;
  readonly errorDomain?: number;
  readonly fsStatus?: number;
  readonly cSyscallInvoked: string;
}): WireFrameInspection => {
  const magicHex = '53 41 43 31'; // "SAC1" (0x53414331)
  const opByte = formatHexByte(params.opcode);
  const seqHex = formatUint32Hex(params.sequenceNumber);
  const reqLenHigh = formatHexByte((params.requestPayload.length >>> 8) & 0xff);
  const reqLenLow = formatHexByte(params.requestPayload.length & 0xff);

  const statusByte = formatHexByte(params.statusCode ?? 0x00);
  const domainByte = formatHexByte(params.errorDomain ?? 0x00);
  const fsByte = formatHexByte(params.fsStatus ?? 0x00);
  const respLenHex = formatUint32Hex(params.responsePayloadLength);

  return Object.freeze({
    magicHex: '0x53414331 ("SAC1")',
    version: 1,
    opcodeHex: `0x${opByte}`,
    opcodeName: params.opcodeName,
    sequenceNumber: params.sequenceNumber,
    requestPayloadLengthBytes: params.requestPayload.length,
    requestRawHex: `${magicHex} 01 ${opByte} ${seqHex} ${reqLenHigh} ${reqLenLow}`,
    responseStatusHex: `0x${statusByte}`,
    responseDomain:
      (params.errorDomain ?? 0) === 0
        ? 'SAC_DOMAIN_NONE (0x00)'
        : (params.errorDomain ?? 0) === 1
          ? 'SAC_DOMAIN_PROTOCOL (0x01)'
          : 'SAC_DOMAIN_FILESYSTEM (0x02)',
    responseFsStatus: `0x${fsByte}`,
    responsePayloadLengthBytes: params.responsePayloadLength,
    responseRawHex: `${magicHex} 01 ${statusByte} ${domainByte} ${fsByte} ${seqHex} ${respLenHex}`,
    cSyscallInvoked: params.cSyscallInvoked,
  });
};

export interface CommandDispatchOutcome {
  readonly entry: CommandLogEntry;
  readonly nextFsState: SandboxFsState;
  readonly nextSessionState: TlsSessionState;
}

/**
 * Pure functional validator and command router synchronized with `c_project/managers.c`.
 * Rejected requests increment `securityBlocks` and NEVER advance `sequenceCounter`
 * or `commandsExecuted`.
 */
export const dispatchAllowlistedCommand = (
  rawInput: string,
  fsState: SandboxFsState,
  sessionState: TlsSessionState,
  timestampIso: string = new Date().toISOString()
): Result<CommandDispatchOutcome, AppError> => {
  const trimmed = rawInput.trim();

  if (!sessionState.connected) {
    return err(
      createAppError({
        code: ErrorCode.SessionDisconnected,
        domain: ErrorDomain.Protocol,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Mutual TLS 1.3 Session Required (SAC_ERR_UNAUTHENTICATED)',
        message:
          'Rejected RPC dispatch because the simulated mTLS 1.3 session is disconnected.',
        remediation:
          'Reconnect the simulated mTLS 1.3 handshake before dispatching remote opcodes.',
        cweReference: 'CWE-306',
        contextInput: trimmed,
        timestampIso,
      })
    );
  }

  if (SHELL_METACHAR_PATTERN.test(trimmed)) {
    return err(
      createAppError({
        code: ErrorCode.ShellInjectionBlocked,
        domain: ErrorDomain.Protocol,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Forbidden Shell/Control Character Rejected (SAC_ERR_INVALID_ARGUMENT)',
        message: `Input "${trimmed}" contains shell control operators (; | & \` $ > < \\). In c_project/managers.c, has_forbidden_argument_chars() rejects the frame before any syscall.`,
        remediation:
          'Issue a single allowlisted command token (sysinfo, uname, df, ls, cat <file>, cd <dir>).',
        cweReference: 'CWE-78',
        contextInput: trimmed,
        timestampIso,
      })
    );
  }

  const parts = trimmed.split(/\s+/).filter(Boolean);
  const cmd = (parts[0] ?? 'help').toLowerCase();
  const arg = parts.slice(1).join(' ');

  if (arg.length > 256) {
    return err(
      createAppError({
        code: ErrorCode.PayloadTooLarge,
        domain: ErrorDomain.Protocol,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Request Payload Exceeds SAC_MAX_PATH_LEN (SAC_ERR_PAYLOAD_TOO_LARGE)',
        message: `Argument length (${arg.length} bytes) exceeds SAC_MAX_PATH_LEN (256 bytes).`,
        remediation: 'Keep path arguments at or below 256 bytes.',
        cweReference: 'CWE-789',
        contextInput: trimmed.slice(0, 64) + '...',
        timestampIso,
      })
    );
  }

  if (cmd === 'help') {
    const entry: CommandLogEntry = Object.freeze({
      id: `help_${Date.now()}`,
      rawInput: trimmed || 'help',
      timestampIso,
      status: 'LOCAL_HELP',
      outputLines: Object.freeze([
        'Implemented C11 Wire Opcodes in c_project/protocol.h (Zero Shell Execution):',
        '  sysinfo | uptime -> SAC_OP_SYS_UPTIME (0x01)   POSIX sysinfo(&si)',
        '  uname            -> SAC_OP_SYS_UNAME (0x02)    POSIX uname(&uts)',
        '  df | statvfs     -> SAC_OP_SYS_STATVFS (0x03)  POSIX fstatvfs(jail_dirfd, &vfs)',
        '  ls [dir]         -> SAC_OP_FS_LISTDIR (0x10)   sac_fs_list_dir(jail_dirfd, cwd_rel, arg)',
        '  cat <file>       -> SAC_OP_FS_READFILE (0x11)  sac_fs_read_file(jail_dirfd, cwd_rel, arg)',
        '  cd <dir>         -> SAC_OP_FS_CHDIR (0x12)     sac_fs_chdir(jail_dirfd, cwd_rel, arg)',
        'Note: "help" is a local client CLI command and does not send a network frame.',
      ]),
    });
    return ok(
      Object.freeze({
        entry,
        nextFsState: fsState,
        nextSessionState: sessionState,
      })
    );
  }

  const nextSeq = sessionState.sequenceCounter + 1;

  const makeSuccess = (
    opcode: CommandOpcode,
    opcodeName: string,
    cSyscallInvoked: string,
    outputLines: ReadonlyArray<string>,
    updatedFsState: SandboxFsState = fsState
  ): Result<CommandDispatchOutcome, AppError> => {
    const joinedOutput = outputLines.join('\n') + '\n';
    const wireFrame = buildWireFrame({
      opcode,
      opcodeName,
      sequenceNumber: nextSeq,
      requestPayload: arg,
      responsePayloadLength: joinedOutput.length,
      cSyscallInvoked,
    });
    const nextSessionState: TlsSessionState = Object.freeze({
      ...sessionState,
      sequenceCounter: nextSeq,
      commandsExecuted: sessionState.commandsExecuted + 1,
    });
    const entry: CommandLogEntry = Object.freeze({
      id: `cmd_${nextSeq}`,
      rawInput: trimmed,
      timestampIso,
      status: 'SUCCESS',
      outputLines: Object.freeze(outputLines),
      wireFrame,
    });
    return ok(
      Object.freeze({
        entry,
        nextFsState: updatedFsState,
        nextSessionState,
      })
    );
  };

  switch (cmd) {
    case 'sysinfo':
    case 'uptime':
      return makeSuccess(
        CommandOpcode.SysUptime,
        'SAC_OP_SYS_UPTIME',
        'sysinfo(&si) /* c_project/managers.c */',
        [
          '[SIMULATED UI OUTPUT — C11 server runs sysinfo(&si)]',
          'OK uptime=1233739s procs=142 freeram_mb=11420',
        ]
      );

    case 'uname':
      return makeSuccess(
        CommandOpcode.SysUname,
        'SAC_OP_SYS_UNAME',
        'uname(&uts) /* c_project/managers.c */',
        [
          '[SIMULATED UI OUTPUT — C11 server runs uname(&uts)]',
          'OK Linux sandbox-node 6.1.0-sec x86_64',
        ]
      );

    case 'df':
    case 'statvfs': {
      const cwdRel =
        fsState.currentDir === fsState.jailRoot
          ? '.'
          : fsState.currentDir.slice(fsState.jailRoot.length + 1);
      return makeSuccess(
        CommandOpcode.SysStatVfs,
        'SAC_OP_SYS_STATVFS',
        'fstatvfs(state.jail_dirfd, &vfs) /* c_project/managers.c */',
        [
          '[SIMULATED UI OUTPUT — C11 server runs fstatvfs(jail_dirfd, &vfs)]',
          `OK cwd=${cwdRel} free_mb=96870 bsize=4096`,
        ]
      );
    }

    case 'ls': {
      const targetDir = arg ? arg : '.';
      const cdResult = changeSandboxDirectory(fsState, targetDir);
      if (cdResult.tag === 'ERR') {
        return cdResult;
      }
      const children = selectCurrentDirectoryChildren({
        ...cdResult.value,
        searchQuery: '',
      });
      const lines = [
        `Directory listing for ${cdResult.value.currentDir} (resolved from cwd="${fsState.currentDir}"):`,
        ...children.map(
          (node) =>
            `  ${node.permissionsOctal}  ${
              node.type === FsNodeType.Directory
                ? 'DIR '
                : node.type === FsNodeType.Symlink
                  ? 'LINK'
                  : 'FILE'
            }  ${String(node.sizeBytes).padStart(6, ' ')} B  ${node.name}${
              node.type === FsNodeType.Symlink ? ` -> ${node.symlinkTarget}` : ''
            }`
        ),
      ];
      return makeSuccess(
        CommandOpcode.FsListDir,
        'SAC_OP_FS_LISTDIR',
        'sac_fs_list_dir(jail_dirfd, state.cwd_rel, arg) /* openat2 RESOLVE_BENEATH */',
        lines,
        fsState
      );
    }

    case 'cd': {
      const targetDir = arg || '.';
      const cdResult = changeSandboxDirectory(fsState, targetDir);
      if (cdResult.tag === 'ERR') {
        return cdResult;
      }
      const cwdRel =
        cdResult.value.currentDir === cdResult.value.jailRoot
          ? '.'
          : cdResult.value.currentDir.slice(cdResult.value.jailRoot.length + 1);
      return makeSuccess(
        CommandOpcode.FsChangeDir,
        'SAC_OP_FS_CHDIR',
        'sac_fs_chdir(jail_dirfd, state.cwd_rel, arg, next_cwd)',
        [`OK cwd=${cwdRel} (Full sandbox path: ${cdResult.value.currentDir})`],
        cdResult.value
      );
    }

    case 'cat': {
      if (!arg) {
        return err(
          createAppError({
            code: ErrorCode.FileNotFound,
            domain: ErrorDomain.Filesystem,
            severity: ErrorSeverity.Warning,
            title: 'Missing Filename Argument (SAC_FS_ERR_NOT_FOUND)',
            message: 'Command "cat" requires a relative or /srv/sandbox file path.',
            remediation:
              'Try "cat config/tls_policy.conf" or "cd reports" then "cat health_snapshot.txt".',
            contextInput: trimmed,
            timestampIso,
          })
        );
      }
      const readResult = readSandboxFile(fsState, arg);
      if (readResult.tag === 'ERR') {
        return readResult;
      }
      const { file, state: nextFs } = readResult.value;
      const lines = [
        `File: ${file.path} (${file.sizeBytes} bytes · FNV1a-64:${file.fnv1a64Hex})`,
        '------------------------------------------------------------',
        ...(file.content ?? '').split('\n'),
      ];
      return makeSuccess(
        CommandOpcode.FsReadFile,
        'SAC_OP_FS_READFILE',
        'sac_fs_read_file(jail_dirfd, state.cwd_rel, arg) /* openat2 RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS */',
        lines,
        nextFs
      );
    }

    default:
      return err(
        createAppError({
          code: ErrorCode.CommandNotAllowlisted,
          domain: ErrorDomain.Protocol,
          severity: ErrorSeverity.SecurityBlock,
          title: 'Opcode Rejected by Allowlist (SAC_ERR_BAD_OPCODE)',
          message: `Command "${cmd}" is not one of the 6 allowlisted opcodes in c_project/protocol.h. Arbitrary command execution is disabled.`,
          remediation:
            'Use only implemented C11 opcodes: sysinfo, uname, df, ls, cd, cat (or local "help").',
          cweReference: 'CWE-78',
          contextInput: trimmed,
          timestampIso,
        })
      );
  }
};
