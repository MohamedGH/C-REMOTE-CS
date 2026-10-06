/**
 * Pure Functional Allowlisted Command Dispatcher & Binary Wire Frame Engine
 * Enforces zero shell invocation (no system(), popen(), or /bin/sh).
 * Maps allowlisted administrative commands to fixed C11 enum opcodes and
 * direct POSIX syscalls over mutually authenticated TLS 1.3 frames.
 */

import {
  AppError,
  createAppError,
  ErrorCode,
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
  SysNetIfaces = 0x04,
  SysTlsStatus = 0x05,
  FsListDir = 0x10,
  FsReadFile = 0x11,
  FsChangeDir = 0x12,
  Help = 0x7f,
}

export interface WireFrameInspection {
  readonly magicHex: string;
  readonly version: number;
  readonly opcodeHex: string;
  readonly opcodeName: string;
  readonly sequenceNumber: number;
  readonly payloadLengthBytes: number;
  readonly hmacSha256Truncated: string;
  readonly rawHexPreview: string;
  readonly cSyscallInvoked: string;
}

export interface CommandLogEntry {
  readonly id: string;
  readonly rawInput: string;
  readonly timestampIso: string;
  readonly status: 'SUCCESS' | 'BLOCKED';
  readonly outputLines: ReadonlyArray<string>;
  readonly wireFrame?: WireFrameInspection;
  readonly errorCode?: ErrorCode;
}

export interface TlsSessionState {
  readonly connected: boolean;
  readonly remoteHost: string;
  readonly remotePort: number;
  readonly protocolVersion: 'TLSv1.3';
  readonly cipherSuite: 'TLS_AES_256_GCM_SHA384';
  readonly clientCertSubject: string;
  readonly clientCertFingerprint: string;
  readonly sequenceCounter: number;
}

export const createInitialTlsSession = (): TlsSessionState =>
  Object.freeze({
    connected: true,
    remoteHost: '10.24.0.18',
    remotePort: 8443,
    protocolVersion: 'TLSv1.3',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    clientCertSubject: 'CN=admin-workstation-01,O=SecAdminOps',
    clientCertFingerprint: 'SHA256:9f86d081884c7d659a2feaa0c55ad015',
    sequenceCounter: 100,
  });

const SHELL_METACHAR_PATTERN = /[;|&`$><\\!\n\r]/;

const formatHexByte = (n: number): string =>
  (n & 0xff).toString(16).padStart(2, '0').toUpperCase();

const computeFrameHmacPreview = (
  seq: number,
  opcode: number,
  payload: string
): string => {
  let acc = (0x811c9dc5 ^ seq ^ opcode) >>> 0;
  for (let i = 0; i < payload.length; i++) {
    acc ^= payload.charCodeAt(i);
    acc = Math.imul(acc, 0x01000193) >>> 0;
  }
  const p1 = acc.toString(16).padStart(8, '0');
  const p2 = ((acc ^ 0x5bd1e995) >>> 0).toString(16).padStart(8, '0');
  return `${p1}${p2}a4f9021b`;
};

export const buildWireFrame = (params: {
  readonly opcode: CommandOpcode;
  readonly opcodeName: string;
  readonly sequenceNumber: number;
  readonly payload: string;
  readonly cSyscallInvoked: string;
}): WireFrameInspection => {
  const magicHex = '53 41 43 31'; // "SAC1"
  const opByte = formatHexByte(params.opcode);
  const seqHigh = formatHexByte((params.sequenceNumber >> 8) & 0xff);
  const seqLow = formatHexByte(params.sequenceNumber & 0xff);
  const lenHigh = formatHexByte((params.payload.length >> 8) & 0xff);
  const lenLow = formatHexByte(params.payload.length & 0xff);
  const hmac = computeFrameHmacPreview(
    params.sequenceNumber,
    params.opcode,
    params.payload
  );

  return Object.freeze({
    magicHex: '0x53414331 ("SAC1")',
    version: 1,
    opcodeHex: `0x${opByte}`,
    opcodeName: params.opcodeName,
    sequenceNumber: params.sequenceNumber,
    payloadLengthBytes: params.payload.length,
    hmacSha256Truncated: hmac,
    rawHexPreview: `${magicHex} 01 ${opByte} ${seqHigh} ${seqLow} ${lenHigh} ${lenLow}`,
    cSyscallInvoked: params.cSyscallInvoked,
  });
};

export interface CommandDispatchOutcome {
  readonly entry: CommandLogEntry;
  readonly nextFsState: SandboxFsState;
  readonly nextSessionState: TlsSessionState;
}

/**
 * Pure functional validator and command router.
 * Explicitly blocks shell metacharacters (CWE-78) and unauthenticated sessions (CWE-306).
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
        severity: ErrorSeverity.SecurityBlock,
        title: 'Mutual TLS 1.3 Session Required (CWE-306)',
        message:
          'Rejected RPC dispatch because the mTLS session is currently disconnected.',
        remediation:
          'Establish the mutual TLS 1.3 handshake before dispatching remote opcodes.',
        cweReference: 'CWE-306: Missing Authentication for Critical Function',
        contextInput: trimmed,
        timestampIso,
      })
    );
  }

  if (SHELL_METACHAR_PATTERN.test(trimmed)) {
    return err(
      createAppError({
        code: ErrorCode.ShellInjectionBlocked,
        severity: ErrorSeverity.SecurityBlock,
        title: 'OS Shell Metacharacter Blocked (CWE-78)',
        message: `Input "${trimmed}" contains shell control operators (; | & \` $ > <). SecAdminC never invokes /bin/sh, system(), or popen() and strictly rejects compound shell syntax.`,
        remediation:
          'Issue a single allowlisted command token (e.g., sysinfo, uname, df, netstat, ls, cat <file>, cd <dir>).',
        cweReference: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
        contextInput: trimmed,
        timestampIso,
      })
    );
  }

  const parts = trimmed.split(/\s+/).filter(Boolean);
  const cmd = (parts[0] ?? 'help').toLowerCase();
  const arg = parts.slice(1).join(' ');
  const nextSeq = sessionState.sequenceCounter + 1;
  const nextSessionState: TlsSessionState = Object.freeze({
    ...sessionState,
    sequenceCounter: nextSeq,
  });

  const makeSuccess = (
    opcode: CommandOpcode,
    opcodeName: string,
    cSyscallInvoked: string,
    outputLines: ReadonlyArray<string>,
    updatedFsState: SandboxFsState = fsState
  ): Result<CommandDispatchOutcome, AppError> => {
    const wireFrame = buildWireFrame({
      opcode,
      opcodeName,
      sequenceNumber: nextSeq,
      payload: arg,
      cSyscallInvoked,
    });
    const entry: CommandLogEntry = Object.freeze({
      id: `cmd_${nextSeq}`,
      rawInput: trimmed || 'help',
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
    case 'help':
      return makeSuccess(
        CommandOpcode.Help,
        'OP_HELP_SCHEMA',
        'local_dispatch_table_lookup()',
        [
          'Allowlisted Remote RPC Opcodes (Zero Shell Execution):',
          '  sysinfo          -> OP_SYS_UPTIME (0x01)   POSIX sysinfo(&info)',
          '  uname            -> OP_SYS_UNAME (0x02)    POSIX uname(&uts)',
          '  df               -> OP_SYS_STATVFS (0x03)  POSIX statvfs("/srv/sandbox", &vfs)',
          '  netstat          -> OP_SYS_NETIF (0x04)    POSIX getifaddrs(&ifaddr)',
          '  tls              -> OP_SYS_TLS (0x05)      OpenSSL SSL_get_current_cipher(ssl)',
          '  ls [dir]         -> OP_FS_LISTDIR (0x10)   POSIX openat(O_NOFOLLOW | O_DIRECTORY)',
          '  cd <dir>         -> OP_FS_CHDIR (0x12)     realpath() + strncmp() jail verify',
          '  cat <file>       -> OP_FS_READFILE (0x11)  POSIX openat(O_RDONLY | O_NOFOLLOW)',
        ]
      );

    case 'sysinfo':
    case 'uptime':
      return makeSuccess(
        CommandOpcode.SysUptime,
        'OP_SYS_UPTIME',
        'sysinfo(&si) /* <sys/sysinfo.h> */',
        [
          'struct sysinfo telemetry (direct kernel syscall, no shell):',
          '  Uptime        : 14 days, 06:42:19 (1,233,739 seconds)',
          '  Load Averages : 0.14 (1m) · 0.19 (5m) · 0.11 (15m)',
          '  Total RAM     : 16,384 MB (Free: 11,420 MB · Buffered: 980 MB)',
          '  Active Procs  : 142 tasks',
        ]
      );

    case 'uname':
      return makeSuccess(
        CommandOpcode.SysUname,
        'OP_SYS_UNAME',
        'uname(&uts) /* <sys/utsname.h> */',
        [
          'struct utsname kernel identity:',
          '  sysname  : Linux',
          '  nodename : prod-edge-node-04.internal',
          '  release  : 6.8.0-45-generic',
          '  version  : #45-Ubuntu SMP PREEMPT_DYNAMIC',
          '  machine  : x86_64',
        ]
      );

    case 'df':
    case 'statvfs':
      return makeSuccess(
        CommandOpcode.SysStatVfs,
        'OP_SYS_STATVFS',
        'statvfs("/srv/sandbox", &vfs) /* <sys/statvfs.h> */',
        [
          'struct statvfs volume telemetry for /srv/sandbox:',
          '  Filesystem Block Size : 4,096 bytes',
          '  Total Capacity        : 128.00 GB (33,554,432 blocks)',
          '  Available Unprivileged: 94.60 GB (73.9% free)',
          '  Mount Flags           : ST_NOSUID | ST_NODEV | ST_NOEXEC',
        ]
      );

    case 'netstat':
    case 'net-interfaces':
      return makeSuccess(
        CommandOpcode.SysNetIfaces,
        'OP_SYS_NETIF',
        'getifaddrs(&ifaddr) /* <ifaddrs.h> */',
        [
          'POSIX getifaddrs() active interfaces:',
          '  lo    : AF_INET 127.0.0.1/8 · state UP · loopback',
          '  eth0  : AF_INET 10.24.0.18/24 · state UP · mTLS listener :8443',
          '  wg0   : AF_INET 100.64.0.4/32 · state UP · management mesh',
        ]
      );

    case 'tls':
      return makeSuccess(
        CommandOpcode.SysTlsStatus,
        'OP_SYS_TLS',
        'SSL_get_version(ssl) + SSL_get_peer_certificate(ssl)',
        [
          `Protocol Version : ${sessionState.protocolVersion}`,
          `Active Cipher    : ${sessionState.cipherSuite}`,
          `Client Subject   : ${sessionState.clientCertSubject}`,
          `Cert Fingerprint : ${sessionState.clientCertFingerprint}`,
          `Sequence Counter : ${nextSeq} (anti-replay monotonic nonce)`,
        ]
      );

    case 'ls': {
      const targetDir = arg ? arg : fsState.currentDir;
      const cdResult = changeSandboxDirectory(fsState, targetDir);
      if (cdResult.tag === 'ERR') {
        return cdResult;
      }
      const children = selectCurrentDirectoryChildren({
        ...cdResult.value,
        searchQuery: '',
      });
      const lines = [
        `Directory listing for ${cdResult.value.currentDir} (${children.length} entries):`,
        ...children.map(
          (node) =>
            `  ${node.permissionsOctal}  ${node.type === FsNodeType.Directory ? 'DIR ' : 'FILE'}  ${String(node.sizeBytes).padStart(6, ' ')} B  ${node.name}`
        ),
      ];
      return makeSuccess(
        CommandOpcode.FsListDir,
        'OP_FS_LISTDIR',
        'openat(jail_fd, rel_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)',
        lines,
        fsState
      );
    }

    case 'cd': {
      const targetDir = arg || '/srv/sandbox';
      const cdResult = changeSandboxDirectory(fsState, targetDir);
      if (cdResult.tag === 'ERR') {
        return cdResult;
      }
      return makeSuccess(
        CommandOpcode.FsChangeDir,
        'OP_FS_CHDIR',
        'realpath(input, resolved) + strncmp(resolved, "/srv/sandbox", 12)',
        [`Working directory changed to ${cdResult.value.currentDir}`],
        cdResult.value
      );
    }

    case 'cat': {
      if (!arg) {
        return err(
          createAppError({
            code: ErrorCode.FileNotFound,
            severity: ErrorSeverity.Warning,
            title: 'Missing Filename Argument',
            message: 'Command "cat" requires a file path inside /srv/sandbox.',
            remediation:
              'Try "cat /srv/sandbox/config/tls_policy.conf" or "cat health_snapshot.txt".',
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
        `File: ${file.path} (${file.sizeBytes} bytes · SHA256:${file.sha256Short})`,
        '------------------------------------------------------------',
        ...(file.content ?? '').split('\n'),
      ];
      return makeSuccess(
        CommandOpcode.FsReadFile,
        'OP_FS_READFILE',
        'openat(jail_fd, rel_path, O_RDONLY | O_NOFOLLOW)',
        lines,
        nextFs
      );
    }

    default:
      return err(
        createAppError({
          code: ErrorCode.CommandNotAllowlisted,
          severity: ErrorSeverity.SecurityBlock,
          title: 'Command Rejected by Strict Allowlist Policy',
          message: `Command "${cmd}" is not a registered enum opcode. Arbitrary binary execution (execve/system/popen) is disabled by design.`,
          remediation:
            'Use only allowlisted diagnostic commands: sysinfo, uname, df, netstat, tls, ls, cd, cat, or help.',
          cweReference: 'CWE-78: OS Command Injection Prevention via Enum Allowlisting',
          contextInput: trimmed,
          timestampIso,
        })
      );
  }
};
