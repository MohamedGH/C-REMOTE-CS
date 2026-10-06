/**
 * Pure Functional Sandboxed Virtual File System & realpath() Jail Engine
 * Simulates POSIX opendir/readdir/statat/openat(O_NOFOLLOW) strictly confined
 * to JAIL_ROOT = "/srv/sandbox". Blocks any CWE-22 path traversal attempts.
 */

import {
  AppError,
  createAppError,
  ErrorCode,
  ErrorSeverity,
} from './errorManager';
import { err, ok, Result } from './fp';

export const JAIL_ROOT = '/srv/sandbox';

export enum FsNodeType {
  Directory = 'DIRECTORY',
  File = 'FILE',
}

export interface VirtualFsNode {
  readonly path: string;
  readonly name: string;
  readonly parentPath: string | null;
  readonly type: FsNodeType;
  readonly permissionsOctal: string;
  readonly owner: string;
  readonly sizeBytes: number;
  readonly modifiedIso: string;
  readonly sha256Short: string;
  readonly content?: string;
}

export interface SandboxFsState {
  readonly jailRoot: string;
  readonly currentDir: string;
  readonly selectedFilePath: string | null;
  readonly searchQuery: string;
  readonly nodes: ReadonlyArray<VirtualFsNode>;
  readonly traversalAttemptsBlocked: number;
}

const computePseudoDigest = (text: string): string => {
  let h1 = 0xdeadbeef ^ text.length;
  let h2 = 0x41c6ce57 ^ text.length;
  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 =
    Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^
    Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 =
    Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^
    Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (
    (h2 >>> 0).toString(16).padStart(8, '0') +
    (h1 >>> 0).toString(16).padStart(8, '0')
  );
};

export const INITIAL_FS_NODES: ReadonlyArray<VirtualFsNode> = Object.freeze([
  Object.freeze({
    path: '/srv/sandbox',
    name: 'sandbox',
    parentPath: null,
    type: FsNodeType.Directory,
    permissionsOctal: '0750',
    owner: 'secadmin:secadmin',
    sizeBytes: 4096,
    modifiedIso: '2026-10-05T18:00:00Z',
    sha256Short: 'd4f1a90011b2c3d4',
  }),
  Object.freeze({
    path: '/srv/sandbox/config',
    name: 'config',
    parentPath: '/srv/sandbox',
    type: FsNodeType.Directory,
    permissionsOctal: '0750',
    owner: 'secadmin:secadmin',
    sizeBytes: 4096,
    modifiedIso: '2026-10-05T18:10:00Z',
    sha256Short: '88a12f09c441e821',
  }),
  Object.freeze({
    path: '/srv/sandbox/logs',
    name: 'logs',
    parentPath: '/srv/sandbox',
    type: FsNodeType.Directory,
    permissionsOctal: '0750',
    owner: 'secadmin:secadmin',
    sizeBytes: 4096,
    modifiedIso: '2026-10-06T00:15:00Z',
    sha256Short: '91b03e77a219d004',
  }),
  Object.freeze({
    path: '/srv/sandbox/reports',
    name: 'reports',
    parentPath: '/srv/sandbox',
    type: FsNodeType.Directory,
    permissionsOctal: '0750',
    owner: 'secadmin:secadmin',
    sizeBytes: 4096,
    modifiedIso: '2026-10-06T00:30:00Z',
    sha256Short: '3c4490ab1289ef01',
  }),
  Object.freeze({
    path: '/srv/sandbox/config/tls_policy.conf',
    name: 'tls_policy.conf',
    parentPath: '/srv/sandbox/config',
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: 418,
    modifiedIso: '2026-10-05T18:12:00Z',
    sha256Short: '7a9e02bc1940fa88',
    content: [
      '# SecAdminC Mutual TLS 1.3 Daemon Policy',
      'min_protocol_version = TLSv1.3',
      'ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
      'require_client_cert = true',
      'verify_depth = 2',
      'sandbox_chroot_dir = /srv/sandbox',
      'allow_shell_exec = false',
      'max_frame_payload_bytes = 16384',
    ].join('\n'),
  }),
  Object.freeze({
    path: '/srv/sandbox/config/allowlist_opcodes.json',
    name: 'allowlist_opcodes.json',
    parentPath: '/srv/sandbox/config',
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: 362,
    modifiedIso: '2026-10-05T19:00:00Z',
    sha256Short: 'c5109fe3a88412b0',
    content: JSON.stringify(
      {
        schemaVersion: 1,
        shellExecutionPermitted: false,
        allowedOpcodes: [
          { id: 1, name: 'OP_SYS_UPTIME', syscall: 'sysinfo(&info)' },
          { id: 2, name: 'OP_SYS_UNAME', syscall: 'uname(&uts)' },
          { id: 3, name: 'OP_SYS_STATVFS', syscall: 'statvfs("/srv/sandbox", &vfs)' },
          { id: 4, name: 'OP_FS_LISTDIR', syscall: 'openat(O_NOFOLLOW | O_DIRECTORY)' },
          { id: 5, name: 'OP_FS_READFILE', syscall: 'openat(O_RDONLY | O_NOFOLLOW)' },
        ],
      },
      null,
      2
    ),
  }),
  Object.freeze({
    path: '/srv/sandbox/logs/audit_daemon.log',
    name: 'audit_daemon.log',
    parentPath: '/srv/sandbox/logs',
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: 512,
    modifiedIso: '2026-10-06T00:42:10Z',
    sha256Short: 'e01948bc7721a439',
    content: [
      '2026-10-06T00:10:02Z [INFO] TLSv1.3 handshake verified (CN=admin-workstation-01, SHA256=9f86d08)',
      '2026-10-06T00:14:19Z [INFO] Dispatch OP_SYS_UNAME -> 0 (Linux 6.8.0-sec x86_64)',
      '2026-10-06T00:22:41Z [BLOCK] CWE-22 Path Traversal blocked: input="../../etc/shadow" resolved="/etc/shadow" outside "/srv/sandbox"',
      '2026-10-06T00:35:11Z [INFO] Dispatch OP_FS_LISTDIR -> "/srv/sandbox/reports" (2 entries)',
    ].join('\n'),
  }),
  Object.freeze({
    path: '/srv/sandbox/reports/health_snapshot.txt',
    name: 'health_snapshot.txt',
    parentPath: '/srv/sandbox/reports',
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: 294,
    modifiedIso: '2026-10-06T00:30:00Z',
    sha256Short: '4490ab1289ef0192',
    content: [
      'Node Hostname   : prod-edge-node-04.internal',
      'Kernel Release  : Linux 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC',
      'TLS Cipher      : TLS_AES_256_GCM_SHA384 (256-bit)',
      'Sandbox Root    : /srv/sandbox (chroot + O_NOFOLLOW active)',
      'Memory Free     : 11,420 MB / 16,384 MB',
    ].join('\n'),
  }),
]);

export const createInitialSandboxFsState = (): SandboxFsState =>
  Object.freeze({
    jailRoot: JAIL_ROOT,
    currentDir: JAIL_ROOT,
    selectedFilePath: '/srv/sandbox/config/tls_policy.conf',
    searchQuery: '',
    nodes: INITIAL_FS_NODES,
    traversalAttemptsBlocked: 0,
  });

/**
 * Pure POSIX-style path resolution with strict jail root containment check.
 * Simulates C11 realpath() + strncmp(resolved, JAIL_ROOT, strlen(JAIL_ROOT)).
 */
export const resolveSandboxedPath = (
  currentDir: string,
  requestedPath: string,
  jailRoot: string = JAIL_ROOT
): Result<string, AppError> => {
  const raw = requestedPath.trim();
  if (!raw) {
    return ok(currentDir);
  }

  // Detect null bytes or control characters immediately
  if (/[\x00-\x1f]/.test(raw) || raw.includes('\\')) {
    return err(
      createAppError({
        code: ErrorCode.PathTraversalBlocked,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Illegal Control or Backslash Character in Path',
        message: `Rejected path "${raw}" due to illegal characters before syscall invocation.`,
        remediation:
          'Use clean POSIX forward-slash relative or /srv/sandbox paths without backslashes or control bytes.',
        cweReference: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
        contextInput: raw,
      })
    );
  }

  const combined = raw.startsWith('/') ? raw : `${currentDir}/${raw}`;
  const segments = combined.split('/');
  const resolvedStack: string[] = [];

  for (const segment of segments) {
    if (!segment || segment === '.') {
      continue;
    }
    if (segment === '..') {
      resolvedStack.pop();
    } else {
      resolvedStack.push(segment);
    }
  }

  const canonicalPath = '/' + resolvedStack.join('/');

  const isInsideJail =
    canonicalPath === jailRoot || canonicalPath.startsWith(`${jailRoot}/`);

  if (!isInsideJail) {
    return err(
      createAppError({
        code: ErrorCode.PathTraversalBlocked,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Sandbox Jail Escape Blocked (CWE-22)',
        message: `Canonicalized path "${canonicalPath}" escapes sandbox root "${jailRoot}". In C11 server, strncmp(resolved, JAIL_ROOT, strlen(JAIL_ROOT)) rejected the request.`,
        remediation: `Keep all file requests strictly inside ${jailRoot}. Relative parent segments (..) that ascend above the jail root are forbidden.`,
        cweReference: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
        contextInput: requestedPath,
      })
    );
  }

  return ok(canonicalPath);
};

export const changeSandboxDirectory = (
  state: SandboxFsState,
  targetPathInput: string
): Result<SandboxFsState, AppError> => {
  const resolvedResult = resolveSandboxedPath(
    state.currentDir,
    targetPathInput,
    state.jailRoot
  );
  if (resolvedResult.tag === 'ERR') {
    return resolvedResult;
  }

  const targetPath = resolvedResult.value;
  const node = state.nodes.find((n) => n.path === targetPath);

  if (!node) {
    return err(
      createAppError({
        code: ErrorCode.FileNotFound,
        severity: ErrorSeverity.Warning,
        title: 'Directory Not Found (ENOENT)',
        message: `Path "${targetPath}" does not exist inside the sandboxed virtual filesystem.`,
        remediation: 'Verify the directory name or use the directory breadcrumb navigation.',
        contextInput: targetPathInput,
      })
    );
  }

  if (node.type !== FsNodeType.Directory) {
    return err(
      createAppError({
        code: ErrorCode.NotADirectory,
        severity: ErrorSeverity.Warning,
        title: 'Target Is Not a Directory (ENOTDIR)',
        message: `Path "${targetPath}" is a regular file, not a directory.`,
        remediation: 'Select the file to inspect its contents instead of changing directory into it.',
        contextInput: targetPathInput,
      })
    );
  }

  return ok(
    Object.freeze({
      ...state,
      currentDir: targetPath,
    })
  );
};

export const readSandboxFile = (
  state: SandboxFsState,
  targetPathInput: string
): Result<{ readonly state: SandboxFsState; readonly file: VirtualFsNode }, AppError> => {
  const resolvedResult = resolveSandboxedPath(
    state.currentDir,
    targetPathInput,
    state.jailRoot
  );
  if (resolvedResult.tag === 'ERR') {
    return resolvedResult;
  }

  const targetPath = resolvedResult.value;
  const node = state.nodes.find((n) => n.path === targetPath);

  if (!node) {
    return err(
      createAppError({
        code: ErrorCode.FileNotFound,
        severity: ErrorSeverity.Warning,
        title: 'File Not Found (ENOENT)',
        message: `File "${targetPath}" was not found inside ${state.jailRoot}.`,
        remediation: 'Select an existing file in the sandboxed directory list.',
        contextInput: targetPathInput,
      })
    );
  }

  if (node.type !== FsNodeType.File) {
    return err(
      createAppError({
        code: ErrorCode.NotADirectory,
        severity: ErrorSeverity.Warning,
        title: 'Cannot Read Directory as File (EISDIR)',
        message: `Path "${targetPath}" is a directory.`,
        remediation: 'Navigate into the directory to view its entries.',
        contextInput: targetPathInput,
      })
    );
  }

  return ok(
    Object.freeze({
      state: Object.freeze({
        ...state,
        selectedFilePath: targetPath,
      }),
      file: node,
    })
  );
};

export const createSandboxAuditNote = (
  state: SandboxFsState,
  fileNameInput: string,
  contentInput: string
): Result<SandboxFsState, AppError> => {
  const cleanName = fileNameInput.trim();
  if (!/^[a-zA-Z0-9._-]{1,48}$/.test(cleanName) || cleanName === '..' || cleanName === '.') {
    return err(
      createAppError({
        code: ErrorCode.InvalidFilename,
        severity: ErrorSeverity.Warning,
        title: 'Invalid Sandboxed Filename',
        message: `Filename "${cleanName}" must contain only alphanumeric characters, dots, hyphens, or underscores (1–48 chars).`,
        remediation: 'Provide a simple filename such as "audit_note.txt" without path separators.',
        contextInput: fileNameInput,
      })
    );
  }

  const fullPath = `${state.currentDir}/${cleanName}`;
  const resolvedCheck = resolveSandboxedPath(state.currentDir, fullPath, state.jailRoot);
  if (resolvedCheck.tag === 'ERR') {
    return resolvedCheck;
  }

  const normalizedContent = contentInput.slice(0, 4096);
  const newNode: VirtualFsNode = Object.freeze({
    path: resolvedCheck.value,
    name: cleanName,
    parentPath: state.currentDir,
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: normalizedContent.length,
    modifiedIso: new Date().toISOString(),
    sha256Short: computePseudoDigest(normalizedContent),
    content: normalizedContent,
  });

  const filteredNodes = state.nodes.filter((n) => n.path !== newNode.path);
  return ok(
    Object.freeze({
      ...state,
      selectedFilePath: newNode.path,
      nodes: Object.freeze([...filteredNodes, newNode]),
    })
  );
};

export const selectCurrentDirectoryChildren = (
  state: SandboxFsState
): ReadonlyArray<VirtualFsNode> => {
  const query = state.searchQuery.trim().toLowerCase();
  return state.nodes
    .filter((node) => {
      if (query) {
        return (
          node.path !== state.jailRoot &&
          (node.name.toLowerCase().includes(query) ||
            node.path.toLowerCase().includes(query))
        );
      }
      return node.parentPath === state.currentDir;
    })
    .slice()
    .sort((a, b) => {
      if (a.type !== b.type) {
        return a.type === FsNodeType.Directory ? -1 : 1;
      }
      return a.name.localeCompare(b.name);
    });
};

export const selectSelectedFileNode = (
  state: SandboxFsState
): VirtualFsNode | null =>
  state.selectedFilePath
    ? state.nodes.find((n) => n.path === state.selectedFilePath) ?? null
    : null;
