/**
 * Pure Functional Simulated Virtual File System (Browser UI Demonstrator)
 *
 * Honesty & Architecture Note:
 * - In the browser UI, this module simulates an in-memory directory tree rooted at
 *   "/srv/sandbox" to demonstrate how `cwd_rel`, path normalization, symlink blocking,
 *   and granular `sac_fs_status_t` errors behave.
 * - In the real C11 implementation (`c_project/sandbox_fs.c`), confinement is enforced
 *   at the OS level via an open `jail_dirfd` using Linux `openat2(RESOLVE_BENEATH |
 *   RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` with a documented
 *   component-by-component `openat(O_NOFOLLOW | O_CLOEXEC)` fallback.
 * - Checksums displayed in this in-memory UI are 64-bit FNV-1a non-cryptographic
 *   content checksums (`fnv1a64Hex`), never labeled as SHA-256.
 */

import {
  AppError,
  createAppError,
  ErrorCode,
  ErrorDomain,
  ErrorSeverity,
} from './errorManager';
import { err, ok, Result } from './fp';

export const JAIL_ROOT = '/srv/sandbox';

export enum FsNodeType {
  Directory = 'DIRECTORY',
  File = 'FILE',
  Symlink = 'SYMLINK',
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
  readonly fnv1a64Hex: string;
  readonly symlinkTarget?: string;
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

/**
 * Computes a 64-bit FNV-1a non-cryptographic checksum (16 hex chars) for UI file preview.
 * Explicitly named `computeFnv1a64Hex` to avoid any confusion with SHA-256.
 */
export const computeFnv1a64Hex = (text: string): string => {
  let h1 = 0x811c9dc5 >>> 0;
  let h2 = 0xcbf29ce4 >>> 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ ((ch << 3) | (ch >>> 5)), 0x01000193) >>> 0;
  }
  return (
    h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0')
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
    fnv1a64Hex: '811c9dc5cbf29ce4',
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
    fnv1a64Hex: '88a12f09c441e821',
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
    fnv1a64Hex: '91b03e77a219d004',
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
    fnv1a64Hex: '3c4490ab1289ef01',
  }),
  Object.freeze({
    path: '/srv/sandbox/config/tls_policy.conf',
    name: 'tls_policy.conf',
    parentPath: '/srv/sandbox/config',
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: 432,
    modifiedIso: '2026-10-05T18:12:00Z',
    fnv1a64Hex: computeFnv1a64Hex('tls_policy.conf'),
    content: [
      '# SecAdminC Mutual TLS 1.3 Daemon Policy (c_project/tls_helpers.c)',
      'min_protocol_version = TLSv1.3',
      'ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
      'require_client_cert = true (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT)',
      'client_san_verification = true (SSL_set1_host / X509_VERIFY_PARAM_set1_ip_asc)',
      'sandbox_jail_dir = /srv/sandbox (openat2 RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)',
      'allow_shell_exec = false',
      'max_request_path_bytes = 256',
      'max_response_payload_bytes = 4096',
    ].join('\n'),
  }),
  Object.freeze({
    path: '/srv/sandbox/config/allowlist_opcodes.json',
    name: 'allowlist_opcodes.json',
    parentPath: '/srv/sandbox/config',
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: 486,
    modifiedIso: '2026-10-05T19:00:00Z',
    fnv1a64Hex: computeFnv1a64Hex('allowlist_opcodes.json'),
    content: JSON.stringify(
      {
        headerFile: 'c_project/protocol.h',
        shellExecutionPermitted: false,
        implementedC11Opcodes: [
          { hex: '0x01', name: 'SAC_OP_SYS_UPTIME', cSyscall: 'sysinfo(&si)' },
          { hex: '0x02', name: 'SAC_OP_SYS_UNAME', cSyscall: 'uname(&uts)' },
          { hex: '0x03', name: 'SAC_OP_SYS_STATVFS', cSyscall: 'fstatvfs(jail_dirfd, &vfs)' },
          { hex: '0x10', name: 'SAC_OP_FS_LISTDIR', cSyscall: 'sac_fs_list_dir(jail_dirfd, cwd_rel, arg)' },
          { hex: '0x11', name: 'SAC_OP_FS_READFILE', cSyscall: 'sac_fs_read_file(jail_dirfd, cwd_rel, arg)' },
          { hex: '0x12', name: 'SAC_OP_FS_CHDIR', cSyscall: 'sac_fs_chdir(jail_dirfd, cwd_rel, arg)' },
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
    sizeBytes: 498,
    modifiedIso: '2026-10-06T00:42:10Z',
    fnv1a64Hex: computeFnv1a64Hex('audit_daemon.log'),
    content: [
      '[SIMULATED DEMO LOG — Matches c_project/managers.c format]',
      '2026-10-06T00:10:02Z [INFO] TLSv1.3 mTLS session initialized (jail_dirfd=3, cwd_rel=".")',
      '2026-10-06T00:14:19Z [INFO] Dispatch SAC_OP_SYS_UNAME (seq=1) -> SAC_OK',
      '2026-10-06T00:22:41Z [BLOCK] domain=FILESYSTEM fs_status=SAC_FS_ERR_PATH_ESCAPE input="../../etc/shadow"',
      '2026-10-06T00:35:11Z [INFO] Dispatch SAC_OP_FS_CHDIR (seq=2) -> cwd_rel="reports"',
    ].join('\n'),
  }),
  Object.freeze({
    path: '/srv/sandbox/reports/health_snapshot.txt',
    name: 'health_snapshot.txt',
    parentPath: '/srv/sandbox/reports',
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: 312,
    modifiedIso: '2026-10-06T00:30:00Z',
    fnv1a64Hex: computeFnv1a64Hex('health_snapshot.txt'),
    content: [
      'Sample Report Node : simulated-sandbox-node',
      'Confinement Model  : Linux openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)',
      'Fallback Model     : Stepwise openat(O_NOFOLLOW | O_CLOEXEC) depth>=0 walker',
      'TLS Protocol Floor : TLSv1.3 with mandatory client & server SAN verification',
    ].join('\n'),
  }),
  Object.freeze({
    path: '/srv/sandbox/reports/restricted_key_backup.txt',
    name: 'restricted_key_backup.txt',
    parentPath: '/srv/sandbox/reports',
    type: FsNodeType.File,
    permissionsOctal: '0000',
    owner: 'root:root',
    sizeBytes: 64,
    modifiedIso: '2026-10-06T00:31:00Z',
    fnv1a64Hex: '0000000000000000',
    content: '',
  }),
  Object.freeze({
    path: '/srv/sandbox/logs/symlink_escape_test',
    name: 'symlink_escape_test',
    parentPath: '/srv/sandbox/logs',
    type: FsNodeType.Symlink,
    permissionsOctal: '0777',
    owner: 'secadmin:secadmin',
    sizeBytes: 11,
    modifiedIso: '2026-10-06T00:32:00Z',
    fnv1a64Hex: '0000000000000000',
    symlinkTarget: '/etc/passwd',
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
 * Pure depth-checked relative path resolver modeling `normalize_jail_relative_path()`
 * in `c_project/sandbox_fs.c`.
 * Rejects any `..` segment that ascends above `jailRoot` (depth < 0) rather than
 * silently clamping `..` at root.
 */
export const resolveSandboxedPath = (
  currentDir: string,
  requestedPath: string,
  jailRoot: string = JAIL_ROOT
): Result<string, AppError> => {
  const raw = requestedPath.trim();
  if (!raw || raw === '.') {
    return ok(currentDir);
  }

  if (/[\x00-\x1f\x7f]/.test(raw) || raw.includes('\\')) {
    return err(
      createAppError({
        code: ErrorCode.PathTraversalBlocked,
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Illegal Control or Backslash Character (SAC_FS_ERR_PATH_ESCAPE)',
        message: `Rejected path "${raw}" due to backslash or control byte before descriptor lookup.`,
        remediation:
          'Use clean POSIX forward-slash relative paths inside /srv/sandbox.',
        cweReference: 'CWE-22',
        contextInput: raw,
      })
    );
  }

  let relativeCombined: string;
  if (raw.startsWith('/')) {
    if (raw === jailRoot || raw.startsWith(`${jailRoot}/`)) {
      relativeCombined = raw.slice(jailRoot.length).replace(/^\/+/, '');
    } else {
      return err(
        createAppError({
          code: ErrorCode.PathTraversalBlocked,
          domain: ErrorDomain.Filesystem,
          severity: ErrorSeverity.SecurityBlock,
          title: 'Absolute Path Outside Jail Blocked (SAC_FS_ERR_PATH_ESCAPE)',
          message: `Path "${raw}" points outside jail root "${jailRoot}". In C11 sandbox_fs.c, openat2(RESOLVE_BENEATH) and normalize_jail_relative_path() reject external absolute paths.`,
          remediation: `Specify a path relative to ${currentDir} or inside ${jailRoot}.`,
          cweReference: 'CWE-22',
          contextInput: requestedPath,
        })
      );
    }
  } else {
    const cwdRel =
      currentDir === jailRoot
        ? ''
        : currentDir.slice(jailRoot.length).replace(/^\/+/, '');
    relativeCombined = cwdRel ? `${cwdRel}/${raw}` : raw;
  }

  const segments = relativeCombined.split('/');
  const stack: string[] = [];

  for (const seg of segments) {
    if (!seg || seg === '.') {
      continue;
    }
    if (seg === '..') {
      if (stack.length === 0) {
        return err(
          createAppError({
            code: ErrorCode.PathTraversalBlocked,
            domain: ErrorDomain.Filesystem,
            severity: ErrorSeverity.SecurityBlock,
            title: 'Sandbox Jail Escape Blocked (SAC_FS_ERR_PATH_ESCAPE)',
            message: `Relative traversal "${requestedPath}" from "${currentDir}" ascends above jail root "${jailRoot}" (depth < 0). Blocked by RESOLVE_BENEATH / depth counter.`,
            remediation: `Do not use ".." segments that ascend above ${jailRoot}.`,
            cweReference: 'CWE-22',
            contextInput: requestedPath,
          })
        );
      }
      stack.pop();
    } else {
      stack.push(seg);
    }
  }

  const canonical =
    stack.length === 0 ? jailRoot : `${jailRoot}/${stack.join('/')}`;
  return ok(canonical);
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
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.Warning,
        title: 'Directory Not Found (SAC_FS_ERR_NOT_FOUND)',
        message: `Path "${targetPath}" does not exist inside ${state.jailRoot}.`,
        remediation: 'Verify the directory name or use the directory table.',
        contextInput: targetPathInput,
      })
    );
  }

  if (node.type === FsNodeType.Symlink) {
    return err(
      createAppError({
        code: ErrorCode.PathTraversalBlocked,
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Symlink Traversal Blocked (SAC_FS_ERR_PATH_ESCAPE)',
        message: `Target "${targetPath}" is a symbolic link (-> ${node.symlinkTarget}). Blocked by RESOLVE_NO_SYMLINKS / O_NOFOLLOW.`,
        remediation: 'Access regular directories and files directly; symlinks are forbidden inside the sandbox.',
        cweReference: 'CWE-22',
        contextInput: targetPathInput,
      })
    );
  }

  if (node.type !== FsNodeType.Directory) {
    return err(
      createAppError({
        code: ErrorCode.NotADirectory,
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.Warning,
        title: 'Target Is Not a Directory (SAC_FS_ERR_NOT_DIR)',
        message: `Path "${targetPath}" is a regular file, not a directory.`,
        remediation: 'Use "cat" or click the file row to read regular files.',
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
): Result<
  { readonly state: SandboxFsState; readonly file: VirtualFsNode },
  AppError
> => {
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
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.Warning,
        title: 'File Not Found (SAC_FS_ERR_NOT_FOUND)',
        message: `File "${targetPath}" (resolved from working dir "${state.currentDir}") does not exist.`,
        remediation: 'Verify the filename or check the current working directory.',
        contextInput: targetPathInput,
      })
    );
  }

  if (node.type === FsNodeType.Symlink) {
    return err(
      createAppError({
        code: ErrorCode.PathTraversalBlocked,
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Symlink Escape Blocked (SAC_FS_ERR_PATH_ESCAPE)',
        message: `Entry "${node.name}" is a symbolic link pointing to "${node.symlinkTarget}". Blocked by openat2(RESOLVE_NO_SYMLINKS) / openat(O_NOFOLLOW).`,
        remediation: 'Symbolic links are strictly forbidden in the sandbox.',
        cweReference: 'CWE-22',
        contextInput: targetPathInput,
      })
    );
  }

  if (node.type === FsNodeType.Directory) {
    return err(
      createAppError({
        code: ErrorCode.NotARegularFile,
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.Warning,
        title: 'Cannot Read Directory as Regular File (SAC_FS_ERR_NOT_REGULAR)',
        message: `Path "${targetPath}" is a directory (!S_ISREG(sb.st_mode)).`,
        remediation: 'Use "ls" or click the directory to list its entries.',
        contextInput: targetPathInput,
      })
    );
  }

  if (node.permissionsOctal === '0000') {
    return err(
      createAppError({
        code: ErrorCode.PermissionDenied,
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.SecurityBlock,
        title: 'Permission Denied (SAC_FS_ERR_PERMISSION_DENIED)',
        message: `File "${targetPath}" has mode ${node.permissionsOctal} (${node.owner}) and returned EACCES.`,
        remediation: 'Only files readable by the unprivileged daemon UID can be accessed.',
        cweReference: 'CWE-285',
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
  if (
    !/^[a-zA-Z0-9._-]{1,48}$/.test(cleanName) ||
    cleanName === '..' ||
    cleanName === '.'
  ) {
    return err(
      createAppError({
        code: ErrorCode.InvalidFilename,
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.Warning,
        title: 'Invalid Sandboxed Filename',
        message: `Filename "${cleanName}" must contain only alphanumeric characters, dots, hyphens, or underscores (1–48 chars).`,
        remediation:
          'Provide a simple filename such as "audit_note.txt" without path separators.',
        contextInput: fileNameInput,
      })
    );
  }

  if (contentInput.length >= 4096) {
    return err(
      createAppError({
        code: ErrorCode.BufferTooSmall,
        domain: ErrorDomain.Filesystem,
        severity: ErrorSeverity.Warning,
        title: 'Payload Exceeds SAC_MAX_PAYLOAD_LEN (SAC_FS_ERR_BUFFER_TOO_SMALL)',
        message: `Content length (${contentInput.length} B) exceeds the 4096-byte buffer cap.`,
        remediation: 'Keep note content under 4,095 bytes.',
        contextInput: fileNameInput,
      })
    );
  }

  const fullPath = `${state.currentDir}/${cleanName}`;
  const resolvedCheck = resolveSandboxedPath(
    state.currentDir,
    fullPath,
    state.jailRoot
  );
  if (resolvedCheck.tag === 'ERR') {
    return resolvedCheck;
  }

  const newNode: VirtualFsNode = Object.freeze({
    path: resolvedCheck.value,
    name: cleanName,
    parentPath: state.currentDir,
    type: FsNodeType.File,
    permissionsOctal: '0640',
    owner: 'secadmin:secadmin',
    sizeBytes: contentInput.length,
    modifiedIso: new Date().toISOString(),
    fnv1a64Hex: computeFnv1a64Hex(contentInput),
    content: contentInput,
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
