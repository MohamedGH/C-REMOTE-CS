/**
 * C11 + POSIX + OpenSSL 3.x Architecture Registry & Honest Static Heuristic Scanner
 *
 * Synchronized directly with `/c_project/*` via Vite `?raw` imports so the
 * browser UI, static heuristic checks, and downloadable bundle always reflect
 * the exact C11 source files compiled by `make -C c_project all test`.
 */

import protocolH from '../../c_project/protocol.h?raw';
import ioFramingC from '../../c_project/io_framing.c?raw';
import sandboxFsC from '../../c_project/sandbox_fs.c?raw';
import managersC from '../../c_project/managers.c?raw';
import tlsHelpersH from '../../c_project/tls_helpers.h?raw';
import tlsHelpersC from '../../c_project/tls_helpers.c?raw';
import tlsServerC from '../../c_project/tls_server.c?raw';
import tlsClientC from '../../c_project/tls_client.c?raw';
import testSuiteC from '../../c_project/test_suite.c?raw';
import makefileRaw from '../../c_project/Makefile?raw';

export interface CSourceFile {
  readonly filename: string;
  readonly title: string;
  readonly role:
    | 'Header'
    | 'Framing'
    | 'SandboxFS'
    | 'Managers'
    | 'TLSHelpers'
    | 'Server'
    | 'Client'
    | 'Tests'
    | 'Build';
  readonly linesOfCode: number;
  readonly summary: string;
  readonly securityGuarantees: ReadonlyArray<string>;
  readonly code: string;
}

export type AuditCheckStatus =
  | 'PATTERN_NOT_FOUND'
  | 'HEURISTIC_PRESENT'
  | 'VIOLATION_DETECTED';

export interface StaticAuditFinding {
  readonly id: string;
  readonly ruleId: string;
  readonly cwe: string;
  readonly checkType: 'ABSENCE_REGEX' | 'PRESENCE_HEURISTIC';
  readonly status: AuditCheckStatus;
  readonly title: string;
  readonly description: string;
  readonly patternChecked: string;
  readonly scopeLimitation: string;
}

export const STATIC_AUDIT_LIMITATIONS: ReadonlyArray<string> = Object.freeze([
  'Syntactic Scope Only: Regex and substring checks inspect source text after stripping comments; they are NOT an AST, data-flow, or formal verification proof.',
  'Preprocessor & Aliasing Blindness: A regex check cannot detect indirect function pointers, dlsym() lookups, or macro token pasting.',
  'Kernel & Runtime Dependencies: openat2(RESOLVE_BENEATH) confinement requires Linux >= 5.6; on older kernels, the fallback step-by-step openat(O_NOFOLLOW) walker cannot prevent a privileged concurrent directory rename race (CWE-367).',
  'Per-Session Sequence Scope: The monotonic sequence_num prevents in-session frame reordering/duplication; cross-session replay protection relies on the TLS 1.3 handshake.',
]);

const countLines = (text: string): number => text.split('\n').length;

export const C_SOURCE_FILES: ReadonlyArray<CSourceFile> = Object.freeze([
  Object.freeze({
    filename: 'protocol.h',
    title: 'Wire Framing, Separated Error Domains & Opcode Contract',
    role: 'Header',
    linesOfCode: countLines(protocolH),
    summary:
      'Defines packed request (12 B) and response (16 B) headers, allowlisted sac_opcode_t enum, separated protocol vs filesystem error domains, and stream callbacks.',
    securityGuarantees: [
      'Explicit request (sac_frame_header_t) and response (sac_resp_header_t) binary framing',
      'Separates SAC_DOMAIN_PROTOCOL from SAC_DOMAIN_FILESYSTEM (sac_fs_status_t)',
      'Documents value-passed sac_session_state_t vs mutable OS handles (jail_dirfd, SSL*)',
    ],
    code: protocolH,
  }),
  Object.freeze({
    filename: 'io_framing.c',
    title: 'Exact-Length Read/Write Framing (sac_io_read_exact / sac_io_write_all)',
    role: 'Framing',
    linesOfCode: countLines(ioFramingC),
    summary:
      'Implements loop-based read_exact and write_all over abstract streams so partial SSL_read() or SSL_write() records never corrupt frame parsing.',
    securityGuarantees: [
      'Never assumes a single SSL_read() returns the complete header or payload',
      'Reassembles 1-byte fragmented reads and completes partial writes',
      'Validates payload_length <= SAC_MAX_PATH_LEN before reading request payload',
    ],
    code: ioFramingC,
  }),
  Object.freeze({
    filename: 'sandbox_fs.c',
    title: 'Confined Directory Resolution (Linux openat2 + openat Fallback)',
    role: 'SandboxFS',
    linesOfCode: countLines(sandboxFsC),
    summary:
      'Confines all file operations to an open jail_dirfd using Linux openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS) with a documented component-by-component openat(O_NOFOLLOW) fallback.',
    securityGuarantees: [
      'Uses Linux openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV) when available',
      'Distinguishes NOT_FOUND, PERMISSION_DENIED, NOT_REGULAR, NOT_DIR, PATH_ESCAPE, and BUFFER_TOO_SMALL',
      'Resolves paths relative to session state.cwd_rel so `cd` affects subsequent `ls` and `cat`',
    ],
    code: sandboxFsC,
  }),
  Object.freeze({
    filename: 'managers.c',
    title: 'Pre-Dispatch Validator, Error Manager, State Manager & Dispatcher',
    role: 'Managers',
    linesOfCode: countLines(managersC),
    summary:
      'Validates authentication, magic, version, opcode allowlist, payload length, and sequence monotonicity before executing any POSIX syscall.',
    securityGuarantees: [
      'Checks sac_opcode_is_valid() and header invariants BEFORE advancing sequence or command counters',
      'Rejected frames increment security_blocks and never increment commands_executed',
      'Zero calls to system(), popen(), or exec*()',
    ],
    code: managersC,
  }),
  Object.freeze({
    filename: 'tls_helpers.h',
    title: 'OpenSSL 3.x Mutual TLS 1.3 & Peer SAN Verification Interface',
    role: 'TLSHelpers',
    linesOfCode: countLines(tlsHelpersH),
    summary:
      'Declares OpenSSL 3.x server/client mTLS context builders, SAN identity verification, and SSL_get_error()-aware stream adapters.',
    securityGuarantees: [
      'Exposes sac_configure_client_peer_identity() for strict DNS/IP SAN matching',
      'Exposes sac_verify_accepted_client_cert() for server-side peer verification',
    ],
    code: tlsHelpersH,
  }),
  Object.freeze({
    filename: 'tls_helpers.c',
    title: 'OpenSSL 3.x mTLS 1.3 Implementation & SSL_get_error() Stream Adapter',
    role: 'TLSHelpers',
    linesOfCode: countLines(tlsHelpersC),
    summary:
      'Configures TLS 1.3 minimum version, mandatory client certs, client-side X509_VERIFY_PARAM_set1_ip_asc / SSL_set1_host SAN verification, and SSL_ERROR_WANT_READ/WRITE loops.',
    securityGuarantees: [
      'Checks return values of SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) and SSL_CTX_set_ciphersuites()',
      'Verifies both server certificate chain and Subject Alternative Name (DNS or IP)',
      'Handles SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE, and SSL_ERROR_ZERO_RETURN in I/O callbacks',
    ],
    code: tlsHelpersC,
  }),
  Object.freeze({
    filename: 'tls_server.c',
    title: 'Mutual TLS 1.3 Server Daemon Entry Point',
    role: 'Server',
    linesOfCode: countLines(tlsServerC),
    summary:
      'Opens the sandbox jail directory descriptor (O_DIRECTORY | O_NOFOLLOW), initializes mTLS 1.3 SSL_CTX, and serves framed RPC requests.',
    securityGuarantees: [
      'Anchors session filesystem operations to an open jail_dirfd',
      'Returns EXIT_FAILURE on any initialization, bind, or --once handshake failure',
    ],
    code: tlsServerC,
  }),
  Object.freeze({
    filename: 'tls_client.c',
    title: 'Mutual TLS 1.3 Client CLI Entry Point',
    role: 'Client',
    linesOfCode: countLines(tlsClientC),
    summary:
      'Validates CLI command against allowlisted opcodes, verifies server chain + SAN, exchanges framed RPC messages, and returns strict exit codes.',
    securityGuarantees: [
      'Never returns EXIT_SUCCESS after a socket, TLS handshake, SAN mismatch, or dispatch error',
      'Supports --expect-host <san> to verify DNS or IP Subject Alternative Names',
    ],
    code: tlsClientC,
  }),
  Object.freeze({
    filename: 'test_suite.c',
    title: '19-Case C11 Unit & Live OpenSSL 3.x mTLS 1.3 Integration Test Suite',
    role: 'Tests',
    linesOfCode: countLines(testSuiteC),
    summary:
      'Tests protocol validation, 1-byte fragmented reads, 2-byte partial writes, live TLS 1.3 record fragmentation, CWE-22 traversal/symlinks, DAC permissions, stateful cd/ls/cat, and mTLS cert/SAN failures.',
    securityGuarantees: [
      'Executes 19 deterministic C assertions including real fork() + socketpair/loopback OpenSSL 3.x handshakes',
      'Contains zero calls to system(), popen(), or exec*()',
    ],
    code: testSuiteC,
  }),
  Object.freeze({
    filename: 'Makefile',
    title: 'Hardened C11 Build & Test Automation',
    role: 'Build',
    linesOfCode: countLines(makefileRaw),
    summary:
      'Compiles secadmin_server, secadmin_client, and secadmin_tests with -std=c11 -Wall -Wextra -Werror -Wpedantic -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2.',
    securityGuarantees: [
      'Treats all compiler warnings as errors (-Werror -Wpedantic)',
      'Links with PIE and full RELRO (-pie -Wl,-z,relro,-z,now)',
    ],
    code: makefileRaw,
  }),
]);

/**
 * Generates a self-extracting POSIX shell script containing all C11 source files
 * so users can unpack and compile the entire C11 project in one command.
 */
export const buildSelfExtractingCBundle = (
  files: ReadonlyArray<CSourceFile> = C_SOURCE_FILES
): string => {
  const lines: string[] = [
    '#!/usr/bin/env sh',
    '# SecAdminC — Self-Extracting C11 + POSIX + OpenSSL 3.x Project Bundle',
    '# Usage: sh secadminc_c11_bundle.sh && cd secadminc_c11 && make all && make test',
    'set -e',
    'mkdir -p secadminc_c11',
    'cd secadminc_c11',
    '',
  ];

  for (const file of files) {
    lines.push(`cat << 'EOF_${file.filename}' > ${file.filename}`);
    lines.push(file.code);
    lines.push(`EOF_${file.filename}`);
    lines.push('');
  }

  lines.push('echo "Extracted SecAdminC C11 project into ./secadminc_c11"');
  lines.push('echo "Run: cd secadminc_c11 && make all && make test"');
  return lines.join('\n');
};

/**
 * Honest syntactic heuristic scanner over the C11 source files.
 * Distinguishes ABSENCE_REGEX (`PATTERN_NOT_FOUND`) from PRESENCE_HEURISTIC
 * (`HEURISTIC_PRESENT`), and explicitly documents the scope limitations of each check.
 */
export const runStaticSecurityAudit = (
  files: ReadonlyArray<CSourceFile> = C_SOURCE_FILES
): ReadonlyArray<StaticAuditFinding> => {
  const strippedSource = files
    .filter((f) => f.filename !== 'Makefile')
    .map((f) =>
      f.code
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/\/\/.*$/gm, '')
    )
    .join('\n');

  const hasShellCall = /\b(system|popen|execl|execle|execlp|execv|execvp|execve)\s*\(/.test(
    strippedSource
  );
  const hasUnboundedStrCall = /\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(/.test(
    strippedSource
  );
  const hasDirfdConfinementHeuristic =
    strippedSource.includes('RESOLVE_BENEATH') &&
    strippedSource.includes('RESOLVE_NO_SYMLINKS') &&
    strippedSource.includes('O_NOFOLLOW');
  const hasMtlsAndSanHeuristic =
    strippedSource.includes('SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)') &&
    strippedSource.includes('SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT') &&
    strippedSource.includes('SSL_set1_host') &&
    strippedSource.includes('X509_VERIFY_PARAM_set1_ip_asc');
  const hasExactFramingHeuristic =
    strippedSource.includes('sac_io_read_exact') &&
    strippedSource.includes('sac_io_write_all') &&
    strippedSource.includes('SSL_get_error');

  return Object.freeze([
    Object.freeze({
      id: 'audit_cwe78_no_shell_pattern',
      ruleId: 'SCAN-C-001',
      cwe: 'CWE-78',
      checkType: 'ABSENCE_REGEX',
      status: hasShellCall ? 'VIOLATION_DETECTED' : 'PATTERN_NOT_FOUND',
      title: 'No Direct OS Shell / Process Execution Calls Matched',
      description:
        'Scans comment-stripped C11 source files for direct invocations of system(), popen(), or exec*() family functions.',
      patternChecked: '/\\b(system|popen|execl|execle|execlp|execv|execvp|execve)\\s*\\(/',
      scopeLimitation:
        'Syntactic regex check only; cannot prove absence of indirect function pointer calls or macro obfuscation.',
    }),
    Object.freeze({
      id: 'audit_cwe120_no_unbounded_str_pattern',
      ruleId: 'SCAN-C-002',
      cwe: 'CWE-120',
      checkType: 'ABSENCE_REGEX',
      status: hasUnboundedStrCall ? 'VIOLATION_DETECTED' : 'PATTERN_NOT_FOUND',
      title: 'No Unbounded C String Copy/Format Calls Matched',
      description:
        'Scans comment-stripped C11 source files for gets(), strcpy(), strcat(), sprintf(), and vsprintf().',
      patternChecked: '/\\b(gets|strcpy|strcat|sprintf|vsprintf)\\s*\\(/',
      scopeLimitation:
        'Confirms absence of banned unbounded APIs, but does not mathematically prove that all snprintf/memcpy bounds are bug-free.',
    }),
    Object.freeze({
      id: 'audit_cwe22_dirfd_confinement_heuristic',
      ruleId: 'SCAN-C-003',
      cwe: 'CWE-22',
      checkType: 'PRESENCE_HEURISTIC',
      status: hasDirfdConfinementHeuristic
        ? 'HEURISTIC_PRESENT'
        : 'VIOLATION_DETECTED',
      title: 'Descriptor-Based Confinement Markers Present (openat2 / O_NOFOLLOW)',
      description:
        'Checks for presence of Linux openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS) and openat(O_NOFOLLOW) fallback markers.',
      patternChecked: 'RESOLVE_BENEATH && RESOLVE_NO_SYMLINKS && O_NOFOLLOW',
      scopeLimitation:
        'Kernel atomic RESOLVE_BENEATH requires Linux >= 5.6; fallback stepwise openat(O_NOFOLLOW) has residual TOCTOU rename-race exposure if a concurrent privileged process mutates directories.',
    }),
    Object.freeze({
      id: 'audit_cwe295_mtls_san_heuristic',
      ruleId: 'SCAN-C-004',
      cwe: 'CWE-295 / CWE-306',
      checkType: 'PRESENCE_HEURISTIC',
      status: hasMtlsAndSanHeuristic
        ? 'HEURISTIC_PRESENT'
        : 'VIOLATION_DETECTED',
      title: 'TLS 1.3 Floor, Server mTLS & Client SAN Verification Markers Present',
      description:
        'Checks for TLS1_3_VERSION minimum, SSL_VERIFY_FAIL_IF_NO_PEER_CERT on server, and SSL_set1_host / X509_VERIFY_PARAM_set1_ip_asc on client.',
      patternChecked:
        'TLS1_3_VERSION && SSL_VERIFY_FAIL_IF_NO_PEER_CERT && SSL_set1_host && X509_VERIFY_PARAM_set1_ip_asc',
      scopeLimitation:
        'Substring check verifies API usage in tls_helpers.c; actual handshake behavior is verified dynamically by test_suite.c (tests 16–19).',
    }),
    Object.freeze({
      id: 'audit_framing_loop_heuristic',
      ruleId: 'SCAN-C-005',
      cwe: 'CWE-130',
      checkType: 'PRESENCE_HEURISTIC',
      status: hasExactFramingHeuristic
        ? 'HEURISTIC_PRESENT'
        : 'VIOLATION_DETECTED',
      title: 'Loop-Based Exact Framing & SSL_get_error() Handling Present',
      description:
        'Checks that io_framing.c and tls_helpers.c implement sac_io_read_exact(), sac_io_write_all(), and SSL_get_error() retry loops.',
      patternChecked: 'sac_io_read_exact && sac_io_write_all && SSL_get_error',
      scopeLimitation:
        'Dynamic fragmented stream behavior (1-byte reads, 2-byte partial writes, and multi-record TLS 1.3 reads) is tested by test_suite.c (tests 06, 06b, 07).',
    }),
  ]);
};
