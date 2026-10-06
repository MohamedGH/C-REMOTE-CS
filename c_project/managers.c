/*
 * managers.c — Error Manager, State Manager, Pre-Dispatch Validator & Dispatcher
 *
 * Key Guarantees:
 * 1. Pre-dispatch validation checks authentication, magic, version, opcode
 *    allowlist membership, payload_length bounds, and sequence monotonicity
 *    BEFORE any state sequence advancement or syscall execution.
 * 2. Rejected operations increment `security_blocks` and NEVER increment
 *    `commands_executed` or advance `last_sequence_num`.
 * 3. Protocol errors (SAC_DOMAIN_PROTOCOL) and filesystem errors
 *    (SAC_DOMAIN_FILESYSTEM) are tracked in distinct fields.
 * 4. `SAC_OP_FS_CHDIR` updates `state.cwd_rel`, which subsequent `SAC_OP_FS_LISTDIR`
 *    and `SAC_OP_FS_READFILE` calls use relative to `state.jail_dirfd`.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include "protocol.h"

/* ==========================================================================
 * 1. CENTRALIZED OPCODE ALLOWLIST & ERROR MANAGER
 * ========================================================================== */
bool sac_opcode_is_valid(uint8_t opcode) {
    switch ((sac_opcode_t)opcode) {
        case SAC_OP_SYS_UPTIME:
        case SAC_OP_SYS_UNAME:
        case SAC_OP_SYS_STATVFS:
        case SAC_OP_FS_LISTDIR:
        case SAC_OP_FS_READFILE:
        case SAC_OP_FS_CHDIR:
            return true;
        default:
            return false;
    }
}

const char *sac_opcode_name(uint8_t opcode) {
    switch ((sac_opcode_t)opcode) {
        case SAC_OP_SYS_UPTIME:  return "SAC_OP_SYS_UPTIME";
        case SAC_OP_SYS_UNAME:   return "SAC_OP_SYS_UNAME";
        case SAC_OP_SYS_STATVFS: return "SAC_OP_SYS_STATVFS";
        case SAC_OP_FS_LISTDIR:  return "SAC_OP_FS_LISTDIR";
        case SAC_OP_FS_READFILE: return "SAC_OP_FS_READFILE";
        case SAC_OP_FS_CHDIR:    return "SAC_OP_FS_CHDIR";
        default:                 return "UNKNOWN_OPCODE";
    }
}

const char *sac_fs_status_name(sac_fs_status_t st) {
    switch (st) {
        case SAC_FS_OK:                    return "SAC_FS_OK";
        case SAC_FS_ERR_NOT_FOUND:         return "SAC_FS_ERR_NOT_FOUND";
        case SAC_FS_ERR_PERMISSION_DENIED: return "SAC_FS_ERR_PERMISSION_DENIED";
        case SAC_FS_ERR_NOT_REGULAR:       return "SAC_FS_ERR_NOT_REGULAR";
        case SAC_FS_ERR_NOT_DIR:           return "SAC_FS_ERR_NOT_DIR";
        case SAC_FS_ERR_PATH_ESCAPE:       return "SAC_FS_ERR_PATH_ESCAPE";
        case SAC_FS_ERR_BUFFER_TOO_SMALL:  return "SAC_FS_ERR_BUFFER_TOO_SMALL";
        case SAC_FS_ERR_IO:                return "SAC_FS_ERR_IO";
        default:                           return "SAC_FS_ERR_UNKNOWN";
    }
}

const char *sac_error_cwe_lookup(sac_error_code_t code, sac_fs_status_t fs_st) {
    if (code == SAC_OK) {
        return "NONE";
    }
    if (code == SAC_ERR_FS_FAILURE) {
        switch (fs_st) {
            case SAC_FS_ERR_PATH_ESCAPE:       return "CWE-22";
            case SAC_FS_ERR_PERMISSION_DENIED: return "CWE-285";
            case SAC_FS_ERR_BUFFER_TOO_SMALL:  return "CWE-120";
            default:                           return "CWE-703";
        }
    }
    switch (code) {
        case SAC_ERR_BAD_OPCODE:
        case SAC_ERR_INVALID_ARGUMENT:    return "CWE-78";
        case SAC_ERR_UNAUTHENTICATED:     return "CWE-306";
        case SAC_ERR_SEQUENCE_REGRESSION: return "CWE-294";
        case SAC_ERR_PAYLOAD_TOO_LARGE:   return "CWE-789";
        default:                          return "CWE-20";
    }
}

sac_error_t sac_error_make(
    sac_error_code_t   code,
    sac_error_domain_t domain,
    sac_fs_status_t    fs_status,
    const char        *detail
) {
    sac_error_t err;
    memset(&err, 0, sizeof(err));
    err.code      = code;
    err.domain    = domain;
    err.fs_status = fs_status;
    err.cwe_id    = sac_error_cwe_lookup(code, fs_status);

    if (domain == SAC_DOMAIN_FILESYSTEM) {
        snprintf(err.message, sizeof(err.message),
                 "ERR domain=FILESYSTEM code=%d fs_status=%s cwe=%s: %s\n",
                 (int)code, sac_fs_status_name(fs_status), err.cwe_id,
                 detail ? detail : "");
    } else if (code != SAC_OK) {
        snprintf(err.message, sizeof(err.message),
                 "ERR domain=PROTOCOL code=%d cwe=%s: %s\n",
                 (int)code, err.cwe_id, detail ? detail : "");
    } else {
        snprintf(err.message, sizeof(err.message), "OK %s\n", detail ? detail : "");
    }
    return err;
}

/* ==========================================================================
 * 2. STATE MANAGER (Pure Value Transitions for Protocol Fields)
 * ========================================================================== */
sac_session_state_t sac_state_init(bool mtls_verified, int jail_dirfd) {
    sac_session_state_t s;
    memset(&s, 0, sizeof(s));
    s.mtls_authenticated = mtls_verified;
    s.last_sequence_num  = 0U;
    s.commands_executed  = 0U;
    s.security_blocks    = 0U;
    s.jail_dirfd         = jail_dirfd;
    snprintf(s.cwd_rel, sizeof(s.cwd_rel), ".");
    return s;
}

sac_session_state_t sac_state_advance_seq(sac_session_state_t state, uint32_t next_seq) {
    sac_session_state_t next = state;
    next.last_sequence_num = next_seq;
    next.commands_executed += 1U;
    return next;
}

sac_session_state_t sac_state_record_block(sac_session_state_t state) {
    sac_session_state_t next = state;
    next.security_blocks += 1U;
    return next;
}

sac_session_state_t sac_state_with_cwd(sac_session_state_t state, const char *new_cwd_rel) {
    sac_session_state_t next = state;
    if (new_cwd_rel && new_cwd_rel[0] != '\0') {
        strncpy(next.cwd_rel, new_cwd_rel, sizeof(next.cwd_rel) - 1);
        next.cwd_rel[sizeof(next.cwd_rel) - 1] = '\0';
    }
    return next;
}

/* ==========================================================================
 * 3. PRE-DISPATCH VALIDATOR & ROUTE DISPATCHER
 * ========================================================================== */
static bool has_forbidden_argument_chars(const char *s, size_t expected_len) {
    if (!s) return false;
    /* Reject embedded NUL bytes, shell metacharacters, or ASCII control bytes */
    const char *forbidden = ";|&\x60$><\n\r\\";
    for (size_t i = 0; i < expected_len; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\0' || c < 0x20 || c == 0x7f || strchr(forbidden, (int)c) != NULL) {
            return true;
        }
    }
    return false;
}

sac_error_t sac_validate_request_header(
    sac_session_state_t       state,
    const sac_frame_header_t *host_hdr
) {
    if (!host_hdr) {
        return sac_error_make(SAC_ERR_INVALID_ARGUMENT, SAC_DOMAIN_PROTOCOL, SAC_FS_OK, "NULL header");
    }
    if (!state.mtls_authenticated) {
        return sac_error_make(SAC_ERR_UNAUTHENTICATED, SAC_DOMAIN_PROTOCOL, SAC_FS_OK,
                              "Mutual TLS 1.3 client certificate not verified");
    }
    if (host_hdr->magic != SAC_MAGIC_BYTES) {
        return sac_error_make(SAC_ERR_BAD_MAGIC, SAC_DOMAIN_PROTOCOL, SAC_FS_OK,
                              "Invalid frame magic bytes");
    }
    if (host_hdr->version != SAC_PROTOCOL_VERSION) {
        return sac_error_make(SAC_ERR_BAD_VERSION, SAC_DOMAIN_PROTOCOL, SAC_FS_OK,
                              "Unsupported protocol version");
    }
    if (!sac_opcode_is_valid(host_hdr->opcode)) {
        return sac_error_make(SAC_ERR_BAD_OPCODE, SAC_DOMAIN_PROTOCOL, SAC_FS_OK,
                              "Opcode is not in allowlist");
    }
    if (host_hdr->payload_length > SAC_MAX_PATH_LEN) {
        return sac_error_make(SAC_ERR_PAYLOAD_TOO_LARGE, SAC_DOMAIN_PROTOCOL, SAC_FS_OK,
                              "Request payload_length exceeds SAC_MAX_PATH_LEN (256)");
    }
    if (host_hdr->sequence_num <= state.last_sequence_num) {
        return sac_error_make(SAC_ERR_SEQUENCE_REGRESSION, SAC_DOMAIN_PROTOCOL, SAC_FS_OK,
                              "Non-monotonic sequence_num rejected");
    }
    return sac_error_make(SAC_OK, SAC_DOMAIN_NONE, SAC_FS_OK, "Header valid");
}

sac_error_t sac_route_dispatch(
    sac_session_state_t       current_state,
    const sac_frame_header_t *host_hdr,
    const char               *payload_arg,
    sac_session_state_t      *out_next_state,
    char                     *out_response,
    size_t                    out_response_cap,
    size_t                   *out_response_len
) {
    if (out_next_state) *out_next_state = current_state;
    if (out_response && out_response_cap > 0) out_response[0] = '\0';
    if (out_response_len) *out_response_len = 0;

    /* 1. Validate protocol header BEFORE touching sequence or command counters */
    sac_error_t hdr_err = sac_validate_request_header(current_state, host_hdr);
    if (hdr_err.code != SAC_OK) {
        if (out_next_state) {
            *out_next_state = sac_state_record_block(current_state);
        }
        return hdr_err;
    }

    /* 2. Validate payload characters */
    const char *arg = payload_arg ? payload_arg : "";
    size_t arg_len = (host_hdr->payload_length > 0) ? host_hdr->payload_length : strlen(arg);
    if (has_forbidden_argument_chars(arg, arg_len)) {
        if (out_next_state) {
            *out_next_state = sac_state_record_block(current_state);
        }
        return sac_error_make(SAC_ERR_INVALID_ARGUMENT, SAC_DOMAIN_PROTOCOL, SAC_FS_OK,
                              "Forbidden control or shell metacharacter in argument");
    }

    if (!out_response || out_response_cap < 2) {
        if (out_next_state) {
            *out_next_state = sac_state_record_block(current_state);
        }
        return sac_error_make(SAC_ERR_FS_FAILURE, SAC_DOMAIN_FILESYSTEM,
                              SAC_FS_ERR_BUFFER_TOO_SMALL, "Response buffer too small");
    }

    /* 3. Execute allowlisted opcode */
    switch ((sac_opcode_t)host_hdr->opcode) {
        case SAC_OP_SYS_UPTIME: {
            struct sysinfo si;
            if (sysinfo(&si) != 0) {
                return sac_error_make(SAC_ERR_SYS_FAILURE, SAC_DOMAIN_SYSTEM, SAC_FS_OK, "sysinfo() failed");
            }
            int n = snprintf(out_response, out_response_cap,
                             "OK uptime=%lds procs=%hu freeram_mb=%lu\n",
                             si.uptime, si.procs, (unsigned long)(si.freeram / (1024UL * 1024UL)));
            if (n < 0 || (size_t)n >= out_response_cap) {
                return sac_error_make(SAC_ERR_FS_FAILURE, SAC_DOMAIN_FILESYSTEM,
                                      SAC_FS_ERR_BUFFER_TOO_SMALL, "sysinfo response truncated");
            }
            if (out_response_len) *out_response_len = (size_t)n;
            if (out_next_state) *out_next_state = sac_state_advance_seq(current_state, host_hdr->sequence_num);
            return sac_error_make(SAC_OK, SAC_DOMAIN_NONE, SAC_FS_OK, "SAC_OP_SYS_UPTIME");
        }

        case SAC_OP_SYS_UNAME: {
            struct utsname uts;
            if (uname(&uts) != 0) {
                return sac_error_make(SAC_ERR_SYS_FAILURE, SAC_DOMAIN_SYSTEM, SAC_FS_OK, "uname() failed");
            }
            int n = snprintf(out_response, out_response_cap,
                             "OK %s %s %s %s\n",
                             uts.sysname, uts.nodename, uts.release, uts.machine);
            if (n < 0 || (size_t)n >= out_response_cap) {
                return sac_error_make(SAC_ERR_FS_FAILURE, SAC_DOMAIN_FILESYSTEM,
                                      SAC_FS_ERR_BUFFER_TOO_SMALL, "uname response truncated");
            }
            if (out_response_len) *out_response_len = (size_t)n;
            if (out_next_state) *out_next_state = sac_state_advance_seq(current_state, host_hdr->sequence_num);
            return sac_error_make(SAC_OK, SAC_DOMAIN_NONE, SAC_FS_OK, "SAC_OP_SYS_UNAME");
        }

        case SAC_OP_SYS_STATVFS: {
            struct statvfs vfs;
            if (current_state.jail_dirfd < 0 || fstatvfs(current_state.jail_dirfd, &vfs) != 0) {
                return sac_error_make(SAC_ERR_SYS_FAILURE, SAC_DOMAIN_SYSTEM, SAC_FS_OK, "fstatvfs() failed");
            }
            unsigned long free_mb = (unsigned long)((vfs.f_bavail * vfs.f_frsize) / (1024ULL * 1024ULL));
            int n = snprintf(out_response, out_response_cap,
                             "OK cwd=%s free_mb=%lu bsize=%lu\n",
                             current_state.cwd_rel, free_mb, (unsigned long)vfs.f_bsize);
            if (n < 0 || (size_t)n >= out_response_cap) {
                return sac_error_make(SAC_ERR_FS_FAILURE, SAC_DOMAIN_FILESYSTEM,
                                      SAC_FS_ERR_BUFFER_TOO_SMALL, "statvfs response truncated");
            }
            if (out_response_len) *out_response_len = (size_t)n;
            if (out_next_state) *out_next_state = sac_state_advance_seq(current_state, host_hdr->sequence_num);
            return sac_error_make(SAC_OK, SAC_DOMAIN_NONE, SAC_FS_OK, "SAC_OP_SYS_STATVFS");
        }

        case SAC_OP_FS_LISTDIR: {
            size_t written = 0;
            sac_fs_status_t st = sac_fs_list_dir(
                current_state.jail_dirfd,
                current_state.cwd_rel,
                arg,
                out_response,
                out_response_cap,
                &written
            );
            if (st != SAC_FS_OK) {
                if (out_next_state) {
                    *out_next_state = (st == SAC_FS_ERR_PATH_ESCAPE)
                        ? sac_state_record_block(current_state)
                        : current_state;
                }
                return sac_error_make(SAC_ERR_FS_FAILURE, SAC_DOMAIN_FILESYSTEM, st,
                                      sac_fs_status_name(st));
            }
            if (out_response_len) *out_response_len = written;
            if (out_next_state) *out_next_state = sac_state_advance_seq(current_state, host_hdr->sequence_num);
            return sac_error_make(SAC_OK, SAC_DOMAIN_NONE, SAC_FS_OK, "SAC_OP_FS_LISTDIR");
        }

        case SAC_OP_FS_READFILE: {
            size_t written = 0;
            sac_fs_status_t st = sac_fs_read_file(
                current_state.jail_dirfd,
                current_state.cwd_rel,
                arg,
                out_response,
                out_response_cap,
                &written
            );
            if (st != SAC_FS_OK) {
                if (out_next_state) {
                    *out_next_state = (st == SAC_FS_ERR_PATH_ESCAPE)
                        ? sac_state_record_block(current_state)
                        : current_state;
                }
                return sac_error_make(SAC_ERR_FS_FAILURE, SAC_DOMAIN_FILESYSTEM, st,
                                      sac_fs_status_name(st));
            }
            if (out_response_len) *out_response_len = written;
            if (out_next_state) *out_next_state = sac_state_advance_seq(current_state, host_hdr->sequence_num);
            return sac_error_make(SAC_OK, SAC_DOMAIN_NONE, SAC_FS_OK, "SAC_OP_FS_READFILE");
        }

        case SAC_OP_FS_CHDIR: {
            char next_cwd[SAC_MAX_PATH_LEN];
            sac_fs_status_t st = sac_fs_chdir(
                current_state.jail_dirfd,
                current_state.cwd_rel,
                arg,
                next_cwd,
                sizeof(next_cwd)
            );
            if (st != SAC_FS_OK) {
                if (out_next_state) {
                    *out_next_state = (st == SAC_FS_ERR_PATH_ESCAPE)
                        ? sac_state_record_block(current_state)
                        : current_state;
                }
                return sac_error_make(SAC_ERR_FS_FAILURE, SAC_DOMAIN_FILESYSTEM, st,
                                      sac_fs_status_name(st));
            }
            sac_session_state_t stepped = sac_state_advance_seq(current_state, host_hdr->sequence_num);
            stepped = sac_state_with_cwd(stepped, next_cwd);
            if (out_next_state) *out_next_state = stepped;

            int n = snprintf(out_response, out_response_cap, "OK cwd=%s\n", next_cwd);
            if (n > 0 && (size_t)n < out_response_cap && out_response_len) {
                *out_response_len = (size_t)n;
            }
            return sac_error_make(SAC_OK, SAC_DOMAIN_NONE, SAC_FS_OK, "SAC_OP_FS_CHDIR");
        }

        default:
            if (out_next_state) *out_next_state = sac_state_record_block(current_state);
            return sac_error_make(SAC_ERR_BAD_OPCODE, SAC_DOMAIN_PROTOCOL, SAC_FS_OK,
                                  "Opcode not in allowlist");
    }
}
