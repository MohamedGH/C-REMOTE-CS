/*
 * managers.c — Pure Functional Error Manager, State Manager & Route Manager in C11
 * Uses value semantics (returning new immutable structs instead of mutating globals).
 */
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <sys/statvfs.h>
#include "protocol.h"

/* ==========================================================================
 * 1. FUNCTIONAL ERROR MANAGER
 * ========================================================================== */
const char *sac_error_cwe_lookup(sac_error_code_t code) {
    switch (code) {
        case SAC_OK:                  return "NONE";
        case SAC_ERR_PATH_TRAVERSAL:  return "CWE-22";
        case SAC_ERR_SHELL_METACHAR:  return "CWE-78";
        case SAC_ERR_BAD_OPCODE:      return "CWE-78";
        case SAC_ERR_UNAUTHENTICATED: return "CWE-306";
        case SAC_ERR_REPLAY_SEQUENCE: return "CWE-294";
        default:                      return "CWE-20";
    }
}

sac_error_t sac_error_make(sac_error_code_t code, const char *detail) {
    sac_error_t err;
    err.code = code;
    err.cwe_id = sac_error_cwe_lookup(code);
    snprintf(err.message, sizeof(err.message), "[%s] code=%d: %s",
             err.cwe_id, (int)code, detail ? detail : "");
    return err;
}

/* ==========================================================================
 * 2. FUNCTIONAL STATE MANAGER (Pure Value Struct Transitions)
 * ========================================================================== */
sac_session_state_t sac_state_init(bool mtls_verified) {
    sac_session_state_t s;
    memset(&s, 0, sizeof(s));
    s.mtls_authenticated = mtls_verified;
    s.last_sequence_num = 0;
    s.commands_executed = 0;
    s.security_blocks = 0;
    strncpy(s.current_dir, SAC_JAIL_ROOT, sizeof(s.current_dir) - 1);
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

sac_session_state_t sac_state_with_cwd(sac_session_state_t state, const char *new_cwd) {
    sac_session_state_t next = state;
    if (new_cwd) {
        strncpy(next.current_dir, new_cwd, sizeof(next.current_dir) - 1);
        next.current_dir[sizeof(next.current_dir) - 1] = '\0';
    }
    return next;
}

/* Pure predicate checking for forbidden shell metacharacters (CWE-78 guard) */
static bool contains_shell_metachar(const char *s) {
    if (!s) return false;
    const char *forbidden = ";|&`$><\n\r";
    for (size_t i = 0; s[i] != '\0'; ++i) {
        if (strchr(forbidden, s[i]) != NULL) return true;
    }
    return false;
}

/* ==========================================================================
 * 3. FUNCTIONAL ROUTE / OPCODE MANAGER
 * ========================================================================== */
sac_error_t sac_route_dispatch(
    sac_session_state_t       current_state,
    const sac_frame_header_t *hdr,
    const char               *payload_arg,
    sac_session_state_t      *out_next_state,
    char                     *out_response,
    size_t                    out_response_cap
) {
    *out_next_state = current_state;

    if (!current_state.mtls_authenticated) {
        *out_next_state = sac_state_record_block(current_state);
        return sac_error_make(SAC_ERR_UNAUTHENTICATED, "Mutual TLS 1.3 peer certificate required");
    }
    if (hdr->magic != SAC_MAGIC_BYTES || hdr->version != SAC_PROTOCOL_VERSION) {
        *out_next_state = sac_state_record_block(current_state);
        return sac_error_make(SAC_ERR_BAD_MAGIC, "Invalid wire frame header magic or version");
    }
    if (hdr->sequence_num <= current_state.last_sequence_num) {
        *out_next_state = sac_state_record_block(current_state);
        return sac_error_make(SAC_ERR_REPLAY_SEQUENCE, "Non-monotonic sequence nonce rejected");
    }
    if (contains_shell_metachar(payload_arg)) {
        *out_next_state = sac_state_record_block(current_state);
        return sac_error_make(SAC_ERR_SHELL_METACHAR, "Forbidden shell metacharacter in argument");
    }

    sac_session_state_t stepped = sac_state_advance_seq(current_state, hdr->sequence_num);

    switch ((sac_opcode_t)hdr->opcode) {
        case SAC_OP_SYS_UPTIME: {
            struct sysinfo si;
            if (sysinfo(&si) != 0) return sac_error_make(SAC_ERR_IO_FAILURE, "sysinfo failed");
            snprintf(out_response, out_response_cap,
                     "OK uptime=%lds procs=%hu freeram_mb=%lu\n",
                     si.uptime, si.procs, (unsigned long)(si.freeram / (1024 * 1024)));
            *out_next_state = stepped;
            return sac_error_make(SAC_OK, "OP_SYS_UPTIME");
        }
        case SAC_OP_SYS_UNAME: {
            struct utsname uts;
            if (uname(&uts) != 0) return sac_error_make(SAC_ERR_IO_FAILURE, "uname failed");
            snprintf(out_response, out_response_cap, "OK %s %s %s %s\n",
                     uts.sysname, uts.nodename, uts.release, uts.machine);
            *out_next_state = stepped;
            return sac_error_make(SAC_OK, "OP_SYS_UNAME");
        }
        case SAC_OP_SYS_STATVFS: {
            struct statvfs vfs;
            if (statvfs(SAC_JAIL_ROOT, &vfs) != 0) {
                snprintf(out_response, out_response_cap, "OK jail=%s statvfs_simulated=1\n", SAC_JAIL_ROOT);
            } else {
                unsigned long free_mb = (vfs.f_bavail * vfs.f_frsize) / (1024 * 1024);
                snprintf(out_response, out_response_cap, "OK jail=%s free_mb=%lu\n", SAC_JAIL_ROOT, free_mb);
            }
            *out_next_state = stepped;
            return sac_error_make(SAC_OK, "OP_SYS_STATVFS");
        }
        case SAC_OP_FS_LISTDIR: {
            const char *target = (payload_arg && payload_arg[0]) ? payload_arg : ".";
            if (sac_sandbox_list_dir(SAC_JAIL_ROOT, target, out_response, out_response_cap) != 0) {
                *out_next_state = sac_state_record_block(stepped);
                return sac_error_make(SAC_ERR_PATH_TRAVERSAL, "Directory access outside sandbox blocked");
            }
            *out_next_state = stepped;
            return sac_error_make(SAC_OK, "OP_FS_LISTDIR");
        }
        case SAC_OP_FS_READFILE: {
            if (!payload_arg || !payload_arg[0]) {
                *out_next_state = sac_state_record_block(stepped);
                return sac_error_make(SAC_ERR_PATH_TRAVERSAL, "Empty file path rejected");
            }
            if (sac_sandbox_read_file(SAC_JAIL_ROOT, payload_arg, out_response, out_response_cap) != 0) {
                *out_next_state = sac_state_record_block(stepped);
                return sac_error_make(SAC_ERR_PATH_TRAVERSAL, "File read outside sandbox blocked");
            }
            *out_next_state = stepped;
            return sac_error_make(SAC_OK, "OP_FS_READFILE");
        }
        case SAC_OP_FS_CHDIR: {
            char resolved[SAC_MAX_PATH_LEN];
            if (sac_verify_within_jail(SAC_JAIL_ROOT, payload_arg ? payload_arg : ".", resolved, sizeof(resolved)) != 0) {
                *out_next_state = sac_state_record_block(stepped);
                return sac_error_make(SAC_ERR_PATH_TRAVERSAL, "chdir outside sandbox jail blocked");
            }
            *out_next_state = sac_state_with_cwd(stepped, resolved);
            snprintf(out_response, out_response_cap, "OK cwd=%s\n", resolved);
            return sac_error_make(SAC_OK, "OP_FS_CHDIR");
        }
        default:
            *out_next_state = sac_state_record_block(stepped);
            return sac_error_make(SAC_ERR_BAD_OPCODE, "Opcode not in allowlist");
    }
}
