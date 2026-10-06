/*
 * protocol.h — SecAdminC Defensive Binary RPC & Functional C11 Architecture
 * Zero-shell architecture: commands are strictly typed uint8_t enum opcodes.
 */
#ifndef SECADMIN_PROTOCOL_H
#define SECADMIN_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define SAC_MAGIC_BYTES      0x53414331U /* "SAC1" */
#define SAC_PROTOCOL_VERSION 0x01U
#define SAC_MAX_PATH_LEN     256U
#define SAC_MAX_PAYLOAD_LEN  4096U
#define SAC_JAIL_ROOT        "/srv/sandbox"

/* Allowlisted RPC Route Opcodes (Zero Shell Execution) */
typedef enum {
    SAC_OP_SYS_UPTIME   = 0x01, /* POSIX sysinfo(&si) */
    SAC_OP_SYS_UNAME    = 0x02, /* POSIX uname(&uts) */
    SAC_OP_SYS_STATVFS  = 0x03, /* POSIX statvfs(SAC_JAIL_ROOT, &vfs) */
    SAC_OP_FS_LISTDIR   = 0x10, /* POSIX openat(O_RDONLY | O_DIRECTORY | O_NOFOLLOW) */
    SAC_OP_FS_READFILE  = 0x11, /* POSIX openat(O_RDONLY | O_NOFOLLOW) */
    SAC_OP_FS_CHDIR     = 0x12  /* POSIX realpath() containment check */
} sac_opcode_t;

/* Centralized C11 Error Manager Codes */
typedef enum {
    SAC_OK                       = 0x00,
    SAC_ERR_BAD_MAGIC            = 0x01,
    SAC_ERR_BAD_OPCODE           = 0x02,
    SAC_ERR_PATH_TRAVERSAL       = 0x03, /* CWE-22 blocked */
    SAC_ERR_SHELL_METACHAR       = 0x04, /* CWE-78 blocked */
    SAC_ERR_REPLAY_SEQUENCE      = 0x05,
    SAC_ERR_UNAUTHENTICATED      = 0x06, /* CWE-306 blocked */
    SAC_ERR_IO_FAILURE           = 0x07
} sac_error_code_t;

/* Immutable Error Value Struct (Functional Error Manager) */
typedef struct {
    sac_error_code_t code;
    const char      *cwe_id;
    char             message[256];
} sac_error_t;

/* Immutable Session State Value Struct (Functional State Manager) */
typedef struct {
    bool     mtls_authenticated;
    uint32_t last_sequence_num;
    uint32_t commands_executed;
    uint32_t security_blocks;
    char     current_dir[SAC_MAX_PATH_LEN];
} sac_session_state_t;

/* Wire Protocol Header (12 bytes packed, Network Byte Order) */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;          /* htonl(SAC_MAGIC_BYTES) */
    uint8_t  version;        /* SAC_PROTOCOL_VERSION */
    uint8_t  opcode;         /* sac_opcode_t */
    uint32_t sequence_num;   /* htonl(monotonic_seq) */
    uint16_t payload_length; /* htons(len <= SAC_MAX_PATH_LEN) */
} sac_frame_header_t;
#pragma pack(pop)

/* Functional Error Manager API */
sac_error_t sac_error_make(sac_error_code_t code, const char *detail);
const char *sac_error_cwe_lookup(sac_error_code_t code);

/* Functional State Manager API (Pure Value Transitions) */
sac_session_state_t sac_state_init(bool mtls_verified);
sac_session_state_t sac_state_advance_seq(sac_session_state_t state, uint32_t next_seq);
sac_session_state_t sac_state_record_block(sac_session_state_t state);
sac_session_state_t sac_state_with_cwd(sac_session_state_t state, const char *new_cwd);

/* Functional Route Manager API */
sac_error_t sac_route_dispatch(
    sac_session_state_t  current_state,
    const sac_frame_header_t *hdr,
    const char          *payload_arg,
    sac_session_state_t *out_next_state,
    char                *out_response,
    size_t               out_response_cap
);

/* Sandboxed Filesystem API */
int sac_verify_within_jail(const char *jail_root, const char *user_rel_path, char *resolved_out, size_t out_sz);
int sac_sandbox_list_dir(const char *jail_root, const char *rel_path, char *out_buf, size_t out_cap);
int sac_sandbox_read_file(const char *jail_root, const char *rel_path, char *out_buf, size_t out_cap);

#endif /* SECADMIN_PROTOCOL_H */
