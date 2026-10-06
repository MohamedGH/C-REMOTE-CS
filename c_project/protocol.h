/*
 * protocol.h — SecAdminC C11 / POSIX.1-2008 / Linux / OpenSSL 3.x Contract
 *
 * Architectural notes:
 * 1. Wire Framing: Both requests (sac_frame_header_t, 12 bytes) and responses
 *    (sac_resp_header_t, 16 bytes) use explicit length-prefixed binary headers
 *    read/written via loop-based read_exact / write_all routines.
 * 2. Error Separation: Protocol validation errors (SAC_DOMAIN_PROTOCOL) are
 *    distinct from filesystem errors (SAC_DOMAIN_FILESYSTEM, with granular
 *    sac_fs_status_t codes).
 * 3. State Semantics: sac_session_state_t is passed and returned by value
 *    (pure struct transition), while OS resources (jail_dirfd, SSL*) remain
 *    explicitly managed mutable handles at the session boundary.
 * 4. Sequence Counter Scope: The monotonic sequence_num prevents in-session
 *    request reordering or duplication at the application framing layer.
 *    Cross-session replay protection relies on TLS 1.3 handshake freshness
 *    (ephemeral ECDHE key exchange).
 */
#ifndef SECADMIN_PROTOCOL_H
#define SECADMIN_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#define SAC_MAGIC_BYTES        0x53414331U /* "SAC1" */
#define SAC_PROTOCOL_VERSION   0x01U
#define SAC_MAX_PATH_LEN       256U
#define SAC_MAX_PAYLOAD_LEN    4096U
#define SAC_DEFAULT_JAIL_ROOT  "/srv/sandbox"

/* Allowlisted RPC Route Opcodes (Zero Shell Execution) */
typedef enum {
    SAC_OP_SYS_UPTIME   = 0x01, /* POSIX sysinfo(&si) */
    SAC_OP_SYS_UNAME    = 0x02, /* POSIX uname(&uts) */
    SAC_OP_SYS_STATVFS  = 0x03, /* POSIX fstatvfs(jail_dirfd, &vfs) */
    SAC_OP_FS_LISTDIR   = 0x10, /* Confined dirfd listing */
    SAC_OP_FS_READFILE  = 0x11, /* Confined regular file read */
    SAC_OP_FS_CHDIR     = 0x12  /* Confined working directory update */
} sac_opcode_t;

/* Error Domains (Separates Protocol vs Filesystem vs System vs TLS I/O) */
typedef enum {
    SAC_DOMAIN_NONE       = 0x00,
    SAC_DOMAIN_PROTOCOL   = 0x01,
    SAC_DOMAIN_FILESYSTEM = 0x02,
    SAC_DOMAIN_SYSTEM     = 0x03,
    SAC_DOMAIN_TLS_IO     = 0x04
} sac_error_domain_t;

/* Granular Filesystem Status Codes */
typedef enum {
    SAC_FS_OK                   = 0x00,
    SAC_FS_ERR_NOT_FOUND        = 0x01, /* ENOENT */
    SAC_FS_ERR_PERMISSION_DENIED= 0x02, /* EACCES / EPERM */
    SAC_FS_ERR_NOT_REGULAR      = 0x03, /* EISDIR / FIFO / device on read */
    SAC_FS_ERR_NOT_DIR          = 0x04, /* ENOTDIR on listdir / chdir */
    SAC_FS_ERR_PATH_ESCAPE      = 0x05, /* CWE-22: .. escape, symlink, EXDEV */
    SAC_FS_ERR_BUFFER_TOO_SMALL = 0x06, /* Output buffer smaller than content */
    SAC_FS_ERR_IO               = 0x07  /* Generic descriptor/read error */
} sac_fs_status_t;

/* Top-Level Dispatch & Protocol Error Codes */
typedef enum {
    SAC_OK                      = 0x00,
    SAC_ERR_BAD_MAGIC           = 0x01,
    SAC_ERR_BAD_VERSION         = 0x02,
    SAC_ERR_BAD_OPCODE          = 0x03,
    SAC_ERR_PAYLOAD_TOO_LARGE   = 0x04,
    SAC_ERR_SEQUENCE_REGRESSION = 0x05,
    SAC_ERR_UNAUTHENTICATED     = 0x06,
    SAC_ERR_INVALID_ARGUMENT    = 0x07,
    SAC_ERR_FS_FAILURE          = 0x08,
    SAC_ERR_SYS_FAILURE         = 0x09,
    SAC_ERR_IO_FAILURE          = 0x0A
} sac_error_code_t;

/* Structured Error Value (Error Manager) */
typedef struct {
    sac_error_code_t   code;
    sac_error_domain_t domain;
    sac_fs_status_t    fs_status;
    const char        *cwe_id;
    char               message[256];
} sac_error_t;

/*
 * Session State Value Struct (State Manager)
 * Value-passed fields represent pure per-session protocol state.
 * Note: jail_dirfd is an OS file descriptor passed alongside the state so
 * filesystem operations are anchored to an open directory descriptor.
 */
typedef struct {
    bool     mtls_authenticated;
    uint32_t last_sequence_num;
    uint32_t commands_executed;
    uint32_t security_blocks;
    int      jail_dirfd;
    char     cwd_rel[SAC_MAX_PATH_LEN]; /* Relative to jail_dirfd, "." at root */
} sac_session_state_t;

#pragma pack(push, 1)
/* Request Frame Header (12 bytes, Network Byte Order) */
typedef struct {
    uint32_t magic;          /* htonl(SAC_MAGIC_BYTES) */
    uint8_t  version;        /* SAC_PROTOCOL_VERSION */
    uint8_t  opcode;         /* sac_opcode_t */
    uint32_t sequence_num;   /* htonl(monotonic_seq) */
    uint16_t payload_length; /* htons(len <= SAC_MAX_PATH_LEN) */
} sac_frame_header_t;

/* Response Frame Header (16 bytes, Network Byte Order) */
typedef struct {
    uint32_t magic;          /* htonl(SAC_MAGIC_BYTES) */
    uint8_t  version;        /* SAC_PROTOCOL_VERSION */
    uint8_t  status_code;    /* sac_error_code_t */
    uint8_t  error_domain;   /* sac_error_domain_t */
    uint8_t  fs_status;      /* sac_fs_status_t */
    uint32_t sequence_echo;  /* htonl(request sequence_num) */
    uint32_t payload_length; /* htonl(response payload bytes <= SAC_MAX_PAYLOAD_LEN) */
} sac_resp_header_t;
#pragma pack(pop)

/* Abstract Transport Stream (supports OpenSSL SSL* and deterministic test streams) */
typedef ssize_t (*sac_read_fn_t)(void *ctx, void *buf, size_t len);
typedef ssize_t (*sac_write_fn_t)(void *ctx, const void *buf, size_t len);

typedef struct {
    void          *ctx;
    sac_read_fn_t  read_some;
    sac_write_fn_t write_some;
} sac_io_stream_t;

/* Opcode & Error Manager API */
bool sac_opcode_is_valid(uint8_t opcode);
const char *sac_opcode_name(uint8_t opcode);
const char *sac_fs_status_name(sac_fs_status_t st);
const char *sac_error_cwe_lookup(sac_error_code_t code, sac_fs_status_t fs_st);
sac_error_t sac_error_make(
    sac_error_code_t   code,
    sac_error_domain_t domain,
    sac_fs_status_t    fs_status,
    const char        *detail
);

/* State Manager API (Value Transitions) */
sac_session_state_t sac_state_init(bool mtls_verified, int jail_dirfd);
sac_session_state_t sac_state_advance_seq(sac_session_state_t state, uint32_t next_seq);
sac_session_state_t sac_state_record_block(sac_session_state_t state);
sac_session_state_t sac_state_with_cwd(sac_session_state_t state, const char *new_cwd_rel);

/* Pre-Dispatch Frame Validator */
sac_error_t sac_validate_request_header(
    sac_session_state_t       state,
    const sac_frame_header_t *host_hdr
);

/* Route / Opcode Dispatcher */
sac_error_t sac_route_dispatch(
    sac_session_state_t       current_state,
    const sac_frame_header_t *host_hdr,
    const char               *payload_arg,
    sac_session_state_t      *out_next_state,
    char                     *out_response,
    size_t                    out_response_cap,
    size_t                   *out_response_len
);

/* Network Framing I/O API (io_framing.c) */
int sac_io_read_exact(sac_io_stream_t *stream, void *buf, size_t len);
int sac_io_write_all(sac_io_stream_t *stream, const void *buf, size_t len);
int sac_read_request_frame(
    sac_io_stream_t    *stream,
    sac_frame_header_t *out_host_hdr,
    char               *out_payload,
    size_t              payload_cap
);
int sac_write_request_frame(
    sac_io_stream_t *stream,
    uint8_t          opcode,
    uint32_t         seq,
    const char      *payload,
    size_t           payload_len
);
int sac_write_response_frame(
    sac_io_stream_t         *stream,
    const sac_resp_header_t *host_resp_hdr,
    const char              *payload,
    size_t                   payload_len
);
int sac_read_response_frame(
    sac_io_stream_t   *stream,
    sac_resp_header_t *out_host_resp_hdr,
    char              *out_payload,
    size_t             payload_cap
);

/* Confined Filesystem API (sandbox_fs.c) */
sac_fs_status_t sac_fs_resolve_and_open(
    int         jail_dirfd,
    const char *cwd_rel,
    const char *user_path,
    int         open_flags,
    int        *out_fd,
    char       *out_normalized_rel,
    size_t      norm_cap
);
sac_fs_status_t sac_fs_chdir(
    int         jail_dirfd,
    const char *cwd_rel,
    const char *user_path,
    char       *out_new_cwd_rel,
    size_t      out_cap
);
sac_fs_status_t sac_fs_list_dir(
    int         jail_dirfd,
    const char *cwd_rel,
    const char *user_path,
    char       *out_buf,
    size_t      out_cap,
    size_t     *out_len
);
sac_fs_status_t sac_fs_read_file(
    int         jail_dirfd,
    const char *cwd_rel,
    const char *user_path,
    char       *out_buf,
    size_t      out_cap,
    size_t     *out_len
);

#endif /* SECADMIN_PROTOCOL_H */
