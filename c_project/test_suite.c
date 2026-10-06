/*
 * test_suite.c — Comprehensive C11 Unit & OpenSSL 3.x mTLS 1.3 Integration Tests
 *
 * Verifies all 19 protocol, framing, filesystem, state, and TLS requirements
 * with ZERO calls to system(), popen(), or exec*():
 *  1. Bad magic rejected before dispatch (SAC_ERR_BAD_MAGIC, SAC_DOMAIN_PROTOCOL)
 *  2. Bad version rejected before dispatch (SAC_ERR_BAD_VERSION, SAC_DOMAIN_PROTOCOL)
 *  3. Unknown opcode rejected before dispatch (SAC_ERR_BAD_OPCODE, SAC_DOMAIN_PROTOCOL)
 *  4. Replay / sequence regression rejected (SAC_ERR_SEQUENCE_REGRESSION)
 *  5. Payload too large rejected (SAC_ERR_PAYLOAD_TOO_LARGE)
 *  6. Fragmented read (1-byte chunks & fragmented SSL_write over TLS 1.3) reassembled
 *  7. Partial write (2-byte chunks) completed by sac_io_write_all()
 *  8. Path traversal (../../etc/passwd) blocked (SAC_FS_ERR_PATH_ESCAPE)
 *  9. Symlink escape (symlink to outside and inside jail) blocked (SAC_FS_ERR_PATH_ESCAPE)
 * 10. Non-existent file returns SAC_FS_ERR_NOT_FOUND
 * 11. Permission denied returns SAC_FS_ERR_PERMISSION_DENIED (tested with seteuid(65534))
 * 12. Reading a directory as a file returns SAC_FS_ERR_NOT_REGULAR
 * 13. Output buffer smaller than content returns SAC_FS_ERR_BUFFER_TOO_SMALL
 * 14. `cd sub` followed by `ls .` lists entries inside `sub`
 * 15. `cd sub` followed by `cat nested.txt` reads `sub/nested.txt`
 * 16. Client certificate failure (untrusted client cert rejected by mTLS server)
 * 17. Server certificate failure (untrusted server cert rejected by mTLS client)
 * 18. Hostname / SAN mismatch failure (wrong expected SAN rejected by client)
 * 19. End-to-end client/server TCP loopback integration:
 *     - TLS/SAN failure returns EXIT_FAILURE
 *     - Valid mTLS 1.3 RPC returns EXIT_SUCCESS and expected file payload
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "tls_helpers.h"

/* ==========================================================================
 * Embedded Ephemeral Test PKI (ECDSA P-256, Valid 2026–2036, Testing Only)
 * ========================================================================== */
static const char TEST_CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiDCCAS2gAwIBAgIUFhBDVf1ZxqvzwzhfljppgHJqm6cwCgYIKoZIzj0EAwIw\n"
    "GTEXMBUGA1UEAwwOU2VjQWRtaW5UZXN0Q0EwHhcNMjYxMDA2MTA0MDMyWhcNMzYx\n"
    "MDAzMTA0MDMyWjAZMRcwFQYDVQQDDA5TZWNBZG1pblRlc3RDQTBZMBMGByqGSM49\n"
    "AgEGCCqGSM49AwEHA0IABFCNeWKTjsFuEXpiOmZMpxE0j/E+h2msFjZr63m1xJy8\n"
    "cXmd9WiS3oeNS9WGuseaZ3UVnVSBG1Ug+mzTAq2YLeGjUzBRMB0GA1UdDgQWBBR1\n"
    "ccGgdb81xMLKmzCinKwLSqoslDAfBgNVHSMEGDAWgBR1ccGgdb81xMLKmzCinKwL\n"
    "SqoslDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCFrlhyYwVg\n"
    "udoAVBBXHDDTCBvy84IbfCy3DbjmuAlKbAIhANgNK682U+M5B24BnavFLtBTZXXA\n"
    "69js8q3oN8dlSMJH\n"
    "-----END CERTIFICATE-----\n";

/* Server cert signed by TEST_CA_PEM with SAN: DNS:localhost, IP:127.0.0.1 */
static const char TEST_SERVER_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBjjCCATOgAwIBAgIUZnH/T7CWTwbSjqG1hRPpf10vHNUwCgYIKoZIzj0EAwIw\n"
    "GTEXMBUGA1UEAwwOU2VjQWRtaW5UZXN0Q0EwHhcNMjYxMDA2MTA0MDMyWhcNMzYx\n"
    "MDAzMTA0MDMyWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggq\n"
    "hkjOPQMBBwNCAAQV8v0X2kxnUwbndIDX/+IHahW50YjXYPaNJ872FkQs4yrvujfN\n"
    "Av/3MJO1yHnJmO1mHxy73lOed3ius+QqsL2Qo14wXDAaBgNVHREEEzARgglsb2Nh\n"
    "bGhvc3SHBH8AAAEwHQYDVR0OBBYEFH2HHNgOphv1DGdh3PHJkq9XdnYeMB8GA1Ud\n"
    "IwQYMBaAFHVxwaB1vzXEwsqbMKKcrAtKqiyUMAoGCCqGSM49BAMCA0kAMEYCIQDT\n"
    "zcAvwPQuIaY3BDOLX8J18pAO4dSMmW1up/tj0pswXQIhAMeoLNUF5achM8cTa5IY\n"
    "2RekJFXjUVwkNsbzrseHhHTk\n"
    "-----END CERTIFICATE-----\n";

static const char TEST_SERVER_KEY[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKt6QQssm5IpXfNwv\n"
    "JwmRXgbkYiWDFmc2gNVPWTzv6FOhRANCAAQV8v0X2kxnUwbndIDX/+IHahW50YjX\n"
    "YPaNJ872FkQs4yrvujfNAv/3MJO1yHnJmO1mHxy73lOed3ius+QqsL2Q\n"
    "-----END PRIVATE KEY-----\n";

/* Client cert signed by TEST_CA_PEM */
static const char TEST_CLIENT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBKzCB0QIUZnH/T7CWTwbSjqG1hRPpf10vHNYwCgYIKoZIzj0EAwIwGTEXMBUG\n"
    "A1UEAwwOU2VjQWRtaW5UZXN0Q0EwHhcNMjYxMDA2MTA0MDMyWhcNMzYxMDAzMTA0\n"
    "MDMyWjAXMRUwEwYDVQQDDAxhZG1pbi1jbGllbnQwWTATBgcqhkjOPQIBBggqhkjO\n"
    "PQMBBwNCAARqz56Wwr0Avl1qXMj0Up4+9UJa9+L/rIzpy2U4IDUnIPK3uPt/9e3G\n"
    "qjC5AAiaZO2nqMAbAUh5qZ9Fj8lJJBTVMAoGCCqGSM49BAMCA0kAMEYCIQCZKmTt\n"
    "5cxUTnPVRapI9WEP8QS31xjvNjUtqFeYO6SaBAIhALrQOoa30gbo7QUHvt9+Fy9V\n"
    "il/FyhD0oSMsbc4zLJSE\n"
    "-----END CERTIFICATE-----\n";

static const char TEST_CLIENT_KEY[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgyWMWX0ZCJTfGqp9H\n"
    "1oYDn8ufdox2XlozGVurPjm7eMahRANCAARqz56Wwr0Avl1qXMj0Up4+9UJa9+L/\n"
    "rIzpy2U4IDUnIPK3uPt/9e3GqjC5AAiaZO2nqMAbAUh5qZ9Fj8lJJBTV\n"
    "-----END PRIVATE KEY-----\n";

/* Self-signed untrusted rogue cert/key */
static const char TEST_ROGUE_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBfTCCASOgAwIBAgIUW/D7oGX7MMSW2jOYQ6GFXs/Vci8wCgYIKoZIzj0EAwIw\n"
    "FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MTAwNjEwNDAzMloXDTM2MTAwMzEw\n"
    "NDAzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
    "AQcDQgAEs38ZoS6o0lWCQpKSc3TtrbNied4yiJGUErUdYg9Roq4B6wxhF0Fk3ESi\n"
    "M5Xi2x3nzqqC364/vX08SRmLiHeXGKNTMFEwHQYDVR0OBBYEFBGT/E9H6DTVTieP\n"
    "vf5TNo+S8jinMB8GA1UdIwQYMBaAFBGT/E9H6DTVTiePvf5TNo+S8jinMA8GA1Ud\n"
    "EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgSF2QI4O6wugfvpjrDquOn0HD\n"
    "w+ejoPu8WuzyybJNzY0CIQDjuJyyM9UQEMtphKc9AifSQ6mijGfOD1OR7D4dv/7k\n"
    "iQ==\n"
    "-----END CERTIFICATE-----\n";

static const char TEST_ROGUE_KEY[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgz/1/rzz7M2I2PM7d\n"
    "LMT/aEfLRWjWpN16jkVZRoNVVB6hRANCAASzfxmhLqjSVYJCkpJzdO2ts2J53jKI\n"
    "kZQStR1iD1GirgHrDGEXQWTcRKIzleLbHefOqoLfrj+9fTxJGYuId5cY\n"
    "-----END PRIVATE KEY-----\n";

static void write_file_str(const char *path, const char *content) {
    FILE *fp = fopen(path, "w");
    assert(fp != NULL);
    assert(fputs(content, fp) >= 0);
    fclose(fp);
}

/* ==========================================================================
 * Mock Fragmented / Partial Stream for Deterministic Framing Tests
 * ========================================================================== */
typedef struct {
    uint8_t buf[8192];
    size_t  write_len;
    size_t  read_pos;
    size_t  max_read_chunk;
    size_t  max_write_chunk;
    size_t  read_calls;
    size_t  write_calls;
} mock_frag_buffer_t;

static ssize_t mock_frag_read_cb(void *ctx, void *dst, size_t len) {
    mock_frag_buffer_t *m = (mock_frag_buffer_t *)ctx;
    if (m->read_pos >= m->write_len) {
        return 0;
    }
    size_t avail = m->write_len - m->read_pos;
    size_t take = len;
    if (take > m->max_read_chunk) take = m->max_read_chunk;
    if (take > avail) take = avail;
    memcpy(dst, m->buf + m->read_pos, take);
    m->read_pos += take;
    m->read_calls++;
    return (ssize_t)take;
}

static ssize_t mock_frag_write_cb(void *ctx, const void *src, size_t len) {
    mock_frag_buffer_t *m = (mock_frag_buffer_t *)ctx;
    if (m->write_len >= sizeof(m->buf)) {
        errno = ENOSPC;
        return -1;
    }
    size_t space = sizeof(m->buf) - m->write_len;
    size_t give = len;
    if (give > m->max_write_chunk) give = m->max_write_chunk;
    if (give > space) give = space;
    memcpy(m->buf + m->write_len, src, give);
    m->write_len += give;
    m->write_calls++;
    return (ssize_t)give;
}

/* ==========================================================================
 * Tests 1-5: Protocol Validation & Pre-Dispatch Guarantees
 * ========================================================================== */
static void test_01_to_05_protocol_validation(int jail_dirfd) {
    sac_session_state_t s0 = sac_state_init(true, jail_dirfd);
    sac_session_state_t s_next;
    char resp[512];
    size_t resp_len = 0;

    /* 1. Bad magic */
    sac_frame_header_t bad_magic = {
        .magic = 0xDEADBEEFU,
        .version = SAC_PROTOCOL_VERSION,
        .opcode = SAC_OP_SYS_UNAME,
        .sequence_num = 1U,
        .payload_length = 0U
    };
    sac_error_t e1 = sac_route_dispatch(s0, &bad_magic, "", &s_next, resp, sizeof(resp), &resp_len);
    assert(e1.code == SAC_ERR_BAD_MAGIC);
    assert(e1.domain == SAC_DOMAIN_PROTOCOL);
    assert(s_next.commands_executed == 0U);
    assert(s_next.last_sequence_num == 0U);
    assert(s_next.security_blocks == 1U);
    printf("[PASS] 01. bad_magic rejected before dispatch (commands_executed=0)\n");

    /* 2. Bad version */
    sac_frame_header_t bad_ver = {
        .magic = SAC_MAGIC_BYTES,
        .version = 0x99U,
        .opcode = SAC_OP_SYS_UNAME,
        .sequence_num = 1U,
        .payload_length = 0U
    };
    sac_error_t e2 = sac_route_dispatch(s0, &bad_ver, "", &s_next, resp, sizeof(resp), &resp_len);
    assert(e2.code == SAC_ERR_BAD_VERSION);
    assert(e2.domain == SAC_DOMAIN_PROTOCOL);
    assert(s_next.commands_executed == 0U);
    printf("[PASS] 02. bad_version rejected before dispatch\n");

    /* 3. Unknown opcode */
    sac_frame_header_t bad_op = {
        .magic = SAC_MAGIC_BYTES,
        .version = SAC_PROTOCOL_VERSION,
        .opcode = 0xFEU,
        .sequence_num = 1U,
        .payload_length = 0U
    };
    sac_error_t e3 = sac_route_dispatch(s0, &bad_op, "", &s_next, resp, sizeof(resp), &resp_len);
    assert(e3.code == SAC_ERR_BAD_OPCODE);
    assert(e3.domain == SAC_DOMAIN_PROTOCOL);
    assert(s_next.commands_executed == 0U);
    printf("[PASS] 03. unknown_opcode rejected before dispatch\n");

    /* Execute one valid request at sequence_num = 5 so we can test sequence regression */
    sac_frame_header_t valid_hdr = {
        .magic = SAC_MAGIC_BYTES,
        .version = SAC_PROTOCOL_VERSION,
        .opcode = SAC_OP_SYS_UNAME,
        .sequence_num = 5U,
        .payload_length = 0U
    };
    sac_error_t e_ok = sac_route_dispatch(s0, &valid_hdr, "", &s_next, resp, sizeof(resp), &resp_len);
    assert(e_ok.code == SAC_OK);
    assert(s_next.commands_executed == 1U);
    assert(s_next.last_sequence_num == 5U);

    /* 4. Replay / sequence regression (seq=5 and seq=3 when last_sequence_num=5) */
    sac_session_state_t s_after_replay;
    sac_error_t e4_dup = sac_route_dispatch(s_next, &valid_hdr, "", &s_after_replay, resp, sizeof(resp), &resp_len);
    assert(e4_dup.code == SAC_ERR_SEQUENCE_REGRESSION);
    assert(e4_dup.domain == SAC_DOMAIN_PROTOCOL);
    assert(s_after_replay.commands_executed == 1U);
    assert(s_after_replay.last_sequence_num == 5U);

    sac_frame_header_t reg_hdr = valid_hdr;
    reg_hdr.sequence_num = 3U;
    sac_error_t e4_reg = sac_route_dispatch(s_next, &reg_hdr, "", &s_after_replay, resp, sizeof(resp), &resp_len);
    assert(e4_reg.code == SAC_ERR_SEQUENCE_REGRESSION);
    printf("[PASS] 04. replay and sequence regression rejected\n");

    /* 5. Payload too large (> SAC_MAX_PATH_LEN) */
    sac_frame_header_t huge_hdr = {
        .magic = SAC_MAGIC_BYTES,
        .version = SAC_PROTOCOL_VERSION,
        .opcode = SAC_OP_FS_READFILE,
        .sequence_num = 6U,
        .payload_length = (uint16_t)(SAC_MAX_PATH_LEN + 50U)
    };
    sac_error_t e5 = sac_route_dispatch(s_next, &huge_hdr, "file.txt", &s_after_replay, resp, sizeof(resp), &resp_len);
    assert(e5.code == SAC_ERR_PAYLOAD_TOO_LARGE);
    assert(e5.domain == SAC_DOMAIN_PROTOCOL);
    assert(s_after_replay.commands_executed == 1U);
    printf("[PASS] 05. payload_too_large rejected\n");
}

/* ==========================================================================
 * Tests 6-7: Fragmented Read & Partial Write Network Framing
 * ========================================================================== */
static void test_06_and_07_fragmented_io_framing(void) {
    mock_frag_buffer_t mock;
    memset(&mock, 0, sizeof(mock));
    mock.max_read_chunk  = 1U;
    mock.max_write_chunk = 2U;

    sac_io_stream_t stream = {
        .ctx        = &mock,
        .read_some  = mock_frag_read_cb,
        .write_some = mock_frag_write_cb
    };

    const char *req_arg = "reports/health.txt";
    int w_rc = sac_write_request_frame(&stream, SAC_OP_FS_READFILE, 42U, req_arg, strlen(req_arg));
    assert(w_rc == 0);
    assert(mock.write_calls == 15U);
    printf("[PASS] 07. partial write_all handled across %zu chunked write calls\n", mock.write_calls);

    sac_frame_header_t decoded_hdr;
    char decoded_arg[SAC_MAX_PATH_LEN + 1];
    int r_rc = sac_read_request_frame(&stream, &decoded_hdr, decoded_arg, sizeof(decoded_arg));
    assert(r_rc == 0);
    assert(mock.read_calls == 30U);
    assert(decoded_hdr.magic == SAC_MAGIC_BYTES);
    assert(decoded_hdr.opcode == SAC_OP_FS_READFILE);
    assert(decoded_hdr.sequence_num == 42U);
    assert(strcmp(decoded_arg, req_arg) == 0);
    printf("[PASS] 06. fragmented read_exact reassembled across %zu 1-byte reads\n", mock.read_calls);
}

/* ==========================================================================
 * Tests 8-15: Confined Filesystem, Error Granularity & Stateful `cd`
 * ========================================================================== */
static void test_08_to_15_sandbox_filesystem(const char *jail_path, int jail_dirfd) {
    char buf[512];
    size_t len = 0;

    /* 8. Path traversal (../../etc/passwd) */
    sac_fs_status_t st_trav = sac_fs_read_file(jail_dirfd, ".", "../../etc/passwd", buf, sizeof(buf), &len);
    assert(st_trav == SAC_FS_ERR_PATH_ESCAPE);
    printf("[PASS] 08. path traversal (../../etc/passwd) blocked with SAC_FS_ERR_PATH_ESCAPE\n");

    /* 9. Symlink escape (create symlink inside jail pointing to /etc/hosts and relative symlink) */
    char sym_abs_path[512];
    char sym_rel_path[512];
    snprintf(sym_abs_path, sizeof(sym_abs_path), "%.240s/evil_abs_link", jail_path);
    snprintf(sym_rel_path, sizeof(sym_rel_path), "%.240s/evil_rel_link", jail_path);
    unlink(sym_abs_path);
    unlink(sym_rel_path);
    assert(symlink("/etc/hosts", sym_abs_path) == 0);
    assert(symlink("sub/nested.txt", sym_rel_path) == 0);

    sac_fs_status_t st_sym1 = sac_fs_read_file(jail_dirfd, ".", "evil_abs_link", buf, sizeof(buf), &len);
    sac_fs_status_t st_sym2 = sac_fs_read_file(jail_dirfd, ".", "evil_rel_link", buf, sizeof(buf), &len);
    assert(st_sym1 == SAC_FS_ERR_PATH_ESCAPE);
    assert(st_sym2 == SAC_FS_ERR_PATH_ESCAPE);
    unlink(sym_abs_path);
    unlink(sym_rel_path);
    printf("[PASS] 09. symlink escapes (external & internal symlinks) blocked with SAC_FS_ERR_PATH_ESCAPE\n");

    /* 10. Non-existent file */
    sac_fs_status_t st_noent = sac_fs_read_file(jail_dirfd, ".", "does_not_exist.txt", buf, sizeof(buf), &len);
    assert(st_noent == SAC_FS_ERR_NOT_FOUND);
    printf("[PASS] 10. non-existent file returns SAC_FS_ERR_NOT_FOUND\n");

    /* 11. Permission denied */
    char secret_path[512];
    snprintf(secret_path, sizeof(secret_path), "%.240s/unreadable.txt", jail_path);
    int sfd = open(secret_path, O_CREAT | O_WRONLY | O_TRUNC, 0000);
    assert(sfd >= 0);
    assert(write(sfd, "secret", 6) == 6);
    close(sfd);
    chmod(secret_path, 0000);

    uid_t orig_euid = geteuid();
    if (orig_euid == 0) {
        chmod(jail_path, 0755);
        assert(seteuid(65534) == 0);
    }
    sac_fs_status_t st_perm = sac_fs_read_file(jail_dirfd, ".", "unreadable.txt", buf, sizeof(buf), &len);
    if (orig_euid == 0) {
        assert(seteuid(0) == 0);
    }
    unlink(secret_path);
    assert(st_perm == SAC_FS_ERR_PERMISSION_DENIED);
    printf("[PASS] 11. permission denied file returns SAC_FS_ERR_PERMISSION_DENIED\n");

    /* 12. Reading a directory as a file */
    sac_fs_status_t st_isdir = sac_fs_read_file(jail_dirfd, ".", "sub", buf, sizeof(buf), &len);
    assert(st_isdir == SAC_FS_ERR_NOT_REGULAR);
    printf("[PASS] 12. reading a directory returns SAC_FS_ERR_NOT_REGULAR\n");

    /* 13. Buffer truncation detection */
    char tiny_buf[6];
    sac_fs_status_t st_trunc = sac_fs_read_file(jail_dirfd, ".", "sub/nested.txt", tiny_buf, sizeof(tiny_buf), &len);
    assert(st_trunc == SAC_FS_ERR_BUFFER_TOO_SMALL);
    printf("[PASS] 13. undersized output buffer returns SAC_FS_ERR_BUFFER_TOO_SMALL\n");

    /* 14 & 15. `cd sub` then `ls .` and `cat nested.txt` via Route Dispatcher */
    sac_session_state_t s0 = sac_state_init(true, jail_dirfd);
    sac_session_state_t s1, s2, s3;

    sac_frame_header_t cd_hdr = {
        .magic = SAC_MAGIC_BYTES,
        .version = SAC_PROTOCOL_VERSION,
        .opcode = SAC_OP_FS_CHDIR,
        .sequence_num = 1U,
        .payload_length = 3U
    };
    sac_error_t err_cd = sac_route_dispatch(s0, &cd_hdr, "sub", &s1, buf, sizeof(buf), &len);
    assert(err_cd.code == SAC_OK);
    assert(strcmp(s1.cwd_rel, "sub") == 0);

    sac_frame_header_t ls_hdr = {
        .magic = SAC_MAGIC_BYTES,
        .version = SAC_PROTOCOL_VERSION,
        .opcode = SAC_OP_FS_LISTDIR,
        .sequence_num = 2U,
        .payload_length = 1U
    };
    sac_error_t err_ls = sac_route_dispatch(s1, &ls_hdr, ".", &s2, buf, sizeof(buf), &len);
    assert(err_ls.code == SAC_OK);
    assert(strstr(buf, "nested.txt\n") != NULL);
    printf("[PASS] 14. `cd sub` followed by `ls .` lists entries inside sub/\n");

    sac_frame_header_t cat_hdr = {
        .magic = SAC_MAGIC_BYTES,
        .version = SAC_PROTOCOL_VERSION,
        .opcode = SAC_OP_FS_READFILE,
        .sequence_num = 3U,
        .payload_length = 10U
    };
    sac_error_t err_cat = sac_route_dispatch(s2, &cat_hdr, "nested.txt", &s3, buf, sizeof(buf), &len);
    assert(err_cat.code == SAC_OK);
    assert(strcmp(buf, "hello_from_sub_nested\n") == 0);
    printf("[PASS] 15. `cd sub` followed by `cat nested.txt` reads sub/nested.txt\n");
}

/* ==========================================================================
 * Tests 16-19: Live OpenSSL 3.x mTLS 1.3 Handshake & End-to-End Integration
 * ========================================================================== */
static void run_socketpair_tls_test(
    SSL_CTX    *srv_ctx,
    SSL_CTX    *cli_ctx,
    const char *expected_san,
    bool        expect_success
) {
    int sv[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    pid_t pid = fork();
    assert(pid >= 0);

    if (pid == 0) {
        close(sv[0]);
        SSL *srv_ssl = SSL_new(srv_ctx);
        assert(srv_ssl != NULL);
        SSL_set_fd(srv_ssl, sv[1]);
        int acc = SSL_accept(srv_ssl);
        bool ok = (acc == 1) && sac_verify_accepted_client_cert(srv_ssl);
        if (ok) {
            SSL_shutdown(srv_ssl);
        }
        SSL_free(srv_ssl);
        close(sv[1]);
        _exit(ok ? 0 : 1);
    }

    close(sv[1]);
    SSL *cli_ssl = SSL_new(cli_ctx);
    assert(cli_ssl != NULL);
    SSL_set_fd(cli_ssl, sv[0]);
    assert(sac_configure_client_peer_identity(cli_ssl, expected_san) == 0);

    int conn = SSL_connect(cli_ssl);
    bool cli_ok = (conn == 1) && (SSL_get_verify_result(cli_ssl) == X509_V_OK);
    if (cli_ok) {
        SSL_shutdown(cli_ssl);
    }
    SSL_free(cli_ssl);
    close(sv[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    bool srv_ok = WIFEXITED(status) && (WEXITSTATUS(status) == 0);

    if (expect_success) {
        assert(cli_ok && srv_ok);
    } else {
        assert(!cli_ok || !srv_ok);
    }
}

static void spawn_single_shot_server(
    uint16_t    port,
    const char *ca_pem,
    const char *srv_pem,
    const char *srv_key,
    int         jail_dirfd,
    pid_t      *out_pid
) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(listen_fd >= 0);
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(port);
    assert(bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    assert(listen(listen_fd, 5) == 0);

    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        SSL_CTX *ctx = sac_create_mtls_server_ctx(ca_pem, srv_pem, srv_key);
        assert(ctx != NULL);
        int cfd = accept(listen_fd, NULL, NULL);
        if (cfd >= 0) {
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, cfd);
            if (SSL_accept(ssl) == 1) {
                sac_handle_tls_session(ssl, jail_dirfd);
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(cfd);
        }
        close(listen_fd);
        SSL_CTX_free(ctx);
        _exit(0);
    }
    close(listen_fd);
    *out_pid = pid;
}

static void test_16_to_19_tls_and_e2e_cli(const char *cert_dir, int jail_dirfd) {
    char ca_pem[256], srv_pem[256], srv_key[256], cli_pem[256], cli_key[256], rogue_pem[256], rogue_key[256];
    snprintf(ca_pem, sizeof(ca_pem), "%.180s/ca.pem", cert_dir);
    snprintf(srv_pem, sizeof(srv_pem), "%.180s/server.pem", cert_dir);
    snprintf(srv_key, sizeof(srv_key), "%.180s/server.key", cert_dir);
    snprintf(cli_pem, sizeof(cli_pem), "%.180s/client.pem", cert_dir);
    snprintf(cli_key, sizeof(cli_key), "%.180s/client.key", cert_dir);
    snprintf(rogue_pem, sizeof(rogue_pem), "%.180s/rogue.pem", cert_dir);
    snprintf(rogue_key, sizeof(rogue_key), "%.180s/rogue.key", cert_dir);

    write_file_str(ca_pem, TEST_CA_PEM);
    write_file_str(srv_pem, TEST_SERVER_PEM);
    write_file_str(srv_key, TEST_SERVER_KEY);
    write_file_str(cli_pem, TEST_CLIENT_PEM);
    write_file_str(cli_key, TEST_CLIENT_KEY);
    write_file_str(rogue_pem, TEST_ROGUE_PEM);
    write_file_str(rogue_key, TEST_ROGUE_KEY);

    SSL_CTX *valid_srv_ctx = sac_create_mtls_server_ctx(ca_pem, srv_pem, srv_key);
    SSL_CTX *valid_cli_ctx = sac_create_mtls_client_ctx(ca_pem, cli_pem, cli_key);
    SSL_CTX *rogue_cli_ctx = sac_create_mtls_client_ctx(ca_pem, rogue_pem, rogue_key);
    SSL_CTX *rogue_srv_ctx = sac_create_mtls_server_ctx(ca_pem, rogue_pem, rogue_key);
    assert(valid_srv_ctx && valid_cli_ctx && rogue_cli_ctx && rogue_srv_ctx);

    /* Positive sanity check: valid client + valid server + matching SAN "127.0.0.1" */
    run_socketpair_tls_test(valid_srv_ctx, valid_cli_ctx, "127.0.0.1", true);

    /* 06b. Real OpenSSL TLS 1.3 multi-record fragmented SSL_write / SSL_read test */
    {
        int sv[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        pid_t fpid = fork();
        assert(fpid >= 0);
        if (fpid == 0) {
            close(sv[0]);
            SSL *srv_ssl = SSL_new(valid_srv_ctx);
            assert(srv_ssl != NULL);
            SSL_set_fd(srv_ssl, sv[1]);
            assert(SSL_accept(srv_ssl) == 1);
            sac_io_stream_t s_stream = sac_ssl_stream_make(srv_ssl);
            sac_frame_header_t f_hdr;
            char f_arg[SAC_MAX_PATH_LEN + 1];
            int r_ok = sac_read_request_frame(&s_stream, &f_hdr, f_arg, sizeof(f_arg));
            bool pass = (r_ok == 0 &&
                         f_hdr.magic == SAC_MAGIC_BYTES &&
                         f_hdr.opcode == SAC_OP_FS_READFILE &&
                         f_hdr.sequence_num == 77U &&
                         strcmp(f_arg, "sub/nested.txt") == 0);
            SSL_shutdown(srv_ssl);
            SSL_free(srv_ssl);
            close(sv[1]);
            _exit(pass ? 0 : 1);
        }
        close(sv[1]);
        SSL *cli_ssl = SSL_new(valid_cli_ctx);
        assert(cli_ssl != NULL);
        SSL_set_fd(cli_ssl, sv[0]);
        assert(sac_configure_client_peer_identity(cli_ssl, "127.0.0.1") == 0);
        assert(SSL_connect(cli_ssl) == 1);

        const char *frag_payload = "sub/nested.txt";
        size_t frag_len = strlen(frag_payload);
        sac_frame_header_t net_hdr = {
            .magic          = htonl(SAC_MAGIC_BYTES),
            .version        = SAC_PROTOCOL_VERSION,
            .opcode         = SAC_OP_FS_READFILE,
            .sequence_num   = htonl(77U),
            .payload_length = htons((uint16_t)frag_len)
        };
        uint8_t raw_wire[64];
        memcpy(raw_wire, &net_hdr, sizeof(net_hdr));
        memcpy(raw_wire + sizeof(net_hdr), frag_payload, frag_len);
        size_t total_wire = sizeof(net_hdr) + frag_len;

        /* Transmit in 4 separate TLS 1.3 records (5B, 7B, 6B, remainder) */
        assert(SSL_write(cli_ssl, raw_wire, 5) == 5);
        assert(SSL_write(cli_ssl, raw_wire + 5, 7) == 7);
        assert(SSL_write(cli_ssl, raw_wire + 12, 6) == 6);
        assert(SSL_write(cli_ssl, raw_wire + 18, (int)(total_wire - 18)) == (int)(total_wire - 18));

        SSL_shutdown(cli_ssl);
        SSL_free(cli_ssl);
        close(sv[0]);
        int fst = 0;
        waitpid(fpid, &fst, 0);
        assert(WIFEXITED(fst) && WEXITSTATUS(fst) == 0);
        printf("[PASS] 06b. multi-record fragmented SSL_read over live TLS 1.3 reassembled\n");
    }

    /* 16. Client certificate failure (rogue client cert rejected by mTLS server) */
    run_socketpair_tls_test(valid_srv_ctx, rogue_cli_ctx, "127.0.0.1", false);
    printf("[PASS] 16. untrusted client certificate rejected by mTLS 1.3 server\n");

    /* 17. Server certificate failure (rogue server cert rejected by client) */
    run_socketpair_tls_test(rogue_srv_ctx, valid_cli_ctx, "127.0.0.1", false);
    printf("[PASS] 17. untrusted server certificate rejected by mTLS 1.3 client\n");

    /* 18. Hostname / SAN mismatch failure (valid server cert for localhost/127.0.0.1, client expects wrong SAN) */
    run_socketpair_tls_test(valid_srv_ctx, valid_cli_ctx, "wrong.host.internal", false);
    printf("[PASS] 18. server SAN / hostname mismatch rejected by mTLS 1.3 client\n");

    SSL_CTX_free(valid_srv_ctx);
    SSL_CTX_free(valid_cli_ctx);
    SSL_CTX_free(rogue_cli_ctx);
    SSL_CTX_free(rogue_srv_ctx);

    /* 19a. End-to-end client/server over loopback: TLS SAN failure => EXIT_FAILURE */
    pid_t srv_pid1 = -1;
    uint16_t port1 = 18445;
    spawn_single_shot_server(port1, ca_pem, srv_pem, srv_key, jail_dirfd, &srv_pid1);

    char out_buf[512];
    int fail_rc = sac_client_execute_once(
        "127.0.0.1", port1, ca_pem, cli_pem, cli_key,
        "uname", "", "invalid.example.org", out_buf, sizeof(out_buf)
    );
    int st1 = 0;
    waitpid(srv_pid1, &st1, 0);
    assert(fail_rc == EXIT_FAILURE);
    printf("[PASS] 19a. client returns EXIT_FAILURE on TLS SAN verification failure\n");

    /* 19b. End-to-end client/server over loopback: valid mTLS 1.3 `cat sub/nested.txt` => EXIT_SUCCESS */
    pid_t srv_pid2 = -1;
    uint16_t port2 = 18446;
    spawn_single_shot_server(port2, ca_pem, srv_pem, srv_key, jail_dirfd, &srv_pid2);

    int ok_rc = sac_client_execute_once(
        "127.0.0.1", port2, ca_pem, cli_pem, cli_key,
        "cat", "sub/nested.txt", "localhost", out_buf, sizeof(out_buf)
    );
    int st2 = 0;
    waitpid(srv_pid2, &st2, 0);
    assert(ok_rc == EXIT_SUCCESS);
    assert(strcmp(out_buf, "hello_from_sub_nested\n") == 0);
    printf("[PASS] 19b. End-to-end mTLS 1.3 client/server integration test succeeded\n");

    unlink(ca_pem);
    unlink(srv_pem);
    unlink(srv_key);
    unlink(cli_pem);
    unlink(cli_key);
    unlink(rogue_pem);
    unlink(rogue_key);
}

int main(void) {
    printf("=== Running SecAdminC C11 / POSIX / OpenSSL 3.x Test Suite ===\n");

    char tmp_template[] = "/tmp/secadmin_test_XXXXXX";
    char *tmp_root = mkdtemp(tmp_template);
    assert(tmp_root != NULL);

    char jail_path[256];
    char sub_path[256];
    char nested_file[256];
    char cert_dir[256];

    snprintf(jail_path, sizeof(jail_path), "%.180s/jail", tmp_root);
    snprintf(sub_path, sizeof(sub_path), "%.180s/jail/sub", tmp_root);
    snprintf(nested_file, sizeof(nested_file), "%.180s/jail/sub/nested.txt", tmp_root);
    snprintf(cert_dir, sizeof(cert_dir), "%.180s/certs", tmp_root);

    assert(mkdir(jail_path, 0755) == 0);
    assert(mkdir(sub_path, 0755) == 0);
    assert(mkdir(cert_dir, 0700) == 0);

    write_file_str(nested_file, "hello_from_sub_nested\n");

    int jail_dirfd = open(jail_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    assert(jail_dirfd >= 0);

    test_01_to_05_protocol_validation(jail_dirfd);
    test_06_and_07_fragmented_io_framing();
    test_08_to_15_sandbox_filesystem(jail_path, jail_dirfd);
    test_16_to_19_tls_and_e2e_cli(cert_dir, jail_dirfd);

    close(jail_dirfd);

    unlink(nested_file);
    rmdir(sub_path);
    rmdir(jail_path);
    rmdir(cert_dir);
    rmdir(tmp_root);

    printf("=== ALL 19 C11 & mTLS 1.3 TESTS PASSED ===\n");
    return EXIT_SUCCESS;
}
