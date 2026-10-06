/*
 * tls_helpers.c — OpenSSL 3.x Mutual TLS 1.3 Setup, SAN Identity Checks & SSL_get_error() I/O
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include "tls_helpers.h"

SSL_CTX *sac_create_mtls_server_ctx(
    const char *ca_pem,
    const char *server_cert_pem,
    const char *server_key_pem
) {
    if (!ca_pem || !server_cert_pem || !server_key_pem) {
        return NULL;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        return NULL;
    }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    /* Mandatory Mutual TLS: reject handshake if client omits or fails cert check */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 2);

    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1 ||
        SSL_CTX_use_certificate_file(ctx, server_cert_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, server_key_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

SSL_CTX *sac_create_mtls_client_ctx(
    const char *ca_pem,
    const char *client_cert_pem,
    const char *client_key_pem
) {
    if (!ca_pem || !client_cert_pem || !client_key_pem) {
        return NULL;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        return NULL;
    }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 2);

    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1 ||
        SSL_CTX_use_certificate_file(ctx, client_cert_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, client_key_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

int sac_configure_client_peer_identity(SSL *ssl, const char *expected_host_or_ip) {
    if (!ssl || !expected_host_or_ip || expected_host_or_ip[0] == '\0') {
        return -1;
    }
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    if (!param) {
        return -1;
    }
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

    unsigned char ip_buf[16];
    if (inet_pton(AF_INET, expected_host_or_ip, ip_buf) == 1 ||
        inet_pton(AF_INET6, expected_host_or_ip, ip_buf) == 1) {
        if (X509_VERIFY_PARAM_set1_ip_asc(param, expected_host_or_ip) != 1) {
            return -1;
        }
    } else {
        if (SSL_set1_host(ssl, expected_host_or_ip) != 1 ||
            SSL_set_tlsext_host_name(ssl, expected_host_or_ip) != 1) {
            return -1;
        }
    }
    return 0;
}

bool sac_verify_accepted_client_cert(SSL *ssl) {
    if (!ssl) {
        return false;
    }
    if (SSL_get_version(ssl) == NULL || strcmp(SSL_get_version(ssl), "TLSv1.3") != 0) {
        return false;
    }
    X509 *peer = SSL_get1_peer_certificate(ssl);
    if (!peer) {
        return false;
    }
    X509_free(peer);
    return (SSL_get_verify_result(ssl) == X509_V_OK);
}

static ssize_t ssl_read_some_cb(void *ctx, void *buf, size_t len) {
    SSL *ssl = (SSL *)ctx;
    if (!ssl || !buf || len == 0) {
        return -1;
    }
    int ask = (len > 16384U) ? 16384 : (int)len;
    for (;;) {
        ERR_clear_error();
        int r = SSL_read(ssl, buf, ask);
        if (r > 0) {
            return (ssize_t)r;
        }
        int ssl_err = SSL_get_error(ssl, r);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        if (ssl_err == SSL_ERROR_ZERO_RETURN) {
            return 0;
        }
        errno = EIO;
        return -1;
    }
}

static ssize_t ssl_write_some_cb(void *ctx, const void *buf, size_t len) {
    SSL *ssl = (SSL *)ctx;
    if (!ssl || !buf || len == 0) {
        return -1;
    }
    int ask = (len > 16384U) ? 16384 : (int)len;
    for (;;) {
        ERR_clear_error();
        int w = SSL_write(ssl, buf, ask);
        if (w > 0) {
            return (ssize_t)w;
        }
        int ssl_err = SSL_get_error(ssl, w);
        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
            continue;
        }
        errno = EIO;
        return -1;
    }
}

sac_io_stream_t sac_ssl_stream_make(SSL *ssl) {
    sac_io_stream_t st = {
        .ctx        = ssl,
        .read_some  = ssl_read_some_cb,
        .write_some = ssl_write_some_cb
    };
    return st;
}

void sac_handle_tls_session(SSL *ssl, int jail_dirfd) {
    bool verified = sac_verify_accepted_client_cert(ssl);
    sac_session_state_t state = sac_state_init(verified, jail_dirfd);
    sac_io_stream_t stream = sac_ssl_stream_make(ssl);

    for (;;) {
        sac_frame_header_t req_hdr;
        char arg_buf[SAC_MAX_PATH_LEN + 1];

        if (sac_read_request_frame(&stream, &req_hdr, arg_buf, sizeof(arg_buf)) != 0) {
            break;
        }

        char resp_buf[SAC_MAX_PAYLOAD_LEN];
        size_t resp_len = 0;
        sac_session_state_t next_state = state;

        sac_error_t err = sac_route_dispatch(
            state,
            &req_hdr,
            arg_buf,
            &next_state,
            resp_buf,
            sizeof(resp_buf),
            &resp_len
        );
        state = next_state;

        const char *wire_payload = (err.code == SAC_OK) ? resp_buf : err.message;
        size_t wire_len = (err.code == SAC_OK) ? resp_len : strlen(err.message);

        sac_resp_header_t resp_hdr = {
            .magic          = SAC_MAGIC_BYTES,
            .version        = SAC_PROTOCOL_VERSION,
            .status_code    = (uint8_t)err.code,
            .error_domain   = (uint8_t)err.domain,
            .fs_status      = (uint8_t)err.fs_status,
            .sequence_echo  = req_hdr.sequence_num,
            .payload_length = (uint32_t)wire_len
        };

        if (sac_write_response_frame(&stream, &resp_hdr, wire_payload, wire_len) != 0) {
            break;
        }

        if (err.code == SAC_ERR_PAYLOAD_TOO_LARGE || err.code == SAC_ERR_BAD_MAGIC) {
            break;
        }
    }
}

int sac_parse_cli_opcode(const char *cmd_str, uint8_t *out_opcode) {
    if (!cmd_str || !out_opcode) return -1;
    if (strcmp(cmd_str, "uptime") == 0 || strcmp(cmd_str, "sysinfo") == 0) {
        *out_opcode = SAC_OP_SYS_UPTIME;
        return 0;
    }
    if (strcmp(cmd_str, "uname") == 0) {
        *out_opcode = SAC_OP_SYS_UNAME;
        return 0;
    }
    if (strcmp(cmd_str, "df") == 0 || strcmp(cmd_str, "statvfs") == 0) {
        *out_opcode = SAC_OP_SYS_STATVFS;
        return 0;
    }
    if (strcmp(cmd_str, "ls") == 0) {
        *out_opcode = SAC_OP_FS_LISTDIR;
        return 0;
    }
    if (strcmp(cmd_str, "cat") == 0) {
        *out_opcode = SAC_OP_FS_READFILE;
        return 0;
    }
    if (strcmp(cmd_str, "cd") == 0) {
        *out_opcode = SAC_OP_FS_CHDIR;
        return 0;
    }
    return -1;
}

int sac_client_execute_once(
    const char *host_ip,
    uint16_t    port,
    const char *ca_pem,
    const char *client_pem,
    const char *client_key,
    const char *cmd_str,
    const char *arg,
    const char *expect_san,
    char       *out_resp_buf,
    size_t      out_resp_cap
) {
    if (out_resp_buf && out_resp_cap > 0) {
        out_resp_buf[0] = '\0';
    }
    uint8_t opcode = 0;
    if (sac_parse_cli_opcode(cmd_str, &opcode) != 0) {
        return EXIT_FAILURE;
    }

    const char *safe_arg = arg ? arg : "";
    size_t arg_len = strlen(safe_arg);
    if (arg_len > SAC_MAX_PATH_LEN) {
        return EXIT_FAILURE;
    }

    SSL_CTX *ctx = sac_create_mtls_client_ctx(ca_pem, client_pem, client_key);
    if (!ctx) {
        return EXIT_FAILURE;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, host_ip, &sa.sin_addr) != 1 ||
        connect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(sock);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        close(sock);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    SSL_set_fd(ssl, sock);

    const char *san_target = (expect_san && expect_san[0] != '\0') ? expect_san : host_ip;
    if (sac_configure_client_peer_identity(ssl, san_target) != 0 ||
        SSL_connect(ssl) != 1 ||
        SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    sac_io_stream_t stream = sac_ssl_stream_make(ssl);
    uint32_t seq = 1U;
    int exit_status = EXIT_FAILURE;

    if (sac_write_request_frame(&stream, opcode, seq, safe_arg, arg_len) == 0) {
        sac_resp_header_t resp_hdr;
        char local_buf[SAC_MAX_PAYLOAD_LEN + 1];
        if (sac_read_response_frame(&stream, &resp_hdr, local_buf, sizeof(local_buf)) == 0 &&
            resp_hdr.sequence_echo == seq) {
            if (out_resp_buf && out_resp_cap > 0) {
                strncpy(out_resp_buf, local_buf, out_resp_cap - 1);
                out_resp_buf[out_resp_cap - 1] = '\0';
            }
            if (resp_hdr.status_code == SAC_OK) {
                exit_status = EXIT_SUCCESS;
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return exit_status;
}
