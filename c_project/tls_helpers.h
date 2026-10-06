/*
 * tls_helpers.h — OpenSSL 3.x Mutual TLS 1.3 Context, Identity Verification & Stream I/O
 */
#ifndef SECADMIN_TLS_HELPERS_H
#define SECADMIN_TLS_HELPERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "protocol.h"

SSL_CTX *sac_create_mtls_server_ctx(
    const char *ca_pem,
    const char *server_cert_pem,
    const char *server_key_pem
);

SSL_CTX *sac_create_mtls_client_ctx(
    const char *ca_pem,
    const char *client_cert_pem,
    const char *client_key_pem
);

/*
 * Configures strict server identity verification (DNS SAN or IP SAN) on a client SSL object
 * prior to SSL_connect(). Returns 0 on success, -1 on failure.
 */
int sac_configure_client_peer_identity(SSL *ssl, const char *expected_host_or_ip);

/*
 * Verifies that an accepted server SSL session negotiated TLSv1.3 and presented
 * a valid, CA-verified client X.509 certificate.
 */
bool sac_verify_accepted_client_cert(SSL *ssl);

/*
 * Binds an OpenSSL SSL* handle into a sac_io_stream_t using SSL_get_error()-aware
 * read/write callbacks.
 */
sac_io_stream_t sac_ssl_stream_make(SSL *ssl);

/*
 * Handles a single accepted SSL session using sac_read_request_frame,
 * sac_route_dispatch, and sac_write_response_frame.
 */
void sac_handle_tls_session(SSL *ssl, int jail_dirfd);

/*
 * Maps CLI command token ("uptime", "sysinfo", "uname", "df", "statvfs", "ls", "cat", "cd")
 * to its allowlisted sac_opcode_t enum value. Returns 0 on match, -1 if not allowlisted.
 */
int sac_parse_cli_opcode(const char *cmd_str, uint8_t *out_opcode);

/*
 * Executes a single client RPC over mTLS 1.3 to host_ip:port, verifying server
 * certificate chain AND expected_san. Returns EXIT_SUCCESS (0) on success and
 * EXIT_FAILURE (non-zero) on any socket, TLS, framing, or server dispatch error.
 */
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
);

#endif /* SECADMIN_TLS_HELPERS_H */
