/*
 * tls_server.c — Complete SecAdminC Mutual TLS 1.3 Server Daemon (C11 / OpenSSL 3.x)
 * Compile: cc -std=c11 -Wall -Wextra -Werror -O2 tls_server.c managers.c sandbox_fs.c -lssl -lcrypto -o secadmin_server
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "protocol.h"

static SSL_CTX *create_mtls_server_ctx(const char *ca_pem, const char *cert_pem, const char *key_pem) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 2);

    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1 ||
        SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static void handle_tls_session(SSL *ssl) {
    X509 *peer = SSL_get_peer_certificate(ssl);
    bool verified = (peer != NULL && SSL_get_verify_result(ssl) == X509_V_OK);
    if (peer) X509_free(peer);

    sac_session_state_t state = sac_state_init(verified);
    sac_frame_header_t net_hdr;

    while (SSL_read(ssl, &net_hdr, sizeof(net_hdr)) == (int)sizeof(net_hdr)) {
        sac_frame_header_t host_hdr = {
            .magic          = ntohl(net_hdr.magic),
            .version        = net_hdr.version,
            .opcode         = net_hdr.opcode,
            .sequence_num   = ntohl(net_hdr.sequence_num),
            .payload_length = ntohs(net_hdr.payload_length)
        };

        char arg_buf[SAC_MAX_PATH_LEN + 1];
        memset(arg_buf, 0, sizeof(arg_buf));

        if (host_hdr.payload_length > SAC_MAX_PATH_LEN) {
            const char *msg = "ERR payload exceeds SAC_MAX_PATH_LEN\n";
            SSL_write(ssl, msg, (int)strlen(msg));
            break;
        }
        if (host_hdr.payload_length > 0) {
            int r = SSL_read(ssl, arg_buf, host_hdr.payload_length);
            if (r != (int)host_hdr.payload_length) break;
            arg_buf[host_hdr.payload_length] = '\0';
        }

        char resp_buf[SAC_MAX_PAYLOAD_LEN];
        memset(resp_buf, 0, sizeof(resp_buf));
        sac_session_state_t next_state = state;

        sac_error_t err = sac_route_dispatch(
            state, &host_hdr, arg_buf, &next_state, resp_buf, sizeof(resp_buf)
        );
        state = next_state;

        if (err.code != SAC_OK) {
            SSL_write(ssl, err.message, (int)strlen(err.message));
        } else {
            SSL_write(ssl, resp_buf, (int)strlen(resp_buf));
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <port> <ca.pem> <server-cert.pem> <server-key.pem>\n", argv[0]);
        return EXIT_FAILURE;
    }
    uint16_t port = (uint16_t)atoi(argv[1]);
    SSL_CTX *ctx = create_mtls_server_ctx(argv[2], argv[3], argv[4]);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize Mutual TLS 1.3 SSL_CTX\n");
        return EXIT_FAILURE;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listen_fd, 5) != 0) {
        close(listen_fd);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    printf("SecAdminC mTLS 1.3 daemon listening on 127.0.0.1:%u (jail=%s)\n", port, SAC_JAIL_ROOT);
    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) continue;
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) == 1) {
            handle_tls_session(ssl);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
}
