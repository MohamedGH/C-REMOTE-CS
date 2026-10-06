/*
 * tls_server.c — SecAdminC Mutual TLS 1.3 Server Daemon (C11 / OpenSSL 3.x)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "protocol.h"
#include "tls_helpers.h"

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s <port> <ca.pem> <server-cert.pem> <server-key.pem> [jail_dir] [--once]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    uint16_t port = (uint16_t)atoi(argv[1]);
    const char *jail_path = (argc >= 6 && strncmp(argv[5], "--", 2) != 0)
        ? argv[5]
        : SAC_DEFAULT_JAIL_ROOT;
    bool run_once = (argc >= 6 && strcmp(argv[argc - 1], "--once") == 0);

    int jail_dirfd = open(jail_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (jail_dirfd < 0) {
        perror("Failed to open sandbox jail directory");
        return EXIT_FAILURE;
    }

    SSL_CTX *ctx = sac_create_mtls_server_ctx(argv[2], argv[3], argv[4]);
    if (!ctx) {
        fprintf(stderr, "Failed to initialize Mutual TLS 1.3 SSL_CTX\n");
        close(jail_dirfd);
        return EXIT_FAILURE;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        SSL_CTX_free(ctx);
        close(jail_dirfd);
        return EXIT_FAILURE;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listen_fd, 5) != 0) {
        close(listen_fd);
        SSL_CTX_free(ctx);
        close(jail_dirfd);
        return EXIT_FAILURE;
    }

    printf("SecAdminC mTLS 1.3 daemon listening on 127.0.0.1:%u (jail=%s)\n", port, jail_path);
    fflush(stdout);

    int exit_code = EXIT_SUCCESS;
    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (run_once) {
                exit_code = EXIT_FAILURE;
                break;
            }
            continue;
        }
        SSL *ssl = SSL_new(ctx);
        if (!ssl) {
            close(client_fd);
            if (run_once) {
                exit_code = EXIT_FAILURE;
                break;
            }
            continue;
        }
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) == 1) {
            sac_handle_tls_session(ssl, jail_dirfd);
        } else if (run_once) {
            exit_code = EXIT_FAILURE;
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);

        if (run_once) {
            break;
        }
    }

    close(listen_fd);
    SSL_CTX_free(ctx);
    close(jail_dirfd);
    return exit_code;
}
