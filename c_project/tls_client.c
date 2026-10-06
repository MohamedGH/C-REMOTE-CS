/*
 * tls_client.c — Complete SecAdminC Mutual TLS 1.3 Client CLI (C11 / OpenSSL 3.x)
 * Compile: cc -std=c11 -Wall -Wextra -Werror -O2 tls_client.c -lssl -lcrypto -o secadmin_client
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

static SSL_CTX *create_mtls_client_ctx(const char *ca_pem, const char *client_cert, const char *client_key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1 ||
        SSL_CTX_use_certificate_file(ctx, client_cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int parse_cli_opcode(const char *cmd_str, uint8_t *out_opcode) {
    if (strcmp(cmd_str, "uptime") == 0 || strcmp(cmd_str, "sysinfo") == 0) {
        *out_opcode = SAC_OP_SYS_UPTIME;
        return 0;
    }
    if (strcmp(cmd_str, "uname") == 0) {
        *out_opcode = SAC_OP_SYS_UNAME;
        return 0;
    }
    if (strcmp(cmd_str, "df") == 0) {
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

static int send_opcode_frame(SSL *ssl, uint8_t opcode, uint32_t seq, const char *path_arg) {
    size_t arg_len = path_arg ? strlen(path_arg) : 0;
    if (arg_len > SAC_MAX_PATH_LEN) return -1;

    sac_frame_header_t hdr = {
        .magic          = htonl(SAC_MAGIC_BYTES),
        .version        = SAC_PROTOCOL_VERSION,
        .opcode         = opcode,
        .sequence_num   = htonl(seq),
        .payload_length = htons((uint16_t)arg_len)
    };

    if (SSL_write(ssl, &hdr, sizeof(hdr)) <= 0) return -1;
    if (arg_len > 0 && SSL_write(ssl, path_arg, (int)arg_len) <= 0) return -1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr, "Usage: %s <host_ip> <port> <ca.pem> <client.pem> <client.key> <cmd> [arg]\n", argv[0]);
        return EXIT_FAILURE;
    }
    uint8_t opcode = 0;
    if (parse_cli_opcode(argv[6], &opcode) != 0) {
        fprintf(stderr, "Error: Command '%s' is not in the allowlisted opcode table.\n", argv[6]);
        return EXIT_FAILURE;
    }
    const char *arg = (argc >= 8) ? argv[7] : "";

    SSL_CTX *ctx = create_mtls_client_ctx(argv[3], argv[4], argv[5]);
    if (!ctx) return EXIT_FAILURE;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &sa.sin_addr);

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(sock);
        SSL_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) == 1 && send_opcode_frame(ssl, opcode, 1U, arg) == 0) {
        char buf[SAC_MAX_PAYLOAD_LEN];
        int n = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            fputs(buf, stdout);
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return EXIT_SUCCESS;
}
