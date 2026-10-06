/*
 * tls_client.c — SecAdminC Mutual TLS 1.3 Client CLI (C11 / OpenSSL 3.x)
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protocol.h"
#include "tls_helpers.h"

int main(int argc, char **argv) {
    if (argc < 7) {
        fprintf(stderr,
                "Usage: %s <host_ip> <port> <ca.pem> <client.pem> <client.key> <cmd> [arg] [--expect-host <san>]\n",
                argv[0]);
        return EXIT_FAILURE;
    }

    const char *host_ip    = argv[1];
    uint16_t    port       = (uint16_t)atoi(argv[2]);
    const char *ca_pem     = argv[3];
    const char *client_pem = argv[4];
    const char *client_key = argv[5];
    const char *cmd_str    = argv[6];
    const char *arg        = "";
    const char *expect_san = host_ip;

    for (int i = 7; i < argc; ++i) {
        if (strcmp(argv[i], "--expect-host") == 0 && i + 1 < argc) {
            expect_san = argv[++i];
        } else {
            arg = argv[i];
        }
    }

    char resp_buf[SAC_MAX_PAYLOAD_LEN + 1];
    int rc = sac_client_execute_once(
        host_ip,
        port,
        ca_pem,
        client_pem,
        client_key,
        cmd_str,
        arg,
        expect_san,
        resp_buf,
        sizeof(resp_buf)
    );

    if (rc == EXIT_SUCCESS) {
        fputs(resp_buf, stdout);
        return EXIT_SUCCESS;
    }
    if (resp_buf[0] != '\0') {
        fprintf(stderr, "%s", resp_buf);
    } else {
        fprintf(stderr, "Error: mTLS 1.3 RPC execution failed.\n");
    }
    return EXIT_FAILURE;
}
