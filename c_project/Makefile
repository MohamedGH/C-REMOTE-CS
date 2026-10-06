# Makefile — Hardened C11 / POSIX / OpenSSL 3.x Build & Verification
CC       := cc
CFLAGS   := -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic \
            -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
LDFLAGS  := -pie -Wl,-z,relro,-z,now
LDLIBS   := -lssl -lcrypto

COMMON_SRCS := managers.c sandbox_fs.c io_framing.c tls_helpers.c
HEADERS     := protocol.h tls_helpers.h

.PHONY: all test clean

all: secadmin_server secadmin_client secadmin_tests

secadmin_server: tls_server.c $(COMMON_SRCS) $(HEADERS)
	$(CC) $(CFLAGS) tls_server.c $(COMMON_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

secadmin_client: tls_client.c $(COMMON_SRCS) $(HEADERS)
	$(CC) $(CFLAGS) tls_client.c $(COMMON_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

secadmin_tests: test_suite.c $(COMMON_SRCS) $(HEADERS)
	$(CC) $(CFLAGS) test_suite.c $(COMMON_SRCS) $(LDFLAGS) $(LDLIBS) -o $@

test: all
	./secadmin_tests

clean:
	rm -f secadmin_server secadmin_client secadmin_tests
