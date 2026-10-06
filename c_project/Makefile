# Makefile — Hardened C11 Build & Test Configuration
CC       := cc
CFLAGS   := -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic \
            -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=3
LDFLAGS  := -pie -Wl,-z,relro,-z,now
LDLIBS   := -lssl -lcrypto

.PHONY: all test clean

all: secadmin_server secadmin_client secadmin_tests

secadmin_server: tls_server.c managers.c sandbox_fs.c protocol.h
	$(CC) $(CFLAGS) tls_server.c managers.c sandbox_fs.c $(LDFLAGS) $(LDLIBS) -o $@

secadmin_client: tls_client.c protocol.h
	$(CC) $(CFLAGS) tls_client.c $(LDFLAGS) $(LDLIBS) -o $@

secadmin_tests: test_suite.c managers.c sandbox_fs.c protocol.h
	$(CC) $(CFLAGS) test_suite.c managers.c sandbox_fs.c $(LDFLAGS) -o $@

test: secadmin_tests
	./secadmin_tests

clean:
	rm -f secadmin_server secadmin_client secadmin_tests
