/*
 * test_suite.c — Automated Unit Tests for SecAdminC C11 Modules
 * Run: make test
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include "protocol.h"

static void test_state_manager_immutability(void) {
    sac_session_state_t s0 = sac_state_init(true);
    sac_session_state_t s1 = sac_state_advance_seq(s0, 10U);
    sac_session_state_t s2 = sac_state_record_block(s1);

    assert(s0.last_sequence_num == 0U);
    assert(s1.last_sequence_num == 10U);
    assert(s1.commands_executed == 1U);
    assert(s2.security_blocks == 1U);
    printf("[PASS] test_state_manager_immutability\n");
}

static void test_error_manager_classification(void) {
    sac_error_t e22 = sac_error_make(SAC_ERR_PATH_TRAVERSAL, "escaped root");
    sac_error_t e78 = sac_error_make(SAC_ERR_SHELL_METACHAR, "semicolon injection");

    assert(strcmp(e22.cwe_id, "CWE-22") == 0);
    assert(strcmp(e78.cwe_id, "CWE-78") == 0);
    printf("[PASS] test_error_manager_classification\n");
}

static void test_route_manager_and_cwe78_guard(void) {
    sac_session_state_t s0 = sac_state_init(true);
    sac_session_state_t s_next;
    char resp[1024];

    /* 1. Valid OP_SYS_UNAME */
    sac_frame_header_t valid_hdr = {
        .magic = SAC_MAGIC_BYTES,
        .version = SAC_PROTOCOL_VERSION,
        .opcode = SAC_OP_SYS_UNAME,
        .sequence_num = 1U,
        .payload_length = 0U
    };
    sac_error_t err1 = sac_route_dispatch(s0, &valid_hdr, "", &s_next, resp, sizeof(resp));
    assert(err1.code == SAC_OK);
    assert(s_next.last_sequence_num == 1U);

    /* 2. Replay Attack (same sequence_num = 1U) must be blocked */
    sac_session_state_t s_replay;
    sac_error_t err_replay = sac_route_dispatch(s_next, &valid_hdr, "", &s_replay, resp, sizeof(resp));
    assert(err_replay.code == SAC_ERR_REPLAY_SEQUENCE);

    /* 3. CWE-78 Shell Metacharacter Injection must be blocked */
    sac_frame_header_t inj_hdr = valid_hdr;
    inj_hdr.opcode = SAC_OP_FS_LISTDIR;
    inj_hdr.sequence_num = 2U;
    sac_error_t err_inj = sac_route_dispatch(s_next, &inj_hdr, "logs; id", &s_replay, resp, sizeof(resp));
    assert(err_inj.code == SAC_ERR_SHELL_METACHAR);
    assert(s_replay.security_blocks == 1U);

    printf("[PASS] test_route_manager_and_cwe78_guard\n");
}

static void test_sandbox_fs_cwe22_containment(void) {
    char resolved[SAC_MAX_PATH_LEN];
    /* Using /tmp as a test jail root that exists on all POSIX hosts */
    int escape_rc = sac_verify_within_jail("/tmp", "../../etc/passwd", resolved, sizeof(resolved));
    assert(escape_rc == -1);
    printf("[PASS] test_sandbox_fs_cwe22_containment\n");
}

int main(void) {
    printf("Running SecAdminC C11 Functional & Security Test Suite...\n");
    test_state_manager_immutability();
    test_error_manager_classification();
    test_route_manager_and_cwe78_guard();
    test_sandbox_fs_cwe22_containment();
    printf("All 4 C11 test suites passed successfully.\n");
    return EXIT_SUCCESS;
}
