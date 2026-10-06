/*
 * sandbox_fs.c — Strict Directory Jail & Safe File Reader (C11 / POSIX.1-2008)
 * Prevents CWE-22 Path Traversal and symlink escape attacks.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "protocol.h"

int sac_verify_within_jail(const char *jail_root, const char *user_rel_path, char *resolved_out, size_t out_sz) {
    char candidate[PATH_MAX];
    char canonical_jail[PATH_MAX];
    char canonical_target[PATH_MAX];

    if (!jail_root || !user_rel_path || strchr(user_rel_path, '\\') != NULL) {
        return -1;
    }
    if (realpath(jail_root, canonical_jail) == NULL) {
        return -1;
    }
    int n = snprintf(candidate, sizeof(candidate), "%s/%s", canonical_jail, user_rel_path);
    if (n < 0 || (size_t)n >= sizeof(candidate)) {
        return -1;
    }
    if (realpath(candidate, canonical_target) == NULL) {
        return -1;
    }

    size_t jail_len = strlen(canonical_jail);
    if (strncmp(canonical_target, canonical_jail, jail_len) != 0 ||
        (canonical_target[jail_len] != '\0' && canonical_target[jail_len] != '/')) {
        /* CWE-22 Path Traversal blocked */
        return -1;
    }
    strncpy(resolved_out, canonical_target, out_sz - 1);
    resolved_out[out_sz - 1] = '\0';
    return 0;
}

int sac_sandbox_list_dir(const char *jail_root, const char *rel_path, char *out_buf, size_t out_cap) {
    char safe_path[PATH_MAX];
    if (sac_verify_within_jail(jail_root, rel_path ? rel_path : ".", safe_path, sizeof(safe_path)) != 0) {
        return -1;
    }
    int dir_fd = open(safe_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir_fd < 0) return -1;

    DIR *dirp = fdopendir(dir_fd);
    if (!dirp) {
        close(dir_fd);
        return -1;
    }
    size_t used = 0;
    out_buf[0] = '\0';
    struct dirent *dp;
    while ((dp = readdir(dirp)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) continue;
        int written = snprintf(out_buf + used, out_cap - used, "%s\n", dp->d_name);
        if (written < 0 || (size_t)written >= out_cap - used) break;
        used += (size_t)written;
    }
    closedir(dirp);
    return 0;
}

int sac_sandbox_read_file(const char *jail_root, const char *rel_path, char *out_buf, size_t out_cap) {
    char safe_path[PATH_MAX];
    if (sac_verify_within_jail(jail_root, rel_path, safe_path, sizeof(safe_path)) != 0) {
        return -1;
    }
    int fd = open(safe_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    ssize_t bytes_read = read(fd, out_buf, out_cap - 1);
    close(fd);
    if (bytes_read < 0) return -1;
    out_buf[bytes_read] = '\0';
    return 0;
}
