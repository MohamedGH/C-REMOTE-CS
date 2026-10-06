/*
 * sandbox_fs.c — Confined Directory Resolution & Safe File Access (Linux / POSIX)
 *
 * Security & TOCTOU Architecture:
 * 1. Primary Mechanism (Linux >= 5.6):
 *    Uses openat2(jail_dirfd, rel_path, &how, sizeof(how)) with:
 *      RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
 *    This delegates path traversal and symlink rejection atomically to the Linux VFS
 *    anchored at the open directory descriptor `jail_dirfd`.
 * 2. Documented Fallback (when SYS_openat2 returns ENOSYS or non-Linux POSIX):
 *    Traverses path components one by one via openat(cur_fd, token, O_NOFOLLOW | O_CLOEXEC),
 *    maintaining an explicit depth counter so ".." at depth 0 is rejected with
 *    SAC_FS_ERR_PATH_ESCAPE.
 *    Limitation of fallback: While O_NOFOLLOW at each hop blocks symlinks at every
 *    component, user-space step-by-step traversal without kernel RESOLVE_BENEATH
 *    cannot prevent a concurrent privileged directory rename race (CWE-367) inside
 *    the jail hierarchy. Therefore, Linux openat2(RESOLVE_BENEATH) is always tried first.
 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "protocol.h"

#if defined(__linux__) && defined(SYS_openat2)
#include <linux/openat2.h>
#define SAC_HAS_LINUX_OPENAT2 1
#else
#define SAC_HAS_LINUX_OPENAT2 0
#endif

static sac_fs_status_t map_errno_to_fs_status(int err_no, bool expecting_dir) {
    switch (err_no) {
        case ENOENT:
            return SAC_FS_ERR_NOT_FOUND;
        case EACCES:
        case EPERM:
            return SAC_FS_ERR_PERMISSION_DENIED;
        case ELOOP:
        case EXDEV:
            return SAC_FS_ERR_PATH_ESCAPE;
        case ENOTDIR:
            return SAC_FS_ERR_NOT_DIR;
        case EISDIR:
            return expecting_dir ? SAC_FS_OK : SAC_FS_ERR_NOT_REGULAR;
        case ENAMETOOLONG:
            return SAC_FS_ERR_BUFFER_TOO_SMALL;
        default:
            return SAC_FS_ERR_IO;
    }
}

/*
 * Purely normalizes (cwd_rel + "/" + user_path) into a relative path inside the jail,
 * rejecting any ".." segment that attempts to ascend above the jail root (depth < 0),
 * backslashes, control characters, or absolute paths outside "/srv/sandbox".
 */
static sac_fs_status_t normalize_jail_relative_path(
    const char *cwd_rel,
    const char *user_path,
    char       *out_rel,
    size_t      out_cap
) {
    if (!out_rel || out_cap < 2) {
        return SAC_FS_ERR_BUFFER_TOO_SMALL;
    }

    const char *raw = (user_path && user_path[0] != '\0') ? user_path : ".";

    /* Reject backslashes or ASCII control characters */
    for (size_t i = 0; raw[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)raw[i];
        if (c == '\\' || c < 0x20 || c == 0x7f) {
            return SAC_FS_ERR_PATH_ESCAPE;
        }
    }

    char combined[SAC_MAX_PATH_LEN * 2 + 4];
    if (raw[0] == '/') {
        /* Allow "/srv/sandbox" prefix as alias for jail root; reject other absolute paths */
        size_t root_len = strlen(SAC_DEFAULT_JAIL_ROOT);
        if (strncmp(raw, SAC_DEFAULT_JAIL_ROOT, root_len) == 0 &&
            (raw[root_len] == '\0' || raw[root_len] == '/')) {
            const char *sub = raw + root_len;
            while (*sub == '/') sub++;
            snprintf(combined, sizeof(combined), "%s", (*sub) ? sub : ".");
        } else {
            return SAC_FS_ERR_PATH_ESCAPE;
        }
    } else {
        const char *base = (cwd_rel && cwd_rel[0] != '\0' && strcmp(cwd_rel, ".") != 0)
            ? cwd_rel
            : "";
        if (base[0] != '\0') {
            int n = snprintf(combined, sizeof(combined), "%s/%s", base, raw);
            if (n < 0 || (size_t)n >= sizeof(combined)) {
                return SAC_FS_ERR_BUFFER_TOO_SMALL;
            }
        } else {
            int n = snprintf(combined, sizeof(combined), "%s", raw);
            if (n < 0 || (size_t)n >= sizeof(combined)) {
                return SAC_FS_ERR_BUFFER_TOO_SMALL;
            }
        }
    }

    /* Tokenize and track depth strictly >= 0 */
    const char *segments[128];
    size_t seg_lens[128];
    size_t depth = 0;

    const char *p = combined;
    while (*p != '\0') {
        while (*p == '/') p++;
        if (*p == '\0') break;
        const char *start = p;
        while (*p != '\0' && *p != '/') p++;
        size_t len = (size_t)(p - start);

        if (len == 1 && start[0] == '.') {
            continue;
        }
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            if (depth == 0) {
                /* Attempted to traverse above jail root */
                return SAC_FS_ERR_PATH_ESCAPE;
            }
            depth--;
            continue;
        }
        if (depth >= 128) {
            return SAC_FS_ERR_BUFFER_TOO_SMALL;
        }
        segments[depth] = start;
        seg_lens[depth] = len;
        depth++;
    }

    if (depth == 0) {
        strncpy(out_rel, ".", out_cap - 1);
        out_rel[out_cap - 1] = '\0';
        return SAC_FS_OK;
    }

    size_t pos = 0;
    for (size_t i = 0; i < depth; ++i) {
        size_t need = seg_lens[i] + (i + 1 < depth ? 1U : 0U);
        if (pos + need >= out_cap) {
            return SAC_FS_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(out_rel + pos, segments[i], seg_lens[i]);
        pos += seg_lens[i];
        if (i + 1 < depth) {
            out_rel[pos++] = '/';
        }
    }
    out_rel[pos] = '\0';
    return SAC_FS_OK;
}

/*
 * Fallback step-by-step openat() walker when openat2() is unavailable.
 * Opens each directory segment with O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
 * and opens the final component with (open_flags | O_NOFOLLOW | O_CLOEXEC).
 */
static sac_fs_status_t fallback_openat_walk(
    int         jail_dirfd,
    const char *rel_path,
    int         open_flags,
    int        *out_fd
) {
    bool expecting_dir = (open_flags & O_DIRECTORY) != 0;

    if (strcmp(rel_path, ".") == 0) {
        int dup_fd = openat(jail_dirfd, ".", open_flags | O_NOFOLLOW | O_CLOEXEC);
        if (dup_fd < 0) {
            return map_errno_to_fs_status(errno, expecting_dir);
        }
        *out_fd = dup_fd;
        return SAC_FS_OK;
    }

    char temp[SAC_MAX_PATH_LEN];
    size_t rel_len = strlen(rel_path);
    if (rel_len >= sizeof(temp)) {
        return SAC_FS_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(temp, rel_path, rel_len + 1);

    int cur_fd = jail_dirfd;
    bool cur_is_owned = false;
    char *cursor = temp;

    while (cursor && *cursor != '\0') {
        char *slash = strchr(cursor, '/');
        bool is_last = (slash == NULL);
        if (slash) {
            *slash = '\0';
        }

        int flags = is_last
            ? (open_flags | O_NOFOLLOW | O_CLOEXEC)
            : (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

        int next_fd = openat(cur_fd, cursor, flags);
        int saved_errno = errno;

        if (cur_is_owned) {
            close(cur_fd);
        }

        if (next_fd < 0) {
            /* On POSIX, openat(O_NOFOLLOW) on a symlink fails with ELOOP (or EMLINK/EFTYPE on BSDs) */
            if (saved_errno == ELOOP) {
                return SAC_FS_ERR_PATH_ESCAPE;
            }
            if (!is_last && saved_errno == ENOTDIR) {
                /* Intermediate component was a symlink or regular file */
                struct stat lst;
                if (fstatat(jail_dirfd, rel_path, &lst, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(lst.st_mode)) {
                    return SAC_FS_ERR_PATH_ESCAPE;
                }
                return SAC_FS_ERR_NOT_DIR;
            }
            return map_errno_to_fs_status(saved_errno, expecting_dir);
        }

        if (is_last) {
            *out_fd = next_fd;
            return SAC_FS_OK;
        }

        cur_fd = next_fd;
        cur_is_owned = true;
        cursor = slash + 1;
    }

    if (cur_is_owned) {
        close(cur_fd);
    }
    return SAC_FS_ERR_IO;
}

sac_fs_status_t sac_fs_resolve_and_open(
    int         jail_dirfd,
    const char *cwd_rel,
    const char *user_path,
    int         open_flags,
    int        *out_fd,
    char       *out_normalized_rel,
    size_t      norm_cap
) {
    if (jail_dirfd < 0 || !out_fd) {
        return SAC_FS_ERR_IO;
    }
    *out_fd = -1;

    char norm_rel[SAC_MAX_PATH_LEN];
    sac_fs_status_t norm_st = normalize_jail_relative_path(
        cwd_rel,
        user_path,
        norm_rel,
        sizeof(norm_rel)
    );
    if (norm_st != SAC_FS_OK) {
        return norm_st;
    }

    if (out_normalized_rel && norm_cap > 0) {
        size_t norm_len = strlen(norm_rel);
        if (norm_len >= norm_cap) {
            return SAC_FS_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(out_normalized_rel, norm_rel, norm_len + 1);
    }

#if SAC_HAS_LINUX_OPENAT2
    struct open_how how;
    memset(&how, 0, sizeof(how));
    how.flags = (uint64_t)(open_flags | O_CLOEXEC | O_NOFOLLOW);
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;

    /* Pass original user_path when cwd_rel is "." so kernel RESOLVE_BENEATH also checks raw traversal */
    char kernel_rel[SAC_MAX_PATH_LEN * 2 + 4];
    const char *raw = (user_path && user_path[0]) ? user_path : ".";
    if (raw[0] != '/') {
        if (cwd_rel && cwd_rel[0] && strcmp(cwd_rel, ".") != 0) {
            snprintf(kernel_rel, sizeof(kernel_rel), "%s/%s", cwd_rel, raw);
        } else {
            snprintf(kernel_rel, sizeof(kernel_rel), "%s", raw);
        }
    } else {
        snprintf(kernel_rel, sizeof(kernel_rel), "%s", norm_rel);
    }

    long fd = syscall(SYS_openat2, jail_dirfd, kernel_rel, &how, sizeof(how));
    if (fd >= 0) {
        *out_fd = (int)fd;
        return SAC_FS_OK;
    }
    if (errno != ENOSYS && errno != EPERM) {
        return map_errno_to_fs_status(errno, (open_flags & O_DIRECTORY) != 0);
    }
#endif

    return fallback_openat_walk(jail_dirfd, norm_rel, open_flags, out_fd);
}

sac_fs_status_t sac_fs_chdir(
    int         jail_dirfd,
    const char *cwd_rel,
    const char *user_path,
    char       *out_new_cwd_rel,
    size_t      out_cap
) {
    if (!out_new_cwd_rel || out_cap == 0) {
        return SAC_FS_ERR_BUFFER_TOO_SMALL;
    }
    int dir_fd = -1;
    char norm_rel[SAC_MAX_PATH_LEN];
    sac_fs_status_t st = sac_fs_resolve_and_open(
        jail_dirfd,
        cwd_rel,
        user_path,
        O_RDONLY | O_DIRECTORY,
        &dir_fd,
        norm_rel,
        sizeof(norm_rel)
    );
    if (st != SAC_FS_OK) {
        return st;
    }
    struct stat sb;
    if (fstat(dir_fd, &sb) != 0) {
        int e = errno;
        close(dir_fd);
        return map_errno_to_fs_status(e, true);
    }
    close(dir_fd);
    if (!S_ISDIR(sb.st_mode)) {
        return SAC_FS_ERR_NOT_DIR;
    }
    size_t norm_len = strlen(norm_rel);
    if (norm_len >= out_cap) {
        return SAC_FS_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(out_new_cwd_rel, norm_rel, norm_len + 1);
    return SAC_FS_OK;
}

sac_fs_status_t sac_fs_list_dir(
    int         jail_dirfd,
    const char *cwd_rel,
    const char *user_path,
    char       *out_buf,
    size_t      out_cap,
    size_t     *out_len
) {
    if (!out_buf || out_cap < 2) {
        return SAC_FS_ERR_BUFFER_TOO_SMALL;
    }
    out_buf[0] = '\0';
    if (out_len) *out_len = 0;

    int dir_fd = -1;
    sac_fs_status_t st = sac_fs_resolve_and_open(
        jail_dirfd,
        cwd_rel,
        (user_path && user_path[0]) ? user_path : ".",
        O_RDONLY | O_DIRECTORY,
        &dir_fd,
        NULL,
        0
    );
    if (st != SAC_FS_OK) {
        return st;
    }

    DIR *dirp = fdopendir(dir_fd);
    if (!dirp) {
        int e = errno;
        close(dir_fd);
        return map_errno_to_fs_status(e, true);
    }

    size_t used = 0;
    struct dirent *dp;
    while ((dp = readdir(dirp)) != NULL) {
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }
        size_t name_len = strlen(dp->d_name);
        if (used + name_len + 1 >= out_cap) {
            closedir(dirp);
            out_buf[0] = '\0';
            return SAC_FS_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(out_buf + used, dp->d_name, name_len);
        used += name_len;
        out_buf[used++] = '\n';
        out_buf[used] = '\0';
    }
    closedir(dirp);
    if (out_len) *out_len = used;
    return SAC_FS_OK;
}

sac_fs_status_t sac_fs_read_file(
    int         jail_dirfd,
    const char *cwd_rel,
    const char *user_path,
    char       *out_buf,
    size_t      out_cap,
    size_t     *out_len
) {
    if (!out_buf || out_cap < 2) {
        return SAC_FS_ERR_BUFFER_TOO_SMALL;
    }
    out_buf[0] = '\0';
    if (out_len) *out_len = 0;

    if (!user_path || user_path[0] == '\0') {
        return SAC_FS_ERR_NOT_FOUND;
    }

    int fd = -1;
    sac_fs_status_t st = sac_fs_resolve_and_open(
        jail_dirfd,
        cwd_rel,
        user_path,
        O_RDONLY,
        &fd,
        NULL,
        0
    );
    if (st != SAC_FS_OK) {
        return st;
    }

    struct stat sb;
    if (fstat(fd, &sb) != 0) {
        int e = errno;
        close(fd);
        return map_errno_to_fs_status(e, false);
    }
    if (S_ISDIR(sb.st_mode) || !S_ISREG(sb.st_mode)) {
        close(fd);
        return SAC_FS_ERR_NOT_REGULAR;
    }
    if ((size_t)sb.st_size >= out_cap) {
        close(fd);
        return SAC_FS_ERR_BUFFER_TOO_SMALL;
    }

    size_t total = 0;
    while (total < out_cap - 1) {
        ssize_t n = read(fd, out_buf + total, (out_cap - 1) - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR) continue;
            int e = errno;
            close(fd);
            return map_errno_to_fs_status(e, false);
        }
    }

    /* Check if file grew past out_cap - 1 during read */
    char extra;
    ssize_t more = read(fd, &extra, 1);
    close(fd);
    if (more > 0) {
        out_buf[0] = '\0';
        return SAC_FS_ERR_BUFFER_TOO_SMALL;
    }

    out_buf[total] = '\0';
    if (out_len) *out_len = total;
    return SAC_FS_OK;
}
